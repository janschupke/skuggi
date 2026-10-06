"""The warm agent daemon behind the wrapped shell.

``skuggi`` (the shell wrapper) starts one of these in-process: it holds a single
``AgentCore`` -- graph, ledger, engagement, store all loaded once -- and serves
requests from the thin ``skuggi-client`` over a Unix socket, so a ``/skuggi``
line reaches a *warm* agent with no per-call cold start.

The wire protocol is line-delimited JSON. A request is ``{"op":"input","text":…}``
or ``{"op":"exit"}``; the reply is a stream of ``{"chunk":…}`` objects ending in
``{"end":true,"exit":<bool>}`` -- ``exit`` true tells the client to leave the
shell. ``handle_request`` is the whole routing decision and is unit-tested
directly; the socket accept loop needs a real socket and is exercised by hand.

Routing is **verb-first**: the first word of the line is the action (``ask``,
``findings``, ``mode`` …, from the shared registry in ``skuggi.verbs``), the rest
is its input, and ``exit``/``quit`` leave. This mirrors the REPL's ``/verb``
controls over the same verb set. Requests are serialised by a lock so the single
``AgentCore`` (its SQLite saver and ledger) is only ever touched by one turn at a
time.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from functools import partial
from typing import cast

from skuggi.agent.core import AgentCore
from skuggi.agent.turn_runner import TurnEvent
from skuggi.common.logs import get_logger
from skuggi.frontend import (
    attach,
    cmdflow,
    completion,
    control,
    dispatch,
    memoryflow,
    outcomes,
    presenters,
    presenters_cmd,
    presenters_journal,
    render,
    verbosity,
    verbs,
    wizard,
)
from skuggi.frontend import (
    help as help_mod,
)
from skuggi.install import reconcile
from skuggi.tooling.commands import CommandAlias
from skuggi.tooling.commands import render as render_alias
from skuggi.tooling.doctor import (
    PROBING_MSG,
    TOOL_FILTERS,
    ToolFilter,
    doctor_ansi,
    filter_tool_statuses,
    parse_doctor_flags,
    table_ansi,
    tool_tables,
)

# The help listing's intro line, per surface. The command grammar differs
# (``/skuggi <verb>`` at the wrapped-shell prompt, a bare ``<verb>`` inside the
# chat loop, ``/<verb>`` in the REPL), so the intro names the one that works here.

# The agentic-loop verbs the daemon streams identically: verb -> (core turn method,
# usage hint shown on an empty argument -- forensics defaults in the runner).
_LOOP_TURNS: dict[str, tuple[str, str]] = {
    "osint": ("osint_turn", "usage: osint <request>\n"),
    "research": ("research_turn", "usage: research <subject or instruction>\n"),
    "forensics": ("forensics_turn", ""),
}

log = get_logger(__name__)


class Daemon:
    """Serves one ``AgentCore`` to the wrapped shell's client."""

    def __init__(self, core: AgentCore) -> None:
        self.core = core
        self._lock = threading.Lock()
        # The command grammar to use in hints depends on how this connection
        # attached. Per-connection (= per thread; the server is threaded), so a
        # thread-local keeps concurrent connections from clobbering each other.
        self._local = threading.local()

    def _surface(self) -> verbs.Surface:
        """This connection's command grammar (set per-attach; default shell)."""
        surface: verbs.Surface = getattr(self._local, "surface", "shell")
        return surface

    def _emit(self, lines: render.Styled) -> Iterator[str]:
        """Yield presenter output as ANSI frames (coloured for the real terminal).

        The client writes straight to the operator's terminal, so the daemon
        paints here just as the REPL does -- the same palette, via ``to_ansi`` --
        rather than stripping colour over the socket.
        """
        for line in lines:
            yield render.to_ansi(line) + "\n"

    def _cmd(self, invocation: str) -> str:
        """A command hint formatted for this connection's surface."""
        return verbs.cmd(invocation, self._surface())

    def handle_request(self, msg: dict[str, object]) -> Iterator[dict[str, object]]:
        """Route one request, yielding response objects (last carries ``end``)."""
        with self._lock:
            yield from self._dispatch(msg)

    def _completion_tree(self) -> dict[str, object]:
        """The shared Tab-completion vocabulary for the chat loop + ``--complete``."""
        providers, models = completion.provider_model_names(self.core.settings.provider)
        return completion.completion_tree(
            self.core.commands.names(),
            reconcile.known_names(),
            provider_names=providers,
            model_names=models,
        )

    def _complete(self, words: list[str]) -> list[str]:
        """Candidates following the already-complete tokens `words` (host-shell TAB).

        Walks the completion tree by the complete tokens and returns the keys at
        that node (sorted); the shell filters them by the word being typed.
        """
        node: object = self._completion_tree()
        for tok in words:
            if isinstance(node, dict) and tok in node:
                node = node[tok]
            else:
                return []
        return sorted(node) if isinstance(node, dict) else []

    def _prompt_frame(
        self, *, ready: bool, context: str | None = None
    ) -> dict[str, object]:
        """The "your turn" frame: engagement context, plus the one-time handshake.

        Sent before each chat-loop prompt so the client can render
        ``🐐 [<engagement>] >`` and refresh it after a ``set engagement``. The
        first frame also carries ``ready`` (the completion tree) so the thin
        client can build its prompt_toolkit session without loading config.
        `context` is the active sub-context (``"chat"`` inside a chat context, else
        ``None``) so the client can mark it in the prompt.
        """
        eng = self.core.engagement
        frame: dict[str, object] = {
            "prompt": {
                "engagement": eng.name if eng is not None else None,
                "autonomous": self.core.autonomous,
                "mode": self.core.mode,
                "context": context,
            }
        }
        if ready:
            frame["ready"] = {"tree": self._completion_tree()}
        return frame

    def run_attached(
        self,
        read_line: Callable[[], str | None],
        emit: Callable[[dict[str, object]], None],
        *,
        mode: str = "loop",
    ) -> None:
        """Drive a persistent attach session against the one warm core.

        Reads a line of operator input (``read_line`` returns ``None`` when the
        client disconnects), routes it through the shared verb dispatch, emits
        every response frame, and repeats -- until the client closes or a turn
        signals ``exit``. The connection stays open across turns, so the whole
        session (thread, ledger, engagement) persists between lines; the routing
        is identical to a one-shot ``{"op":"input"}``, so this is the same code
        the REPL and the one-shot client run.

        ``mode`` is the client's attach intent: ``loop`` is the persistent chat
        loop (bare verbs run, so hints use that grammar); ``once`` is a single
        interactive verb like ``/skuggi setup`` whose output is read back at the
        wrapped-shell prompt (so hints use the ``/skuggi`` grammar).
        """
        self._local.surface = "chat" if mode == "loop" else "shell"
        first = mode == "loop"
        chat_context = False
        while True:
            if mode == "loop":
                # Signal "your turn" with the current engagement context; the first
                # frame also hands over the history path + completion vocabulary.
                emit(
                    self._prompt_frame(
                        ready=first, context="chat" if chat_context else None
                    )
                )
                first = False
            line = read_line()
            if line is None:  # client disconnected
                return
            if chat_context:
                # Inside a chat context every line is a prompt -- no verb routing.
                chat_context, capture_line = attach.chat_turn(line, emit, self._agent)
                if capture_line is not None:
                    attach.capture_after_ask(
                        self.core, self._lock, capture_line, read_line, emit
                    )
                continue
            if mode == "loop" and verbs.split_verb(line) == ("chat", ""):
                chat_context = True
                emit(
                    {
                        "chunk": "entered chat context -- every line goes to the "
                        "agent; type exit to leave\n"
                    }
                )
                continue
            if attach.intercept(self.core, self._lock, line, read_line, emit):
                continue
            exit_session = False
            for resp in self.handle_request({"op": "input", "text": line}):
                emit(resp)
                if resp.get("end"):
                    exit_session = bool(resp.get("exit"))
            if exit_session:
                return
            attach.capture_after_ask(self.core, self._lock, line, read_line, emit)

    def _dispatch(self, msg: dict[str, object]) -> Iterator[dict[str, object]]:
        if msg.get("op") == "exit":
            yield {"end": True, "exit": True}
            return
        if msg.get("op") == "record":
            # A free-typed command forwarded by the shell hook: log it, no reply.
            self.core.record_passthrough(str(msg.get("text", "")))
            yield {"end": True, "exit": False}
            return
        if msg.get("op") == "complete":
            # A host-shell TAB (the `/skuggi` completion hook): candidates for the
            # argv so far. One frame, no side effects.
            raw = msg.get("words")
            words = [str(w) for w in raw] if isinstance(raw, list) else []
            yield {"candidates": self._complete(words), "end": True, "exit": False}
            return
        verb, rest = verbs.split_verb(str(msg.get("text", "")))
        if verbs.is_exit(verb):
            # Two levels of exit, so the message must say which one this is. In the
            # chat loop, leaving drops back to the wrapped shell and the agent stays
            # warm (a second, shell-level `skuggi exit` is what stops it); a one-shot
            # `/skuggi exit` at the shell IS that second level and tears the daemon
            # down. The surface tells them apart.
            if self._surface() == "chat":
                yield {
                    "chunk": "Leaving interactive mode, agent still active until "
                    "another skuggi exit...\n"
                }
            else:
                yield {"chunk": "stopping skuggi -- agent closed\n"}
            yield {"end": True, "exit": True}
            return
        if not verb:
            yield {"end": True, "exit": False}
            return
        available = verb not in verbs.KNOWN or verbs.is_available(verb, self.core.mode)
        if available and verb in verbs.KNOWN and not verbs.is_engagement(verb):
            self.core.note_interaction(verb, rest)  # control verb -> audit log
        yield from self._render_verb(verb, rest, available=available)
        yield {"end": True, "exit": False}

    def _render_verb(
        self, verb: str, rest: str, *, available: bool
    ) -> Iterator[dict[str, object]]:
        """Render a non-exit verb's frames (help / chat / control / unknown)."""
        if verb == "help":
            verbose, help_arg = verbosity.pop_verbose(rest)
            lines = help_mod.help_lines(
                self._surface(), self.core.mode, help_arg, verbose=verbose
            )
            for chunk in self._emit(lines):
                yield {"chunk": chunk}
        elif not available:
            lines = presenters.present_unavailable(verb, self.core.mode)
            yield {"chunk": "".join(self._emit(lines))}
        elif verb == "chat":
            yield from self._agent(rest)
        elif verb in verbs.KNOWN:
            for chunk in self._control(verb, rest):
                yield {"chunk": chunk}
        else:
            yield {
                "chunk": "".join(
                    self._emit(presenters.present_unknown(verb, self._surface()))
                )
            }

    def _agent(self, text: str) -> Iterator[dict[str, object]]:
        """Stream a chat turn: status -> `pending` (live spinner), answer -> `chunk`."""
        if not text:
            hint = self._cmd("chat")
            yield {
                "chunk": f"usage: {self._cmd('chat <prompt>')} -- or run {hint} in "
                "the interactive shell to enter a chat context\n"
            }
            return
        final = ""
        for ev in self.core.turn(text):
            if ev.kind == "status" and ev.text:
                if ev.node == "error":
                    yield {"chunk": f"({ev.node}) {ev.text}\n"}
                else:
                    yield {"pending": f"{ev.text}..."}
            elif ev.kind == "final":
                final = ev.text
        yield {"chunk": (final or "(no answer)") + "\n"}
        # One-shot ask: announce what the evaluator would remember, never write (the
        # chat loop, surface "chat", gates the write itself in run_attached).
        if self._surface() != "chat":
            for line in memoryflow.announce_capture(
                self.core.memory.propose_capture(text), hint=self._cmd("add memory")
            ):
                yield {"chunk": line}

    def _stream_turn(self, events: Iterator[TurnEvent]) -> Iterator[str]:
        """Render a loop's event stream: a line per node status, then the final."""
        final = ""
        for ev in events:
            if ev.kind == "status" and ev.text:
                if ev.node == "error":
                    yield f"({ev.node}) {ev.text}\n"
                else:
                    summary = ev.text.splitlines()[0][: presenters.STATUS_LINE_CAP]
                    yield f"({ev.node}) {summary}\n"
            elif ev.kind == "final":
                final = ev.text
        yield (final or "(no answer)") + "\n"

    def _loop(self, verb: str, text: str) -> Iterator[str]:
        """Stream one agentic loop (osint/research/forensics): node status + summary."""
        turn_name, usage = _LOOP_TURNS[verb]
        if usage and not text:
            yield usage
            return
        turn = getattr(self.core, turn_name)
        yield from self._stream_turn(turn(text))

    def _control(self, verb: str, arg: str) -> Iterator[str]:
        handlers: dict[str, Callable[[str], Iterator[str]]] = {
            "cmd": self._cheat,
            "osint": partial(self._loop, "osint"),
            "research": partial(self._loop, "research"),
            "forensics": partial(self._loop, "forensics"),
            "add": self._add,
            "show": self._show,
            "set": self._set,
            "remove": self._remove,
            "findings": self._findings,
            "report": self._styled(control.report),
            "visualize": self._styled(control.visualize),
            "replay": self._replay,
            "review": self._review,
            "engagement": self._engagement,
            "doctor": self._doctor,
            "login": self._login,
            "ingest": self._styled(control.ingest),
            "update": self._update,
            "reconcile": self._reconcile,
            "clear": self._clear,
        }
        handler = handlers.get(verb)
        if handler is None:  # pragma: no cover -- KNOWN guards this in _dispatch
            yield f"unknown verb: {verb!r}\n"
            return
        yield from handler(arg)

    # ----- grouping-verb routers --------------------------------------------

    def _route_noun(
        self,
        verb: str,
        arg: str,
        router: dict[str, Callable[[str], Iterator[str]]],
    ) -> Iterator[str]:
        """Dispatch ``<verb> <noun> <rest>`` to `router`, or yield the noun usage."""
        noun, _, rest = arg.partition(" ")
        handler = router.get(noun.strip().lower())
        if handler is None:
            options = " | ".join(n.name for n in verbs.nouns_of(verb))
            yield f"usage: {self._cmd(f'{verb} <{options}>')}\n"
            return
        yield from handler(rest.strip())

    def _styled(self, action: control.Action) -> Callable[[str], Iterator[str]]:
        """Adapt a shared control action to this surface's streaming emit."""

        def handler(rest: str) -> Iterator[str]:
            yield from self._emit(action(self.core, rest, self._surface()))

        return handler

    def _show(self, arg: str) -> Iterator[str]:
        yield from self._route_noun(
            "show",
            arg,
            {
                **{n: self._styled(a) for n, a in control.SHOW_ACTIONS.items()},
                "engagement": self._show_engagement,
                "db": self._show_db,
                "latency": self._show_latency,
                "tools": self._show_tools,
                "history": self._history,
                "trace": self._trace,
            },
        )

    def _set(self, arg: str) -> Iterator[str]:
        yield from self._route_noun(
            "set",
            arg,
            {
                **{n: self._styled(a) for n, a in control.SET_ACTIONS.items()},
                "provider": self._set_provider,
                "model": self._set_model,
                "config": self._config,
                "scope": self._scope,
                "listener": self._listener,
            },
        )

    def _remove(self, arg: str) -> Iterator[str]:
        yield from self._route_noun(
            "remove",
            arg,
            {n: self._styled(a) for n, a in control.REMOVE_ACTIONS.items()},
        )

    # ----- control handlers (plain text over the socket) --------------------

    def _cheat(self, arg: str) -> Iterator[str]:
        """The ``cmd`` verb over the socket: search / resolve / list / rm.

        ``add``/``edit`` are interactive and reached through the attach loop
        (``_attach_cmd_editor``); a raw one-shot points there.
        """
        verbose, arg = verbosity.pop_verbose(arg)
        sub, _, rest = arg.partition(" ")
        sub, rest = sub.strip(), rest.strip()
        if not sub or sub == "list":
            yield from self._cheat_list(
                self.core.commands.commands, "", verbose=verbose
            )
            return
        if sub in cmdflow.REMOVE_ARGS:
            yield from self._cheat_remove(rest)
            return
        if sub in (cmdflow.ADD_ARGS | cmdflow.EDIT_ARGS | cmdflow.SUGGEST_ARGS):
            hint = self._cmd("cmd " + sub + (f" {rest}" if rest else ""))
            yield f"cmd {sub} is interactive -- run {hint}\n"
            return
        if self.core.commands.alias_for(sub) is not None:  # exact name -> resolve
            yield from self._cheat_resolve(sub)
            return
        matches = self.core.cmds.search(arg.strip())  # otherwise substring search
        if not matches:
            hint = self._cmd("cmd list")
            yield f"no cheatsheet entry matches {arg.strip()!r} -- try {hint}\n"
            return
        yield from self._cheat_list(matches, arg.strip(), verbose=verbose)

    def _cheat_resolve(self, name: str) -> Iterator[str]:
        yield from self._emit(control.resolve_cmd(self.core, name, self._surface()))

    def _cheat_list(
        self, aliases: tuple[CommandAlias, ...], query: str, *, verbose: bool = False
    ) -> Iterator[str]:
        """List `aliases` via the shared cheatsheet presenter (both surfaces match).

        The name/description highlighting and the compact-vs-``-v`` shape live in
        :func:`presenters_cmd.present_cheatsheet`; here we only supply the rendered
        command (we hold the registry) and emit the result as ANSI frames.
        """
        rows = [
            (a.name, render_alias(a, self.core.registry), a.description)
            for a in aliases
        ]
        yield from self._emit(
            presenters_cmd.present_cheatsheet(rows, query, verbose=verbose)
        )

    def _cheat_remove(self, name: str) -> Iterator[str]:
        if not name:
            yield f"usage: {self._cmd('cmd rm <name>')}\n"
            return
        if self.core.cmds.remove(name):
            yield f"removed alias '{name}'\n"
        else:
            yield f"unknown alias {name!r}\n"

    def _replay(self, arg: str) -> Iterator[str]:
        outcome = dispatch.run_replay(self.core, arg, current_id=self.core.session_id)
        if isinstance(outcome, outcomes.ReplayTranscript):
            yield outcome.text + "\n"  # structural body: rendered per surface
            return
        yield from self._emit(presenters_journal.present_replay_list(outcome))

    def _review(self, arg: str) -> Iterator[str]:
        yield self.core.archive.review(arg.strip() or None) + "\n"

    # ----- show <noun> -------------------------------------------------------

    def _show_engagement(self, _rest: str) -> Iterator[str]:
        described = self.core.describe_engagement()
        if described:
            yield described + "\n"
        else:
            yield f"no engagement loaded -- run {self._cmd('engagement setup')}\n"

    def _show_db(self, _rest: str) -> Iterator[str]:
        yield dispatch.run_db_stats(self.core) + "\n"

    def _show_latency(self, _rest: str) -> Iterator[str]:
        yield dispatch.run_latency(self.core) + "\n"

    def _show_tools(self, rest: str) -> Iterator[str]:
        view = parse_doctor_flags(rest)
        which = view.rest.strip().lower() or "all"
        if which not in TOOL_FILTERS:
            yield (
                f"usage: {self._cmd('show tools [all|scoped|installed|missing]')} "
                "[-v] [--missing] [--category <offensive|forensics>]\n"
            )
            return
        yield PROBING_MSG + "\n"
        filtered = filter_tool_statuses(
            self.core.doctor.tools(), cast("ToolFilter", which), self.core.engagement
        )
        if view.missing_only:
            filtered = [s for s in filtered if not s.found]
        tables = tool_tables(filtered, verbose=view.verbose, category=view.category)
        if not tables:
            yield f"(no {which} tools)\n"
            return
        for table in tables:
            yield table_ansi(table)

    def _engagement(self, arg: str) -> Iterator[str]:
        first = arg.split(maxsplit=1)[0] if arg.split() else ""
        if first in wizard.WIZARD_ARGS:
            # Reached only as a raw one-shot; the client routes the wizard through
            # the attach loop. Point at the command that works here.
            hint = self._cmd("engagement setup")
            yield f"engagement setup is interactive -- run {hint}\n"
            return
        if first == "threat-model":
            rest = arg.split(maxsplit=1)[1] if len(arg.split()) > 1 else ""
            yield dispatch.run_threat_model(self.core, rest) + "\n"
            return
        yield (
            f"usage: {self._cmd('engagement setup | threat-model')} -- "
            f"adopt/scaffold a root with {self._cmd('set engagement [<path>]')}, "
            f"scope summary is {self._cmd('show engagement')}\n"
        )

    def _config(self, arg: str) -> Iterator[str]:
        text = self.core.config.line(arg)
        if text is None:  # a natural-language request; needs the interactive loop
            yield (
                f"a natural-language config request is interactive -- run "
                f"{self._cmd('set config ' + arg)} in the chat loop, or set a key "
                f"directly: {self._cmd('set config <key> <value>')}\n"
            )
            return
        yield text + "\n"

    def _scope(self, arg: str) -> Iterator[str]:
        # A scope edit is always a natural-language request, so it needs the
        # interactive confirm (diff -> approve); one-shot cannot round-trip.
        yield (
            f"editing scope is interactive -- run {self._cmd('set scope ' + arg)} "
            f"in the chat loop\n"
        )

    def _listener(self, _arg: str) -> Iterator[str]:
        # The listener picker is interactive (choose an interface, enter a port),
        # so a one-shot cannot round-trip; it runs in the chat loop via attach_set.
        yield (
            f"setting a listener is interactive -- run {self._cmd('set listener')} "
            f"in the chat loop\n"
        )

    def _login(self, _arg: str) -> Iterator[str]:
        # Login only reports progress (no questions), so it runs here directly;
        # messages are buffered then emitted once the browser flow completes.
        messages: list[str] = []
        try:
            # Already under the handler lock (handle_request); re-acquiring the
            # non-reentrant lock here would deadlock the daemon permanently.
            account = self.core.login_chatgpt(messages.append)
        except (RuntimeError, ImportError) as exc:
            yield from (f"{m}\n" for m in messages)
            yield f"login failed: {exc}\n"
            return
        yield from (f"{m}\n" for m in messages)
        yield f"logged in to chatgpt{f' (account {account})' if account else ''}\n"

    def _doctor(self, arg: str) -> Iterator[str]:
        view = parse_doctor_flags(arg)
        target = dispatch.doctor_install_target(view.rest)
        if target == "missing":
            # Needs the confirm round-trip, so it runs only over the attach loop
            # (intercepted in run_attached); a one-shot request cannot prompt.
            yield "run `doctor install missing` from the interactive shell\n"
            return
        if target is not None:
            yield from self._install(target)
            return
        # Emitted (and flushed) before the probe so the client shows progress.
        yield PROBING_MSG + "\n"
        yield doctor_ansi(
            self.core.doctor.tools(),
            self.core.doctor.runtimes(),
            self.core.doctor.net_tools(),
            self.core.settings,
            view=view,
        )

    def _install(self, binary: str) -> Iterator[str]:
        yield f"installing {binary}...\n"
        yield from self._emit(
            presenters.present_install(dispatch.run_install(self.core, binary))
        )

    def _set_provider(self, arg: str) -> Iterator[str]:
        if not arg:
            # No name: the guided picker needs the attach loop; the client routes
            # `set provider` there, so a direct one-shot just points at it.
            yield f"set provider is interactive -- run {self._cmd('set provider')}\n"
            return
        yield from self._emit(
            control.set_provider_named(self.core, arg, self._surface())
        )

    def _set_model(self, arg: str) -> Iterator[str]:
        if not arg:
            yield f"set model is interactive -- run {self._cmd('set model')}\n"
            return
        yield from self._emit(control.set_model_named(self.core, arg, self._surface()))

    def _history(self, arg: str) -> Iterator[str]:
        yield from self._emit(
            presenters.present_history(self.core.state().get("messages", []), arg)
        )

    def _trace(self, _arg: str) -> Iterator[str]:
        yield from self._emit(
            presenters.present_trace(self.core.state().get("commands") or [])
        )

    def _update(self, _arg: str) -> Iterator[str]:
        yield from self.core.self_update()

    def _reconcile(self, arg: str) -> Iterator[str]:
        yield from self._emit(control.reconcile(self.core, arg, self._surface()))

    def _clear(self, _arg: str) -> Iterator[str]:
        yield "clear is only available in skuggi-repl\n"

    def _add(self, arg: str) -> Iterator[str]:
        noun, _, rest = arg.partition(" ")
        noun = noun.strip().lower()
        if noun == "memory":
            yield from self._emit(
                control.add_memory(self.core, rest.strip(), self._surface())
            )
            return
        if noun in {"note", "loot", "cred", "foothold", "finding"}:
            yield from self._styled(control.add_record_for(noun))(rest.strip())
            return
        options = " | ".join(n.name for n in verbs.nouns_of("add"))
        yield from self._emit(presenters.usage(f"add <{options}>", self._surface()))

    def _findings(self, arg: str) -> Iterator[str]:
        """Review a finding (approve/reject/rescore); listing is `show findings`."""
        message = dispatch.run_findings(self.core, arg)
        if message is not None:
            yield message + "\n"
            return
        yield from self._emit(presenters.present_findings_usage(self._surface()))
