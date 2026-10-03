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

import json
import threading
import zoneinfo
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import cast

from skuggi.agent import protocol, readiness
from skuggi.agent.core import AgentCore, parse_toggle
from skuggi.common import palette
from skuggi.common.logs import get_logger
from skuggi.config.config import PROVIDERS
from skuggi.frontend import cmdflow, configflow, dispatch, setup, verbs, wizard
from skuggi.frontend.prompter import Prompter
from skuggi.persistence import reports, visualize
from skuggi.persistence.ledger import finding_line
from skuggi.tooling.commands import CommandAlias, render
from skuggi.tooling.doctor import (
    PROBING_MSG,
    ToolFilter,
    doctor_ansi,
    doctor_table,
    filter_tool_statuses,
    table_ansi,
)

# The filters ``show tools`` accepts, for argument validation.
_TOOL_FILTERS: frozenset[str] = frozenset({"all", "scoped", "installed", "missing"})

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

    def _cmd(self, invocation: str) -> str:
        """A command hint formatted for this connection's surface."""
        return verbs.cmd(invocation, self._surface())

    def handle_request(self, msg: dict[str, object]) -> Iterator[dict[str, object]]:
        """Route one request, yielding response objects (last carries ``end``)."""
        with self._lock:
            yield from self._dispatch(msg)

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
        while True:
            line = read_line()
            if line is None:  # client disconnected
                return
            if self._is_wizard(line):
                self._attach_wizard(read_line, emit)
                continue
            if self._is_set_interactive(line):
                self._attach_set(line, read_line, emit)
                continue
            if self._is_cmd_editor(line):
                self._attach_cmd_editor(line, read_line, emit)
                continue
            if self._is_config_request(line):
                # Drop the "set config" prefix; the request is the remaining tail.
                request = verbs.split_verb(line)[1].partition(" ")[2]
                self._attach_config(request, read_line, emit)
                continue
            exit_session = False
            for resp in self.handle_request({"op": "input", "text": line}):
                emit(resp)
                if resp.get("end"):
                    exit_session = bool(resp.get("exit"))
            if exit_session:
                return

    @staticmethod
    def _is_wizard(line: str) -> bool:
        """Whether `line` opens the interactive engagement wizard."""
        verb, rest = verbs.split_verb(line)
        parts = rest.split()
        return verb == "engagement" and bool(parts) and parts[0] in wizard.WIZARD_ARGS

    def _engagement_catalog(self) -> wizard.Catalog:
        """The option sources the wizard offers (zones, tools, enums)."""
        tools = tuple(spec.binary for spec in self.core.registry.tools)
        return wizard.Catalog(
            timezones=tuple(sorted(zoneinfo.available_timezones())),
            tools=tools,
            methods=palette.methods(),
            methodologies=protocol.METHODOLOGIES,
            taxonomies=protocol.TAXONOMIES,
            stances=protocol.STANCES,
        )

    def _attach_wizard(
        self,
        read_line: Callable[[], str | None],
        emit: Callable[[dict[str, object]], None],
    ) -> None:
        """Run the engagement wizard over the attach connection.

        Menus (``{"choose"}``) and the checklist (``{"multiselect"}``) round-trip
        to the client, which renders prompt_toolkit widgets locally; autocomplete
        is REPL-only and degrades to a plain ``{"ask"}`` prompt here. The step bar
        and status lines ride ``{"chunk"}``. The turn closes with a non-exit
        ``end`` frame.
        """

        def ask(prompt: str) -> str | None:
            emit({"ask": prompt})
            return read_line()

        def ask_complete(
            prompt: str, _candidates: Sequence[str], _default: str | None
        ) -> str | None:
            emit({"ask": prompt})  # autocomplete is REPL-only; label carries [current]
            return read_line()

        def choose(prompt: str, options: list[str], default: str | None) -> str | None:
            emit({"choose": {"prompt": prompt, "options": options, "default": default}})
            return read_line()

        def multiselect(
            prompt: str, options: Sequence[str], preselected: Sequence[str]
        ) -> list[str] | None:
            emit(
                {
                    "multiselect": {
                        "prompt": prompt,
                        "options": list(options),
                        "preselected": list(preselected),
                    }
                }
            )
            line = read_line()
            if line is None:
                return None
            try:
                picks = json.loads(line)
            except json.JSONDecodeError:
                return None
            return [str(p) for p in picks] if isinstance(picks, list) else None

        def confirm(prompt: str, default: bool) -> bool | None:
            emit(
                {
                    "choose": {
                        "prompt": prompt,
                        "options": ["yes", "no"],
                        "default": "yes" if default else "no",
                    }
                }
            )
            line = read_line()
            return None if line is None else line == "yes"

        def notify(text: str) -> None:
            emit({"chunk": text + "\n"})

        def progress(step: int, total: int, label: str) -> None:
            emit({"chunk": f"[{step}/{total}] {label}\n"})

        prompter = Prompter(
            ask=ask,
            ask_complete=ask_complete,
            choose=choose,
            multiselect=multiselect,
            confirm=confirm,
            notify=notify,
            progress=progress,
        )
        self.core.note_interaction("engagement", "setup")
        with self._lock:
            try:
                wizard.run_wizard(
                    prompter,
                    self.core.create_engagement,
                    self._engagement_catalog(),
                    existing=self.core.engagement,
                )
            except Exception as exc:  # defensive: never kill the daemon thread
                log.exception("engagement wizard failed")
                emit({"chunk": f"engagement setup failed: {exc}\n"})
        emit({"end": True, "exit": False})

    @staticmethod
    def _is_cmd_editor(line: str) -> bool:
        """Whether `line` opens the interactive cheatsheet editor (cmd add/edit)."""
        verb, rest = verbs.split_verb(line)
        parts = rest.split()
        return (
            verb == "cmd"
            and bool(parts)
            and parts[0] in (cmdflow.ADD_ARGS | cmdflow.EDIT_ARGS)
        )

    def _attach_cmd_editor(
        self,
        line: str,
        read_line: Callable[[], str | None],
        emit: Callable[[dict[str, object]], None],
    ) -> None:
        """Run the cheatsheet editor over the attach connection (like the wizard)."""

        def ask(prompt: str) -> str | None:
            emit({"ask": prompt})
            return read_line()

        def notify(text: str) -> None:
            emit({"chunk": text + "\n"})

        _, rest = verbs.split_verb(line)
        parts = rest.split()
        sub, name = parts[0], (parts[1] if len(parts) > 1 else "")
        self.core.note_interaction("cmd", rest)
        with self._lock:
            if sub in cmdflow.EDIT_ARGS:
                existing = self.core.commands.alias_for(name)
                if existing is None:
                    notify(f"unknown alias {name!r}")
                else:
                    cmdflow.run_cmd_editor(
                        ask,
                        lambda raw: self.core.cmds.update(name, raw),
                        notify,
                        existing=existing,
                    )
            else:
                cmdflow.run_cmd_editor(ask, self.core.cmds.add, notify)
        emit({"end": True, "exit": False})

    @staticmethod
    def _is_set_interactive(line: str) -> bool:
        """Whether `line` is ``set provider``/``set model`` with no value (a picker).

        Only the no-value forms prompt; ``set provider openai`` stays a one-shot.
        """
        verb, rest = verbs.split_verb(line)
        parts = rest.split()
        return verb == "set" and len(parts) == 1 and parts[0] in {"provider", "model"}

    def _attach_set(
        self,
        line: str,
        read_line: Callable[[], str | None],
        emit: Callable[[dict[str, object]], None],
    ) -> None:
        """Run ``set provider`` / ``set model`` interactively over the attach loop.

        ``set provider`` (no name) is the full guided provider+credential+model
        flow; ``set model`` (no name) picks a model for the current provider.
        """

        def ask(prompt: str) -> str | None:
            emit({"ask": prompt})
            return read_line()

        def choose(prompt: str, options: list[str], default: str | None) -> str | None:
            emit({"choose": {"prompt": prompt, "options": options, "default": default}})
            return read_line()

        def notify(text: str) -> None:
            emit({"chunk": text + "\n"})

        _, rest = verbs.split_verb(line)
        noun = rest.split()[0]
        self.core.note_interaction("set", rest)
        with self._lock:
            if noun == "provider":
                setup.run_setup(self.core, ask, choose, notify)
            else:
                setup.run_model_select(
                    self.core, self.core.provider, ask, choose, notify
                )
        emit({"end": True, "exit": False})

    def _is_config_request(self, line: str) -> bool:
        """Whether `line` is a natural-language ``set config`` request (escalation)."""
        verb, rest = verbs.split_verb(line)
        if verb != "set":
            return False
        noun, _, tail = rest.partition(" ")
        if noun != "config":
            return False
        parts = tail.split(maxsplit=1)
        if not parts or parts[0] == "show":
            return False
        return parts[0] not in self.core.config.settable_keys()

    def _attach_config(
        self,
        arg: str,
        read_line: Callable[[], str | None],
        emit: Callable[[dict[str, object]], None],
    ) -> None:
        """Run the LLM config escalation over the attach connection."""

        def choose(prompt: str, options: list[str], default: str | None) -> str | None:
            emit({"choose": {"prompt": prompt, "options": options, "default": default}})
            return read_line()

        self.core.note_interaction("config", arg)
        with self._lock:
            configflow.run_config_request(
                arg,
                choose=choose,
                notify=lambda text: emit({"chunk": text + "\n"}),
                propose=self.core.config.propose,
                apply=self.core.config.apply,
            )
        emit({"end": True, "exit": False})

    def _dispatch(self, msg: dict[str, object]) -> Iterator[dict[str, object]]:
        if msg.get("op") == "exit":
            yield {"end": True, "exit": True}
            return
        if msg.get("op") == "record":
            # A free-typed command forwarded by the shell hook: log it, no reply.
            self.core.record_passthrough(str(msg.get("text", "")))
            yield {"end": True, "exit": False}
            return
        verb, rest = verbs.split_verb(str(msg.get("text", "")))
        if verbs.is_exit(verb):
            yield {"chunk": "leaving\n"}
            yield {"end": True, "exit": True}
            return
        if not verb:
            yield {"end": True, "exit": False}
            return
        if verb in verbs.KNOWN and not verbs.is_engagement(verb):
            self.core.note_interaction(verb, rest)  # control verb -> audit log
        if verb == "help":
            yield {"chunk": self._help_text(rest)}
        elif verb == "ask":
            for chunk in self._agent(rest):
                yield {"chunk": chunk}
        elif verb in verbs.KNOWN:
            for chunk in self._control(verb, rest):
                yield {"chunk": chunk}
        else:
            yield {"chunk": f"unknown verb: {verb!r} (try 'help' or 'ask <prompt>')\n"}
        yield {"end": True, "exit": False}

    def _agent(self, text: str) -> Iterator[str]:
        if not text:
            yield "usage: ask <prompt>\n"
            return
        final = ""
        for ev in self.core.turn(text):
            if ev.kind == "status" and ev.text:
                if ev.node == "error":
                    # Surface the whole error -- a pydantic ValidationError spans
                    # several lines, and truncating to the first hides the field
                    # and reason that make a failure diagnosable.
                    yield f"({ev.node}) {ev.text}\n"
                else:
                    yield f"({ev.node}) {ev.text.splitlines()[0]}\n"
            elif ev.kind == "final":
                final = ev.text
        yield (final or "(no answer)") + "\n"

    def _control(self, verb: str, arg: str) -> Iterator[str]:
        handler = {
            "cmd": self._cheat,
            "add": self._add,
            "show": self._show,
            "set": self._set,
            "remove": self._remove,
            "findings": self._findings,
            "report": self._report,
            "visualize": self._visualize,
            "replay": self._replay,
            "review": self._review,
            "engagement": self._engagement,
            "doctor": self._doctor,
            "login": self._login,
            "ingest": self._ingest,
            "update": self._update,
            "clear": self._clear,
        }.get(verb)
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

    def _show(self, arg: str) -> Iterator[str]:
        yield from self._route_noun(
            "show",
            arg,
            {
                "config": self._show_config,
                "provider": self._show_provider,
                "model": self._show_model,
                "engagement": self._show_engagement,
                "db": self._show_db,
                "tools": self._show_tools,
                "memory": self._show_memory,
                "notes": self._notes,
                "loot": self._loot,
                "findings": self._show_findings,
                "history": self._history,
                "trace": self._trace,
                "threads": self._show_threads,
                "status": self._show_status,
            },
        )

    def _set(self, arg: str) -> Iterator[str]:
        yield from self._route_noun(
            "set",
            arg,
            {
                "provider": self._set_provider,
                "model": self._set_model,
                "mode": self._mode,
                "autonomous": self._autonomous,
                "config": self._config,
                "thread": self._set_thread,
            },
        )

    def _remove(self, arg: str) -> Iterator[str]:
        yield from self._route_noun("remove", arg, {"memory": self._remove_memory})

    # ----- control handlers (plain text over the socket) --------------------

    def _cheat(self, arg: str) -> Iterator[str]:
        """The ``cmd`` verb over the socket: search / resolve / list / rm.

        ``add``/``edit`` are interactive and reached through the attach loop
        (``_attach_cmd_editor``); a raw one-shot points there.
        """
        sub, _, rest = arg.partition(" ")
        sub, rest = sub.strip(), rest.strip()
        if not sub or sub == "list":
            yield from self._cheat_list(self.core.commands.commands)
            return
        if sub in cmdflow.REMOVE_ARGS:
            yield from self._cheat_remove(rest)
            return
        if sub in cmdflow.ADD_ARGS or sub in cmdflow.EDIT_ARGS:
            hint = self._cmd("cmd " + sub + (f" {rest}" if rest else ""))
            yield f"cmd {sub} is interactive -- run {hint}\n"
            return
        if self.core.commands.alias_for(sub) is not None:  # exact name -> resolve
            yield from self._cheat_resolve(sub)
            return
        matches = self.core.cmds.search(arg.strip())  # otherwise substring search
        if not matches:
            yield f"no cheatsheet entry matches {arg.strip()!r}\n"
            return
        yield from self._cheat_list(matches)

    def _cheat_resolve(self, name: str) -> Iterator[str]:
        plan = self.core.cmds.plan(name)
        if not plan.known:
            yield plan.note + "\n"
            return
        yield f"$ {plan.raw}\n"  # the rendered raw command, always shown
        if plan.verdict is not None and not plan.verdict.allowed:
            yield f"OUT OF SCOPE: {plan.note}\n"
            return
        if plan.verdict is None:
            yield plan.note + "\n"
        else:
            yield (
                f"{plan.note} -- recorded proposed (cmd:{plan.command_id}); "
                "submit it yourself\n"
            )

    def _cheat_list(self, aliases: tuple[CommandAlias, ...]) -> Iterator[str]:
        if not aliases:
            yield "no command aliases configured\n"
            return
        for a in aliases:
            rendered = render(a, self.core.registry)
            yield f"  {a.name:<16} {rendered}  -- {a.description}\n"

    def _cheat_remove(self, name: str) -> Iterator[str]:
        if not name:
            yield f"usage: {self._cmd('cmd rm <name>')}\n"
            return
        if self.core.cmds.remove(name):
            yield f"removed alias '{name}'\n"
        else:
            yield f"unknown alias {name!r}\n"

    def _report(self, arg: str) -> Iterator[str]:
        first, _, rest = arg.strip().partition(" ")
        if first.lower() == "note":
            if not rest.strip():
                yield "usage: report note <text>\n"
                return
            yield f"changelog: {self.core.journal.add_report_note(rest)}\n"
            return
        result = self.core.journal.write_report(pdf=first.lower() == "pdf")
        for line in reports.report_written_lines(result):
            yield f"{line}\n"

    def _visualize(self, _arg: str) -> Iterator[str]:
        path = self.core.journal.write_visualization()
        for line in visualize.visualization_written_lines(path):
            yield f"{line}\n"

    def _replay(self, arg: str) -> Iterator[str]:
        match dispatch.run_replay(self.core, arg, current_id=self.core.session_id):
            case dispatch.ReplayEmpty():
                yield "(no sessions)\n"
            case dispatch.ReplayList(rows, current_id):
                for s in rows:
                    mark = " *" if s.session_id == current_id else ""
                    yield f"  {s.session_id[:8]}  {s.started_at}  {s.mode}{mark}\n"
            case dispatch.ReplayTranscript(text):
                yield text + "\n"

    def _review(self, arg: str) -> Iterator[str]:
        yield self.core.archive.review(arg.strip() or None) + "\n"

    def _render_memory(self, outcome: dispatch.MemoryOutcome) -> Iterator[str]:
        """Render a memory outcome (shared by show/add/remove memory)."""
        match outcome:
            case dispatch.MemoryUsage():  # pragma: no cover -- callers pre-validate
                pass
            case dispatch.MemoryAdded(row):
                yield f"remembered [{row.id}] {row.text}\n"
            case dispatch.MemoryAlreadyKnown():
                yield "already remembered\n"
            case dispatch.MemoryForgotten():
                yield "forgotten\n"
            case dispatch.MemoryMissing(ref):
                yield f"no preference {ref}\n"
            case dispatch.MemoryCleared(count):
                yield f"cleared {count} preference(s)\n"
            case dispatch.MemoryList(rows):
                if not rows:
                    yield "(nothing remembered yet)\n"
                for row in rows:
                    yield f"  [{row.id}] {row.text} ({row.source})\n"

    def _show_memory(self, _rest: str) -> Iterator[str]:
        yield from self._render_memory(dispatch.run_memory(self.core, ""))

    def _add_memory(self, rest: str) -> Iterator[str]:
        if not rest:
            yield f"usage: {self._cmd('add memory <entry>')}\n"
            return
        yield from self._render_memory(dispatch.run_memory(self.core, f"add {rest}"))

    def _remove_memory(self, rest: str) -> Iterator[str]:
        if rest == "all":
            yield from self._render_memory(dispatch.run_memory(self.core, "clear"))
            return
        if not rest.isdigit():
            yield f"usage: {self._cmd('remove memory <id> | all')}\n"
            return
        yield from self._render_memory(dispatch.run_memory(self.core, f"forget {rest}"))

    # ----- show <noun> -------------------------------------------------------

    def _show_config(self, _rest: str) -> Iterator[str]:
        yield self.core.config.summary() + "\n"

    def _show_provider(self, _rest: str) -> Iterator[str]:
        r = readiness.from_core(self.core)
        state = (
            "configured"
            if r.provider_configured
            else f"not configured -- run {self._cmd('set provider')}"
        )
        yield f"provider {r.provider} -- {state}\n"
        if r.provider_note:
            yield f"note: {r.provider_note}\n"

    def _show_model(self, _rest: str) -> Iterator[str]:
        r = readiness.from_core(self.core)
        yield f"model {r.model} on provider {r.provider}\n"

    def _show_engagement(self, _rest: str) -> Iterator[str]:
        described = self.core.describe_engagement()
        if described:
            yield described + "\n"
        else:
            yield f"no engagement loaded -- run {self._cmd('engagement setup')}\n"

    def _show_db(self, _rest: str) -> Iterator[str]:
        yield dispatch.run_db_stats(self.core) + "\n"

    def _show_tools(self, rest: str) -> Iterator[str]:
        which = rest.strip().lower() or "all"
        if which not in _TOOL_FILTERS:
            yield f"usage: {self._cmd('show tools [all|scoped|installed|missing]')}\n"
            return
        yield PROBING_MSG + "\n"
        filtered = filter_tool_statuses(
            self.core.doctor.tools(), cast("ToolFilter", which), self.core.engagement
        )
        if not filtered:
            yield f"(no {which} tools)\n"
            return
        yield table_ansi(doctor_table(filtered))

    def _show_findings(self, _rest: str) -> Iterator[str]:
        yield from self._render_findings()

    def _show_threads(self, _rest: str) -> Iterator[str]:
        ids = self.core.list_threads()
        if not ids:
            yield "(no threads)\n"
            return
        yield "".join(
            f"  {tid}{' *' if tid == self.core.thread_id else ''}\n" for tid in ids
        )

    def _show_status(self, _rest: str) -> Iterator[str]:
        r = dispatch.run_status(self.core)
        auto = "ON" if r.autonomous else "off"
        yield (
            f"mode={r.mode}  provider={r.provider}  model={r.model}  "
            f"engagement={r.engagement or '(none)'}  autonomous={auto}\n"
        )
        if r.provider_note:
            yield f"note: {r.provider_note}\n"
        notes = readiness.render_banner_notes(r, self._surface())
        for note in notes:
            yield f"{note}\n"
        if not notes:
            yield "ready\n"

    def _engagement(self, arg: str) -> Iterator[str]:
        first = arg.split(maxsplit=1)[0] if arg.split() else ""
        if first in wizard.WIZARD_ARGS:
            # Reached only as a raw one-shot; the client routes the wizard through
            # the attach loop. Point at the command that works here.
            hint = self._cmd("engagement setup")
            yield f"engagement setup is interactive -- run {hint}\n"
            return
        if first == "scaffold":
            yield from self._scaffold()
            return
        if first == "threat-model":
            rest = arg.split(maxsplit=1)[1] if len(arg.split()) > 1 else ""
            yield dispatch.run_threat_model(self.core, rest) + "\n"
            return
        yield (
            f"usage: {self._cmd('engagement setup | scaffold | threat-model')} -- "
            f"scope summary is {self._cmd('show engagement')}\n"
        )

    def _scaffold(self) -> Iterator[str]:
        match dispatch.run_scaffold(Path.cwd()):
            case dispatch.Scaffolded(path):
                yield f"scaffolded -> {path}\n"
            case dispatch.ScaffoldExists(path):
                yield f"exists: {path} -- not overwritten\n"
            case dispatch.ScaffoldError(message):
                yield f"scaffold failed: {message}\n"

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

    def _login(self, _arg: str) -> Iterator[str]:
        # Login only reports progress (no questions), so it runs here directly;
        # messages are buffered then emitted once the browser flow completes.
        messages: list[str] = []
        try:
            with self._lock:
                account = self.core.login_chatgpt(messages.append)
        except (RuntimeError, ImportError) as exc:
            yield from (f"{m}\n" for m in messages)
            yield f"login failed: {exc}\n"
            return
        yield from (f"{m}\n" for m in messages)
        yield f"logged in to chatgpt{f' (account {account})' if account else ''}\n"

    def _doctor(self, arg: str) -> Iterator[str]:
        target = dispatch.doctor_install_target(arg)
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
        )

    def _install(self, binary: str) -> Iterator[str]:
        match dispatch.run_install(self.core, binary):
            case dispatch.InstallUnknown(name):
                yield f"unknown tool: {name!r}\n"
            case dispatch.Installed(name, version, source):
                yield f"installed {name} ({version or '?'}) via {source}\n"
            case dispatch.InstallFailed(name):
                yield f"install failed or unavailable for {name}\n"

    def _mode(self, arg: str) -> Iterator[str]:
        try:
            self.core.set_mode(arg)
        except ValueError as e:
            yield f"{e}\n"
            return
        yield f"mode: {self.core.mode}\n"

    def _autonomous(self, arg: str) -> Iterator[str]:
        try:
            state = self.core.set_autonomous(parse_toggle(arg))
        except ValueError as e:
            yield f"{e}\n"
            return
        yield f"autonomous execution is now {'ON' if state else 'off'}\n"

    def _set_provider(self, arg: str) -> Iterator[str]:
        if not arg:
            # No name: the guided picker needs the attach loop; the client routes
            # `set provider` there, so a direct one-shot just points at it.
            yield f"set provider is interactive -- run {self._cmd('set provider')}\n"
            return
        match dispatch.run_provider(self.core, arg):
            case dispatch.ProviderUsage():  # pragma: no cover -- arg is non-empty here
                yield f"usage: {self._cmd('set provider')} <{'|'.join(PROVIDERS)}>\n"
            case dispatch.ProviderUnknown(message):
                yield f"{message}\n"
            case dispatch.ProviderNoCredential(provider):
                yield (
                    f"{provider} isn't configured -- "
                    f"run {self._cmd('set provider')} to add a key\n"
                )
            case dispatch.ProviderError(message):
                yield f"provider error: {message}\n"
            case dispatch.ProviderSwitched(provider, model):
                yield f"switched to {provider}/{model or '(default)'}\n"

    def _set_model(self, arg: str) -> Iterator[str]:
        if not arg:
            yield f"set model is interactive -- run {self._cmd('set model')}\n"
            return
        match dispatch.run_model(self.core, arg):
            case dispatch.ModelUsage():  # pragma: no cover -- arg is non-empty here
                yield f"usage: {self._cmd('set model <name>')}\n"
            case dispatch.ModelNoCredential(provider):
                yield (
                    f"can't switch model: {provider} isn't configured -- "
                    f"run {self._cmd('set provider')} first\n"
                )
            case dispatch.ModelError(message):
                yield f"provider error: {message}\n"
            case dispatch.ModelSwitched(provider, model):
                yield f"switched to {provider}/{model}\n"

    def _set_thread(self, arg: str) -> Iterator[str]:
        if arg in ("new", ""):
            yield f"new thread: {self.core.new_thread()}\n"
        else:
            self.core.set_thread(arg)
            yield f"switched to thread: {arg}\n"

    def _history(self, arg: str) -> Iterator[str]:
        count = int(arg) if arg.isdigit() else 20
        labels = {"human": "you", "ai": "bot", "system": "sys", "tool": "tool"}
        for message in self.core.state().get("messages", [])[-count:]:
            yield f"{labels.get(message.type, message.type)}: {message.text}\n"

    def _trace(self, _arg: str) -> Iterator[str]:
        commands = self.core.state().get("commands") or []
        if not commands:
            yield "(no command activity on this thread)\n"
            return
        for cmd in commands:
            yield f"{cmd.status} [cmd:{cmd.id}] {cmd.command}\n"
            if cmd.summary:
                yield f"  {cmd.summary.splitlines()[0][:200]}\n"

    def _ingest(self, arg: str) -> Iterator[str]:
        if not arg:
            yield "usage: ingest <path>\n"
            return
        yield f"indexed {self.core.ingest(Path(arg))} chunk(s)\n"

    def _update(self, _arg: str) -> Iterator[str]:
        yield from self.core.self_update()

    def _clear(self, _arg: str) -> Iterator[str]:
        yield "clear is only available in skuggi-repl\n"

    def _add(self, arg: str) -> Iterator[str]:
        noun, _, rest = arg.partition(" ")
        noun = noun.strip().lower()
        if noun == "memory":
            yield from self._add_memory(rest.strip())
            return
        if noun in {"note", "loot", "finding"}:
            yield from self._add_record(f"{noun} {rest.strip()}".strip())
            return
        options = " | ".join(n.name for n in verbs.nouns_of("add"))
        yield f"usage: {self._cmd(f'add <{options}>')}\n"

    def _add_record(self, arg: str) -> Iterator[str]:
        match dispatch.run_add(self.core, arg):
            case dispatch.AddUsage(form):
                yield f"usage: add {form}\n"
            case dispatch.NoEngagement(kind):
                yield (
                    f"no engagement loaded -- run {self._cmd('engagement setup')} "
                    f"to record {kind}s\n"
                )
            case dispatch.BadSeverity(value, allowed):
                choices = ", ".join(allowed)
                yield f"unknown severity {value!r}; choose one of: {choices}\n"
            case dispatch.AddedNote(path):
                yield f"noted -> {path}\n"
            case dispatch.AddedLoot(path):
                yield f"loot recorded -> {path}\n"
            case dispatch.FindingRecorded(row):
                yield "recorded " + finding_line(row) + "\n"

    def _notes(self, _arg: str) -> Iterator[str]:
        text = self.core.journal.notes()
        if not text.strip():
            yield "(no notes yet)\n"
            return
        yield text if text.endswith("\n") else text + "\n"

    def _loot(self, _arg: str) -> Iterator[str]:
        text = self.core.journal.loot()
        if not text.strip():
            yield "(no loot yet)\n"
            return
        yield text if text.endswith("\n") else text + "\n"

    def _findings(self, arg: str) -> Iterator[str]:
        """Review a finding (approve/reject/rescore); listing is `show findings`."""
        message = dispatch.run_findings(self.core, arg)
        if message is not None:
            yield message + "\n"
            return
        yield (
            f"usage: {self._cmd('findings approve <id> | reject <id> <reason>')} -- "
            f"list with {self._cmd('show findings')}\n"
        )

    def _render_findings(self) -> Iterator[str]:
        rows = self.core.journal.findings()
        if not rows:
            yield "(no findings yet)\n"
            return
        current = self.core.ledger.current_threat_model_version()
        yield (
            "\n".join(
                finding_line(
                    f,
                    outdated=f.cvss_tm_version is not None
                    and f.cvss_tm_version != current,
                )
                for f in rows
            )
            + "\n"
        )

    def _help_text(self, arg: str = "") -> str:
        verb = arg.strip().split(" ", 1)[0]
        if verb:
            rows = verbs.help_for(verb)
            if rows is None:
                return f"no such command: {verb}\n"
            lines = [
                f"/skuggi {verb}:",
                *(f"  /skuggi {inv:<34} {summary}" for inv, summary in rows),
            ]
            return "\n".join(lines) + "\n"
        lines = ["skuggi shell commands (/skuggi <verb> <rest>):"]
        for title, section_rows in verbs.help_sections():
            lines.append(f"  {title}:")
            lines += [
                f"    /skuggi {inv:<32} {summary}"
                for inv, summary in section_rows
                if not inv.startswith("clear")
            ]
        return "\n".join(lines) + "\n"


def serve(core: AgentCore, sock_path: str) -> ServerHandle:  # pragma: no cover
    """Start the daemon on `sock_path` in a background thread.

    Returns a handle whose ``stop`` shuts the server down and removes the socket
    file. Interactive plumbing: exercised by hand, not in the offline suite.
    """
    import contextlib
    import json
    import socketserver
    from pathlib import Path

    daemon = Daemon(core)

    class _Handler(socketserver.StreamRequestHandler):
        def _emit(self, resp: dict[str, object]) -> None:
            # A wizard may still emit after the operator aborted (Ctrl-D closed
            # the socket); dropping those writes beats crashing the handler.
            with contextlib.suppress(OSError):
                self.wfile.write((json.dumps(resp) + "\n").encode())
                self.wfile.flush()

        def handle(self) -> None:
            line = self.rfile.readline()
            if not line:
                return
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                log.warning("dropping malformed client request frame: %r", line)
                msg = {}
            if msg.get("op") == "attach":
                self._attach(str(msg.get("mode", "loop")))
                return
            for resp in daemon.handle_request(msg):
                self._emit(resp)

        def _attach(self, mode: str) -> None:
            """Serve a persistent interactive session over this connection."""

            def read_line() -> str | None:
                raw = self.rfile.readline()
                if not raw:
                    return None
                try:
                    return str(json.loads(raw).get("text", ""))
                except json.JSONDecodeError:
                    log.warning("dropping malformed client attach frame: %r", raw)
                    return ""

            daemon.run_attached(read_line, self._emit, mode=mode)

    class _Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True
        allow_reuse_address = True

    with contextlib.suppress(FileNotFoundError):
        Path(sock_path).unlink()
    server = _Server(sock_path, _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return ServerHandle(server, thread, sock_path)


class ServerHandle:  # pragma: no cover -- interactive plumbing
    """A running daemon server; ``stop`` tears it down and unlinks the socket."""

    def __init__(
        self, server: object, thread: threading.Thread, sock_path: str
    ) -> None:
        self._server = server
        self._thread = thread
        self._sock_path = sock_path

    def stop(self) -> None:
        """Shut the server down and remove its socket file."""
        import contextlib
        from pathlib import Path

        shutdown = getattr(self._server, "shutdown", None)
        if callable(shutdown):
            shutdown()
        close = getattr(self._server, "server_close", None)
        if callable(close):
            close()
        with contextlib.suppress(FileNotFoundError):
            Path(self._sock_path).unlink()
