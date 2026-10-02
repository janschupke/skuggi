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
from pathlib import Path

from skuggi.agent import prompts
from skuggi.agent.core import AgentCore, parse_toggle
from skuggi.common.logs import get_logger
from skuggi.config.config import PROVIDERS
from skuggi.config.configs import ConfigError
from skuggi.frontend import cmdflow, configflow, setup, verbs, wizard
from skuggi.frontend.commands import CommandAlias, render
from skuggi.persistence import reports
from skuggi.persistence.ledger import finding_line
from skuggi.tooling.doctor import PROBING_MSG, doctor_ansi

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

    def _cmd(self, invocation: str) -> str:
        """A command hint formatted for this connection's surface."""
        surface: verbs.Surface = getattr(self._local, "surface", "shell")
        return verbs.cmd(invocation, surface)

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
            if self._is_setup(line):
                self._attach_setup(read_line, emit)
                continue
            if self._is_cmd_editor(line):
                self._attach_cmd_editor(line, read_line, emit)
                continue
            if self._is_config_request(line):
                self._attach_config(verbs.split_verb(line)[1], read_line, emit)
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

    def _attach_wizard(
        self,
        read_line: Callable[[], str | None],
        emit: Callable[[dict[str, object]], None],
    ) -> None:
        """Run the engagement wizard over the attach connection.

        Each question is an ``{"ask": prompt}`` frame; the client prompts the
        operator and sends the answer back, which arrives as the next line. The
        turn closes with the usual non-exit ``end`` frame.
        """

        def ask(prompt: str) -> str | None:
            emit({"ask": prompt})
            return read_line()

        self.core.note_interaction("engagement", "setup")
        with self._lock:
            wizard.run_wizard(
                ask,
                self.core.create_engagement,
                lambda text: emit({"chunk": text + "\n"}),
                existing=self.core.engagement,
            )
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
                        lambda raw: self.core.update_command(name, raw),
                        notify,
                        existing=existing,
                    )
            else:
                cmdflow.run_cmd_editor(ask, self.core.add_command, notify)
        emit({"end": True, "exit": False})

    @staticmethod
    def _is_setup(line: str) -> bool:
        """Whether `line` opens the interactive provider/credential setup."""
        return verbs.split_verb(line)[0] == "setup"

    def _attach_setup(
        self,
        read_line: Callable[[], str | None],
        emit: Callable[[dict[str, object]], None],
    ) -> None:
        """Run the guided setup over the attach connection (like the wizard)."""

        def ask(prompt: str) -> str | None:
            emit({"ask": prompt})
            return read_line()

        def choose(prompt: str, options: list[str], default: str | None) -> str | None:
            emit({"choose": {"prompt": prompt, "options": options, "default": default}})
            return read_line()

        self.core.note_interaction("setup", "")
        with self._lock:
            setup.run_setup(
                self.core, ask, choose, lambda text: emit({"chunk": text + "\n"})
            )
        emit({"end": True, "exit": False})

    def _is_config_request(self, line: str) -> bool:
        """Whether `line` is a natural-language `config` request (LLM escalation)."""
        verb, rest = verbs.split_verb(line)
        if verb != "config":
            return False
        parts = rest.split(maxsplit=1)
        if not parts or parts[0] == "show":
            return False
        return parts[0] not in self.core.settable_config_keys()

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
                propose=self.core.propose_config,
                apply=self.core.apply_config,
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
            yield {"chunk": self._help_text()}
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
                yield f"({ev.node}) {ev.text.splitlines()[0]}\n"
            elif ev.kind == "final":
                final = ev.text
        yield (final or "(no answer)") + "\n"

    def _control(self, verb: str, arg: str) -> Iterator[str]:
        handler = {
            "cmd": self._cheat,
            "findings": self._findings,
            "report": self._report,
            "replay": self._replay,
            "review": self._review,
            "memory": self._memory,
            "engagement": self._engagement,
            "config": self._config,
            "setup": self._setup,
            "doctor": self._doctor,
            "mode": self._mode,
            "autonomous": self._autonomous,
            "provider": self._provider,
            "login": self._login,
            "model": self._model,
            "thread": self._thread,
            "history": self._history,
            "trace": self._trace,
            "ingest": self._ingest,
            "update": self._update,
            "clear": self._clear,
        }.get(verb)
        if handler is None:  # pragma: no cover -- KNOWN guards this in _dispatch
            yield f"unknown verb: {verb!r}\n"
            return
        yield from handler(arg)

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
        matches = self.core.search_commands(arg.strip())  # otherwise substring search
        if not matches:
            yield f"no cheatsheet entry matches {arg.strip()!r}\n"
            return
        yield from self._cheat_list(matches)

    def _cheat_resolve(self, name: str) -> Iterator[str]:
        plan = self.core.plan_cmd(name)
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
        yield from self._agent(prompts.EVALUATE_RUN.format(command=plan.raw))

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
        if self.core.remove_command(name):
            yield f"removed alias '{name}'\n"
        else:
            yield f"unknown alias {name!r}\n"

    def _report(self, arg: str) -> Iterator[str]:
        result = self.core.write_report(pdf=arg.strip().lower() == "pdf")
        for line in reports.report_written_lines(result):
            yield f"{line}\n"

    def _replay(self, arg: str) -> Iterator[str]:
        a = arg.strip()
        if a == "list":
            rows = self.core.list_sessions()
            if not rows:
                yield "(no sessions)\n"
                return
            for s in rows:
                mark = " *" if s.session_id == self.core.session_id else ""
                yield f"  {s.session_id[:8]}  {s.started_at}  {s.mode}{mark}\n"
            return
        yield self.core.transcript(a or None) + "\n"

    def _review(self, arg: str) -> Iterator[str]:
        yield self.core.review_session(arg.strip() or None) + "\n"

    def _memory(self, arg: str) -> Iterator[str]:
        sub, _, rest = arg.partition(" ")
        sub, rest = sub.strip().lower(), rest.strip()
        if sub == "add":
            if not rest:
                yield "usage: memory add <preference>\n"
                return
            row = self.core.add_preference(rest)
            yield (
                f"remembered [{row.id}] {row.text}\n" if row else "already remembered\n"
            )
            return
        if sub == "forget":
            if not rest.isdigit():
                yield "usage: memory forget <id>\n"
                return
            removed = self.core.forget_preference(int(rest))
            yield "forgotten\n" if removed else f"no preference {rest}\n"
            return
        if sub == "clear":
            yield f"cleared {self.core.clear_preferences()} preference(s)\n"
            return
        rows = self.core.list_preferences()
        if not rows:
            yield "(nothing remembered yet)\n"
            return
        for row in rows:
            yield f"  [{row.id}] {row.text} ({row.source})\n"

    def _engagement(self, arg: str) -> Iterator[str]:
        parts = arg.split()
        if parts and parts[0] in wizard.WIZARD_ARGS:
            # Reached only as a raw one-shot; the client routes the wizard through
            # the attach loop. Point at the command that works here.
            hint = self._cmd("engagement setup")
            yield f"engagement setup is interactive -- run {hint}\n"
            return
        described = self.core.describe_engagement()
        if described:
            yield described + "\n"
        else:
            hint = self._cmd("engagement setup")
            yield f"no engagement loaded -- run {hint} to create one\n"

    def _config(self, arg: str) -> Iterator[str]:
        text = self.core.config_line(arg)
        if text is None:  # a natural-language request; needs the interactive loop
            yield (
                f"a natural-language config request is interactive -- run "
                f"{self._cmd('config ' + arg)} in the chat loop, or set a key "
                f"directly: {self._cmd('config <key> <value>')}\n"
            )
            return
        yield text + "\n"

    def _setup(self, _arg: str) -> Iterator[str]:
        # Reached only as a raw one-shot; the client routes setup through the
        # attach loop. Point at the command that works here.
        yield f"setup is interactive -- run {self._cmd('setup')}\n"

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
        if arg.split()[:1] == ["install"]:
            yield from self._install(arg.split(maxsplit=1)[1] if " " in arg else "")
            return
        # Emitted (and flushed) before the probe so the client shows progress.
        yield PROBING_MSG + "\n"
        yield doctor_ansi(
            self.core.doctor_statuses(),
            self.core.runtime_statuses(),
            self.core.net_tool_statuses(),
            self.core.settings,
        )

    def _install(self, binary: str) -> Iterator[str]:
        status = self.core.install_tool(binary)
        if status is None:
            yield f"unknown tool: {binary!r}\n"
        elif status.found:
            yield f"installed {binary} ({status.version or '?'}) via {status.source}\n"
        else:
            yield f"install failed or unavailable for {binary}\n"

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

    def _provider(self, arg: str) -> Iterator[str]:
        if not arg.strip():
            yield (
                f"usage: provider <{'|'.join(PROVIDERS)}> -- "
                f"or run {self._cmd('setup')} to configure one\n"
            )
            return
        try:
            self.core.set_provider(arg)
        except ValueError as e:
            yield f"{e}\n"
            return
        except ConfigError:  # switched, but the new provider has no credential
            yield f"{arg} isn't configured -- run {self._cmd('setup')} to add a key\n"
            return
        except (RuntimeError, ImportError) as e:
            yield f"provider error: {e}\n"
            return
        yield f"switched to {self.core.provider}/{self.core.model or '(default)'}\n"

    def _model(self, arg: str) -> Iterator[str]:
        try:
            self.core.set_model(arg)
        except ValueError:
            yield f"usage: {self._cmd('model <name>')}\n"
            return
        except ConfigError:  # the model switch rebuilt the llm and found no key
            yield (
                f"can't switch model: {self.core.provider} isn't configured -- "
                f"run {self._cmd('setup')} first\n"
            )
            return
        except (RuntimeError, ImportError) as e:
            yield f"provider error: {e}\n"
            return
        yield f"switched to {self.core.provider}/{self.core.model}\n"

    def _thread(self, arg: str) -> Iterator[str]:
        if arg in ("new", ""):
            yield f"new thread: {self.core.new_thread()}\n"
        elif arg == "list":
            ids = self.core.list_threads()
            if not ids:
                yield "(no threads)\n"
                return
            yield "".join(
                f"  {tid}{' *' if tid == self.core.thread_id else ''}\n" for tid in ids
            )
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

    def _findings(self, _arg: str) -> Iterator[str]:
        rows = self.core.findings()
        if not rows:
            yield "(no findings yet)\n"
            return
        yield "\n".join(finding_line(f) for f in rows) + "\n"

    def _help_text(self) -> str:
        rows = [
            (inv, summary)
            for inv, summary in verbs.help_rows()
            if not inv.startswith("clear")
        ]
        lines = [
            "skuggi shell commands (/skuggi <verb> <rest>):",
            *(f"  /skuggi {inv:<34} {summary}" for inv, summary in rows),
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
