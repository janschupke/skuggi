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

from langchain_core.messages import AIMessage

from skuggi import configflow, reports, verbs, wizard
from skuggi.commands import raw_command
from skuggi.core import AgentCore, parse_toggle
from skuggi.doctor import PROBING_MSG, doctor_ansi
from skuggi.ledger import finding_line


class Daemon:
    """Serves one ``AgentCore`` to the wrapped shell's client."""

    def __init__(self, core: AgentCore) -> None:
        self.core = core
        self._lock = threading.Lock()

    def handle_request(self, msg: dict[str, object]) -> Iterator[dict[str, object]]:
        """Route one request, yielding response objects (last carries ``end``)."""
        with self._lock:
            yield from self._dispatch(msg)

    def run_attached(
        self,
        read_line: Callable[[], str | None],
        emit: Callable[[dict[str, object]], None],
    ) -> None:
        """Drive a persistent attach session against the one warm core.

        Reads a line of operator input (``read_line`` returns ``None`` when the
        client disconnects), routes it through the shared verb dispatch, emits
        every response frame, and repeats -- until the client closes or a turn
        signals ``exit``. The connection stays open across turns, so the whole
        session (thread, ledger, engagement) persists between lines; the routing
        is identical to a one-shot ``{"op":"input"}``, so this is the same code
        the REPL and the one-shot client run.
        """
        while True:
            line = read_line()
            if line is None:  # client disconnected
                return
            if self._is_wizard(line):
                self._attach_wizard(read_line, emit)
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

        def ask(prompt: str) -> str | None:
            emit({"ask": prompt})
            return read_line()

        self.core.note_interaction("config", arg)
        with self._lock:
            configflow.run_config_request(
                arg,
                ask=ask,
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
            "run": self._run,
            "findings": self._findings,
            "report": self._report,
            "replay": self._replay,
            "review": self._review,
            "engagement": self._engagement,
            "config": self._config,
            "doctor": self._doctor,
            "mode": self._mode,
            "autonomous": self._autonomous,
            "provider": self._provider,
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

    def _run(self, arg: str) -> Iterator[str]:
        name, _, rest = arg.partition(" ")
        if not name or name == "list":
            yield from self._run_list()
            return
        plan = self.core.plan_run(name, rest.split())
        if not plan.known:
            yield plan.note + "\n"
            return
        yield f"$ {plan.raw}\n"  # the resolved raw command, always shown
        if plan.verdict is not None and not plan.verdict.allowed:
            yield f"OUT OF SCOPE: {plan.note}\n"
            return
        if plan.verdict is None:
            yield plan.note + "\n"
        else:
            yield (
                f"in scope -- recorded proposed (cmd:{plan.command_id}); "
                "submit it yourself\n"
            )
        yield from self._agent(
            "Briefly evaluate this proposed command and note any risks; do not "
            f"run anything, just advise: {plan.raw}"
        )

    def _run_list(self) -> Iterator[str]:
        aliases = self.core.commands.commands
        if not aliases:
            yield "no command aliases configured\n"
            return
        for a in aliases:
            yield f"  {a.name:<16} {raw_command(list(a.argv))}  -- {a.description}\n"

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

    def _engagement(self, arg: str) -> Iterator[str]:
        parts = arg.split()
        if parts and parts[0] in wizard.WIZARD_ARGS:
            yield (
                "engagement setup is interactive: run '/skuggi' (no args) to open "
                "the chat loop, then 'engagement setup'\n"
            )
            return
        described = self.core.describe_engagement()
        yield (described + "\n") if described else "no engagement loaded\n"

    def _config(self, arg: str) -> Iterator[str]:
        text = self.core.config_line(arg)
        if text is None:  # a natural-language request; needs the interactive loop
            yield (
                "config from a natural-language request needs the chat loop: run "
                "'/skuggi' (no args), then 'config <request>'\n"
            )
            return
        yield text + "\n"

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
        try:
            self.core.set_provider(arg)
        except ValueError as e:
            yield f"{e}\n"
            return
        except (RuntimeError, ImportError) as e:
            yield f"provider error: {e}\n"
            return
        yield f"switched to {self.core.provider}/{self.core.model or '(default)'}\n"

    def _model(self, arg: str) -> Iterator[str]:
        try:
            self.core.set_model(arg)
        except ValueError:
            yield "usage: model <name>\n"
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
        shown = False
        for message in self.core.state().get("scratch", []):
            if isinstance(message, AIMessage) and message.tool_calls:
                for call in message.tool_calls:
                    yield f"call {call['name']}({call['args']})\n"
                    shown = True
            elif message.type == "tool":
                yield f"result {message.text[:200]}\n"
                shown = True
        if not shown:
            yield "(no tool activity on this thread)\n"

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
                msg = {}
            if msg.get("op") == "attach":
                self._attach()
                return
            for resp in daemon.handle_request(msg):
                self._emit(resp)

        def _attach(self) -> None:
            """Serve a persistent interactive session over this connection."""

            def read_line() -> str | None:
                raw = self.rfile.readline()
                if not raw:
                    return None
                try:
                    return str(json.loads(raw).get("text", ""))
                except json.JSONDecodeError:
                    return ""

            daemon.run_attached(read_line, self._emit)

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
