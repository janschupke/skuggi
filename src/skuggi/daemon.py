"""The warm agent daemon behind the wrapped shell.

``skuggi`` (the shell wrapper) starts one of these in-process: it holds a single
``AgentCore`` -- graph, ledger, engagement, store all loaded once -- and serves
requests from the thin ``skuggi-client`` over a Unix socket, so a ``/skuggi``
line in the shell reaches a *warm* agent with no per-call cold start.

The wire protocol is line-delimited JSON. A request is ``{"op":"input","text":…}``
or ``{"op":"exit"}``; the reply is a stream of ``{"chunk":…}`` objects ending in
``{"end":true,"exit":<bool>}`` -- ``exit`` true tells the client to leave the
shell. ``handle_request`` is the whole routing decision and is unit-tested
directly; the socket accept loop needs a real socket and is exercised by hand.

Routing mirrors the REPL: a leading ``/`` is a control command (``/findings``,
``/report``, …), the bare words ``exit``/``quit`` leave, and anything else is an
agent turn. Requests are serialized by a lock so the single ``AgentCore`` (its
SQLite saver and ledger) is only ever touched by one turn at a time.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator

from skuggi.core import AgentCore
from skuggi.registry import doctor_ansi

_CONTROL_HELP = (
    "skuggi shell commands:\n"
    "  /skuggi <prompt>       ask the agent\n"
    "  /skuggi /findings      list findings recorded this session\n"
    "  /skuggi /report        write a Markdown engagement report\n"
    "  /skuggi /engagement    show the loaded scope\n"
    "  /skuggi /doctor        probe host tools\n"
    "  /skuggi /mode <m>      switch mode (pentest|redteam|blueteam)\n"
    "  /skuggi /autonomous [on|off]  toggle autonomous execution\n"
    "  /skuggi exit           leave the skuggi shell\n"
)


class Daemon:
    """Serves one ``AgentCore`` to the wrapped shell's client."""

    def __init__(self, core: AgentCore) -> None:
        self.core = core
        self._lock = threading.Lock()

    def handle_request(self, msg: dict[str, object]) -> Iterator[dict[str, object]]:
        """Route one request, yielding response objects (last carries ``end``)."""
        with self._lock:
            yield from self._dispatch(msg)

    def _dispatch(self, msg: dict[str, object]) -> Iterator[dict[str, object]]:
        if msg.get("op") == "exit":
            yield {"end": True, "exit": True}
            return
        text = str(msg.get("text", "")).strip()
        if not text:
            yield {"end": True, "exit": False}
            return
        if text in ("exit", "quit"):
            yield {"chunk": "leaving skuggi shell\n"}
            yield {"end": True, "exit": True}
            return
        chunks = (
            self._control(text[1:].strip())
            if text.startswith("/")
            else self._agent(text)
        )
        for chunk in chunks:
            yield {"chunk": chunk}
        yield {"end": True, "exit": False}

    def _agent(self, text: str) -> Iterator[str]:
        final = ""
        for ev in self.core.turn(text):
            if ev.kind == "status" and ev.text:
                yield f"({ev.node}) {ev.text.splitlines()[0]}\n"
            elif ev.kind == "final":
                final = ev.text
        yield (final or "(no answer)") + "\n"

    def _control(self, body: str) -> Iterator[str]:
        name, _, arg = body.partition(" ")
        name, arg = name.lower(), arg.strip()
        if name == "findings":
            yield self._findings_text()
        elif name == "report":
            yield f"report written: {self.core.write_report()}\n"
        elif name == "engagement":
            described = self.core.describe_engagement()
            yield (described + "\n") if described else "no engagement loaded\n"
        elif name == "doctor":
            # Emitted (and flushed) before the probe runs, so the client shows
            # progress immediately rather than a silent wait.
            yield "probing host tools and runtimes...\n"
            yield doctor_ansi(
                self.core.doctor_statuses(),
                self.core.runtime_statuses(),
                self.core.net_tool_statuses(),
            )
        elif name == "mode":
            yield self._set_mode(arg)
        elif name == "autonomous":
            yield self._set_autonomous(arg)
        elif name in ("help", ""):
            yield _CONTROL_HELP
        else:
            yield f"unknown control: /{name} (try /skuggi help)\n"

    def _set_mode(self, arg: str) -> str:
        try:
            self.core.set_mode(arg)
        except ValueError as e:
            return f"{e}\n"
        return f"mode: {self.core.mode}\n"

    def _set_autonomous(self, arg: str) -> str:
        want = {"on": True, "off": False}.get(arg.lower())
        try:
            state = self.core.set_autonomous(want)
        except ValueError as e:
            return f"{e}\n"
        return f"autonomous execution is now {'ON' if state else 'off'}\n"

    def _findings_text(self) -> str:
        rows = self.core.findings()
        if not rows:
            return "(no findings yet)\n"
        lines = [
            f"{f.severity.upper()} [{f.id}] {f.title}"
            + (f" (cmd:{f.command_id})" if f.command_id is not None else "")
            for f in rows
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
        def handle(self) -> None:
            line = self.rfile.readline()
            if not line:
                return
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                msg = {}
            for resp in daemon.handle_request(msg):
                self.wfile.write((json.dumps(resp) + "\n").encode())
                self.wfile.flush()

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
