"""Unix-socket transport for the wrapped-shell daemon.

The :class:`~skuggi.frontend.daemon.Daemon` is the request handler (pure, unit
tested); this module is the socket server that drives it over a Unix domain
socket -- the interactive plumbing exercised by hand rather than in the offline
suite. Kept apart so the handler logic imports without the server machinery.
"""

from __future__ import annotations

import contextlib
import json
import socketserver
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from skuggi.common.logs import get_logger
from skuggi.frontend.daemon import Daemon

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore

log = get_logger(__name__)


def serve(core: AgentCore, sock_path: str) -> ServerHandle:  # pragma: no cover
    """Start the daemon on `sock_path` in a background thread.

    Returns a handle whose ``stop`` shuts the server down and removes the socket
    file. Interactive plumbing: exercised by hand, not in the offline suite.
    """
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
        shutdown = getattr(self._server, "shutdown", None)
        if callable(shutdown):
            shutdown()
        close = getattr(self._server, "server_close", None)
        if callable(close):
            close()
        with contextlib.suppress(FileNotFoundError):
            Path(self._sock_path).unlink()
