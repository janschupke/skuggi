"""The thin ``skuggi-client`` the wrapped shell calls for ``/skuggi`` lines.

It is deliberately tiny -- only ``json``, ``os``, ``socket``, ``sys`` -- so that
starting it per ``/skuggi`` invocation is cheap; the warm agent lives in the
daemon, not here. It reads ``$SKUGGI_SOCK`` (set by the shell wrapper), sends the
operator's input as one request, streams the reply to stdout, and exits ``42``
when the daemon says to leave -- the shell's ``command_not_found`` hook turns
that into a shell ``exit``. ``Ctrl+C`` during a turn just returns to the prompt.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from collections.abc import Iterator
from typing import TextIO

_EXIT_SHELL = 42


def build_message(text: str) -> dict[str, str]:
    """The request object for one line of operator input."""
    return {"op": "input", "text": text}


def _iter_lines(conn: socket.socket) -> Iterator[bytes]:
    """Yield newline-delimited frames from `conn` as they arrive.

    A generator (not a buffered read) so the caller can stop on the terminal
    frame without waiting for the connection to close.
    """
    buffer = b""
    while True:
        data = conn.recv(4096)
        if not data:
            if buffer.strip():
                yield buffer
            return
        buffer += data
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            yield line


def run_over(conn: socket.socket, text: str, out: TextIO) -> int:
    """Send `text` over an open connection and stream the reply to `out`.

    Returns ``42`` when the daemon signals the shell should exit, else ``0``.
    Split from ``run`` so it is testable over a plain socket pair.
    """
    conn.sendall((json.dumps(build_message(text)) + "\n").encode())
    exit_shell = False
    for line in _iter_lines(conn):
        try:
            resp = json.loads(line)
        except json.JSONDecodeError:
            continue
        chunk = resp.get("chunk")
        if chunk:
            out.write(chunk)
            out.flush()
        if resp.get("end"):
            exit_shell = bool(resp.get("exit"))
            break
    return _EXIT_SHELL if exit_shell else 0


def run(sock_path: str, text: str, out: TextIO) -> int:  # pragma: no cover
    """Connect to the daemon socket and converse (see ``run_over``)."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(sock_path)
            return run_over(conn, text, out)
    except KeyboardInterrupt:
        out.write("\n")
        return 0
    except OSError as e:
        print(f"skuggi: cannot reach the harness: {e}", file=sys.stderr)
        return 1


def main() -> int:  # pragma: no cover -- console entry point
    """Console entry point invoked by the shell's ``/skuggi`` hook."""
    sock_path = os.environ.get("SKUGGI_SOCK")
    if not sock_path:
        print("skuggi: not running inside a skuggi shell", file=sys.stderr)
        return 1
    return run(sock_path, " ".join(sys.argv[1:]), sys.stdout)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
