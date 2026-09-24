"""L1: the thin skuggi-client's message building and streaming."""

from __future__ import annotations

import io
import json
import socket

from skuggi.client import build_message, run_over


def test_build_message() -> None:
    assert build_message("scan the host") == {"op": "input", "text": "scan the host"}


def _server_writes(
    lines: list[dict[str, object]],
) -> tuple[socket.socket, socket.socket]:
    client_sock, server_sock = socket.socketpair()
    for line in lines:
        server_sock.sendall((json.dumps(line) + "\n").encode())
    return client_sock, server_sock


def test_run_over_streams_chunks_and_returns_zero() -> None:
    client_sock, server_sock = _server_writes(
        [{"chunk": "hello\n"}, {"end": True, "exit": False}]
    )
    out = io.StringIO()
    try:
        code = run_over(client_sock, "hi", out)
    finally:
        client_sock.close()
        server_sock.close()
    assert code == 0
    assert out.getvalue() == "hello\n"


def test_run_over_returns_42_on_exit() -> None:
    client_sock, server_sock = _server_writes(
        [{"chunk": "leaving\n"}, {"end": True, "exit": True}]
    )
    out = io.StringIO()
    try:
        code = run_over(client_sock, "exit", out)
    finally:
        client_sock.close()
        server_sock.close()
    assert code == 42
    assert "leaving" in out.getvalue()


def test_run_over_ignores_malformed_frames() -> None:
    client_sock, server_sock = _server_writes([])
    server_sock.sendall(b"not-json\n")
    server_sock.sendall((json.dumps({"end": True, "exit": False}) + "\n").encode())
    out = io.StringIO()
    try:
        code = run_over(client_sock, "hi", out)
    finally:
        client_sock.close()
        server_sock.close()
    assert code == 0
    assert out.getvalue() == ""
