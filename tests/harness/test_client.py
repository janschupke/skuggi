"""L1: the thin skuggi-client's message building and streaming."""

from __future__ import annotations

import builtins
import io
import json
import socket
from typing import cast

import pytest

from skuggi.frontend import client
from skuggi.frontend.client import (
    _stdin_prompt,
    _stream_turn,
    attach_once_over,
    attach_over,
    build_message,
    build_record_message,
    record_over,
    run_over,
)


def test_build_message() -> None:
    assert build_message("scan the host") == {"op": "input", "text": "scan the host"}


def test_build_record_message() -> None:
    assert build_record_message("nmap 10.0.0.5") == {
        "op": "record",
        "text": "nmap 10.0.0.5",
    }


def test_record_over_sends_one_frame_and_does_not_wait() -> None:
    client_sock, server_sock = socket.socketpair()
    try:
        record_over(client_sock, "nmap -sV 10.0.0.5")
        server_sock.settimeout(1.0)
        sent = json.loads(server_sock.recv(4096).decode())
    finally:
        client_sock.close()
        server_sock.close()
    assert sent == {"op": "record", "text": "nmap -sV 10.0.0.5"}


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


# --- interactive attach loop ------------------------------------------------


def _reply(*frames: dict[str, object]) -> bytes:
    return "".join(json.dumps(f) + "\n" for f in frames).encode()


class _FakeConn:
    """A scripted duplex socket: each sent input line buffers a canned reply.

    ``sendall`` eagerly queues the whole reply for the following ``recv``, so
    ``attach_over`` drives a full request/response cycle single-threaded without
    a deadlock.
    """

    def __init__(self, replies: dict[str, bytes]) -> None:
        self._replies = replies
        self._inbox = b""

    def sendall(self, data: bytes) -> None:
        msg = json.loads(data)
        if msg.get("op") == "attach":
            return
        self._inbox += self._replies.get(str(msg.get("text", "")), b"")

    def recv(self, _n: int) -> bytes:
        chunk, self._inbox = self._inbox[:_n], self._inbox[_n:]
        return chunk


def _as_socket(conn: _FakeConn) -> socket.socket:
    return cast(socket.socket, conn)


def test_stream_turn_writes_chunks_and_defaults_exit_to_false() -> None:
    out = io.StringIO()
    lines = _reply({"chunk": "hi\n"}, {"end": True}).splitlines()  # no exit key
    assert _stream_turn(iter(lines), out) is False
    assert out.getvalue() == "hi\n"


def test_stream_turn_reports_exit_flag() -> None:
    out = io.StringIO()
    lines = _reply({"chunk": "bye\n"}, {"end": True, "exit": True}).splitlines()
    assert _stream_turn(iter(lines), out) is True
    assert out.getvalue() == "bye\n"


def test_stream_turn_returns_false_when_frames_run_dry() -> None:
    out = io.StringIO()
    assert _stream_turn(iter([]), out) is False


def test_stream_turn_stops_spinner_on_first_frame() -> None:
    class _StubSpinner:
        def __init__(self) -> None:
            self.stops = 0

        def stop(self) -> None:
            self.stops += 1

    out = io.StringIO()
    spinner = _StubSpinner()
    lines = _reply({"chunk": "hi\n"}, {"end": True}).splitlines()
    result = _stream_turn(iter(lines), out, spinner=cast(client._Spinner, spinner))
    assert result is False
    assert out.getvalue() == "hi\n"
    assert spinner.stops >= 1  # stopped the moment the first frame arrived


def test_attach_over_streams_replies_then_ends_on_blank_line() -> None:
    conn = _FakeConn(
        {
            "one": _reply({"chunk": "r1\n"}, {"end": True, "exit": False}),
            "two": _reply({"chunk": "r2\n"}, {"end": True, "exit": False}),
        }
    )
    lines = iter(["one", "two", ""])  # blank line ends the loop
    out = io.StringIO()
    code = attach_over(_as_socket(conn), lambda _p: next(lines), out)
    assert code == 0
    assert out.getvalue() == "r1\nr2\n"


def test_attach_over_stops_when_daemon_signals_exit() -> None:
    conn = _FakeConn(
        {"bye": _reply({"chunk": "leaving\n"}, {"end": True, "exit": True})}
    )
    lines = iter(["bye", "unreached"])
    out = io.StringIO()
    code = attach_over(_as_socket(conn), lambda _p: next(lines), out)
    assert code == 0
    assert out.getvalue() == "leaving\n"
    assert next(lines) == "unreached"  # the loop stopped before a second prompt


def test_attach_over_ends_immediately_on_eof() -> None:
    conn = _FakeConn({})
    out = io.StringIO()
    assert attach_over(_as_socket(conn), lambda _p: None, out) == 0
    assert out.getvalue() == ""


class _RecordingConn:
    """Records what was sent, for the wizard's ask/answer round-trip."""

    def __init__(self) -> None:
        self.sent: list[dict[str, object]] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(json.loads(data))


def test_stream_turn_answers_ask_frames_over_the_connection() -> None:
    """An `ask` frame prompts the operator and sends the answer back."""
    conn = _RecordingConn()
    frames = iter(
        [
            json.dumps({"ask": "name? "}).encode(),
            json.dumps({"chunk": "loaded\n"}).encode(),
            json.dumps({"end": True, "exit": False}).encode(),
        ]
    )
    out = io.StringIO()
    exit_flag = _stream_turn(
        frames, out, conn=cast(socket.socket, conn), ask=lambda _q: "acme"
    )
    assert exit_flag is False
    assert conn.sent == [{"op": "input", "text": "acme"}]  # answer sent back
    assert out.getvalue() == "loaded\n"


def test_stream_turn_leaves_loop_when_wizard_aborted() -> None:
    conn = _RecordingConn()
    frames = iter([json.dumps({"ask": "name? "}).encode()])
    out = io.StringIO()
    assert _stream_turn(
        frames, out, conn=cast(socket.socket, conn), ask=lambda _q: None
    )  # abort -> leave
    assert conn.sent == []  # nothing sent; the socket close aborts the daemon


# --- attach_once (interactive verbs like /skuggi setup) ---------------------


def test_attach_once_over_runs_one_verb_then_returns() -> None:
    conn = _FakeConn(
        {"setup": _reply({"chunk": "done\n"}, {"end": True, "exit": False})}
    )
    out = io.StringIO()
    code = attach_once_over(_as_socket(conn), "setup", lambda _p: None, out)
    assert code == 0
    assert out.getvalue() == "done\n"


def test_attach_once_over_aborts_cleanly_when_prompt_cancelled() -> None:
    # An ask frame whose prompt the operator cancels (Ctrl-C -> None): the verb
    # aborts and control returns to the shell (0), never a shell exit.
    conn = _FakeConn({"setup": _reply({"ask": "provider? "})})
    out = io.StringIO()
    code = attach_once_over(_as_socket(conn), "setup", lambda _p: None, out)
    assert code == 0


def test_stdin_prompt_returns_none_on_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise(_prompt: str) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(builtins, "input", _raise)
    assert _stdin_prompt("provider? ") is None  # no traceback escapes


def test_stream_turn_answers_choose_frames(monkeypatch: pytest.MonkeyPatch) -> None:
    """A `choose` frame renders a menu and sends the selection back."""
    conn = _RecordingConn()
    frames = iter(
        [
            json.dumps({"choose": {"prompt": "p", "options": ["a", "b"]}}).encode(),
            json.dumps({"chunk": "ok\n"}).encode(),
            json.dumps({"end": True, "exit": False}).encode(),
        ]
    )
    monkeypatch.setattr(client, "_choose_frame", lambda _spec: "b")
    out = io.StringIO()
    exit_flag = _stream_turn(frames, out, conn=cast(socket.socket, conn), ask=None)
    assert exit_flag is False
    assert conn.sent == [{"op": "input", "text": "b"}]
    assert out.getvalue() == "ok\n"


def test_stream_turn_aborts_when_choose_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _RecordingConn()
    frames = iter([json.dumps({"choose": {"prompt": "p", "options": ["a"]}}).encode()])
    monkeypatch.setattr(client, "_choose_frame", lambda _spec: None)
    out = io.StringIO()
    assert _stream_turn(frames, out, conn=cast(socket.socket, conn), ask=None)  # abort
    assert conn.sent == []


def test_stream_turn_answers_multiselect_frames(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A `multiselect` frame renders a checklist and sends the picks back as JSON."""
    conn = _RecordingConn()
    frames = iter(
        [
            json.dumps(
                {"multiselect": {"prompt": "p", "options": ["a", "b"]}}
            ).encode(),
            json.dumps({"end": True, "exit": False}).encode(),
        ]
    )
    monkeypatch.setattr(client, "_multiselect_frame", lambda _spec: ["a", "b"])
    out = io.StringIO()
    exit_flag = _stream_turn(frames, out, conn=cast(socket.socket, conn), ask=None)
    assert exit_flag is False
    assert conn.sent == [{"op": "input", "text": json.dumps(["a", "b"])}]


def test_stream_turn_aborts_when_multiselect_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _RecordingConn()
    frames = iter(
        [json.dumps({"multiselect": {"prompt": "p", "options": ["a"]}}).encode()]
    )
    monkeypatch.setattr(client, "_multiselect_frame", lambda _spec: None)
    out = io.StringIO()
    assert _stream_turn(frames, out, conn=cast(socket.socket, conn), ask=None)  # abort
    assert conn.sent == []
