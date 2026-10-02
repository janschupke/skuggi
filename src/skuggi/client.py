"""The thin ``skuggi-client`` the wrapped shell calls for ``/skuggi`` lines.

It is deliberately tiny -- only ``json``, ``os``, ``socket``, ``sys`` -- so that
starting it per ``/skuggi`` invocation is cheap; the warm agent lives in the
daemon, not here. It reads ``$SKUGGI_SOCK`` (set by the shell wrapper), sends the
operator's input as one request, streams the reply to stdout, and exits ``42``
when the daemon says to leave -- the shell's ``/skuggi`` function hook turns
that into a shell ``exit``. ``Ctrl+C`` during a turn just returns to the prompt.

A bare ``/skuggi`` (no arguments) instead **attaches** an interactive loop to the
same warm daemon: the client runs a local prompt, sending each line and
streaming the reply over one persistent connection, so the session (thread,
ledger, engagement) stays live across lines. A blank line, ``exit``/``quit`` or
``Ctrl+D`` leaves the loop and hands the shell back -- the daemon stays warm.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
from collections.abc import Callable, Iterator
from typing import TextIO

from skuggi.logs import get_logger, setup_logging

log = get_logger(__name__)

_EXIT_SHELL = 42


class _Spinner:
    """A stderr 'working...' spinner, active only on a real terminal.

    Keeps ``/skuggi`` from looking hung while the daemon plans a turn or probes
    the host. It writes to stderr (never the piped stdout) and erases itself
    when the first response frame arrives. No-op off a tty, so tests are
    unaffected.
    """

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def maybe_start(self) -> None:
        """Start spinning if stderr is a terminal."""
        if sys.stderr.isatty():  # pragma: no cover -- needs a real terminal
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()

    def _spin(self) -> None:  # pragma: no cover -- needs a real terminal
        frames = "|/-\\"
        i = 0
        while not self._stop.wait(0.12):
            sys.stderr.write(f"\r{frames[i % 4]} working...")
            sys.stderr.flush()
            i += 1

    def stop(self) -> None:
        """Stop the spinner and erase its line (idempotent)."""
        self._stop.set()
        if self._thread is not None:  # pragma: no cover -- needs a real terminal
            self._thread.join()
            self._thread = None
            sys.stderr.write("\r\x1b[K")
            sys.stderr.flush()


def build_message(text: str) -> dict[str, str]:
    """The request object for one line of operator input."""
    return {"op": "input", "text": text}


def build_record_message(text: str) -> dict[str, str]:
    """The request object for logging a free-typed shell command (fire-and-forget)."""
    return {"op": "record", "text": text}


def record_over(conn: socket.socket, text: str) -> None:
    """Send a passthrough-record request; do not wait for a reply.

    The shell hook backgrounds this, so it must never block on the daemon: it
    sends one frame and returns. Split from ``record`` so it is testable over a
    plain socket pair.
    """
    conn.sendall((json.dumps(build_record_message(text)) + "\n").encode())


def record(sock_path: str, text: str) -> int:  # pragma: no cover -- real socket
    """Forward a free-typed command to the daemon to log; fail open, never block.

    A dead or slow daemon must never disrupt the operator's shell, so any socket
    error is swallowed and the exit code is always ``0``.
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(2.0)
            conn.connect(sock_path)
            record_over(conn, text)
    except OSError as exc:
        # Fail-open by design (a dead daemon must not disrupt the shell), but the
        # dropped passthrough record is worth a trace.
        log.debug("passthrough record not delivered: %s", exc)
        return 0
    return 0


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
    spinner = _Spinner()
    spinner.maybe_start()
    exit_shell = False
    try:
        for line in _iter_lines(conn):
            spinner.stop()  # first frame arrived; stop looking busy
            try:
                resp = json.loads(line)
            except json.JSONDecodeError:
                log.warning("dropping malformed daemon frame: %r", line)
                continue
            chunk = resp.get("chunk")
            if chunk:
                out.write(chunk)
                out.flush()
            if resp.get("end"):
                exit_shell = bool(resp.get("exit"))
                break
    finally:
        spinner.stop()
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
        log.exception("cannot reach the harness over %s", sock_path)
        print(f"skuggi: cannot reach the harness: {e}", file=sys.stderr)
        return 1


_PROMPT = "🐐 skuggi> "

# Verbs that drive an interactive round-trip and so need an attach session rather
# than a one-shot request: setup (prompts + menus), engagement (the wizard),
# config (a natural-language request is LLM + confirm), and login (streams OAuth
# progress). Everything else stays one-shot.
_INTERACTIVE_VERBS = frozenset({"setup", "engagement", "config", "login"})


def _choose_frame(spec: object) -> str | None:  # pragma: no cover -- real terminal
    """Render a ``{"choose"}`` frame as an arrow-key menu; return the selection.

    prompt_toolkit is imported here, not at module load, so the fire-and-forget
    ``--record`` path never pays for it.
    """
    from skuggi import menu  # noqa: PLC0415 -- lazy; keep ptk off the hot path

    data = spec if isinstance(spec, dict) else {}
    prompt = str(data.get("prompt", "choose:"))
    options = [str(option) for option in data.get("options", [])]
    raw_default = data.get("default")
    default = raw_default if isinstance(raw_default, str) else None
    return menu.select(prompt, options, default=default)


def _stream_turn(
    frames: Iterator[bytes],
    out: TextIO,
    *,
    conn: socket.socket | None = None,
    ask: Callable[[str], str | None] | None = None,
) -> bool:
    """Consume one reply (through its terminal frame) from `frames`.

    Writes each chunk to `out`; returns the daemon's exit flag. An ``{"ask": …}``
    frame is an interactive prompt (the engagement wizard): `ask` reads the
    operator's answer and it is sent back over `conn`, so a whole wizard runs
    inside one reply stream. A ``None`` answer (operator aborted) leaves the
    loop. Returns ``False`` if `frames` runs dry before an ``end`` frame (the
    connection closed mid-turn). Shared by the attach loop, which reads many
    replies off one long-lived frame stream.
    """
    for line in frames:
        try:
            resp = json.loads(line)
        except json.JSONDecodeError:
            log.warning("dropping malformed daemon frame: %r", line)
            continue
        if "ask" in resp and conn is not None and ask is not None:
            answer = ask(str(resp["ask"]))
            if answer is None:  # operator aborted the wizard
                return True
            conn.sendall((json.dumps(build_message(answer)) + "\n").encode())
            continue
        if "choose" in resp and conn is not None:
            selection = _choose_frame(resp["choose"])
            if selection is None:  # operator aborted the menu
                return True
            conn.sendall((json.dumps(build_message(selection)) + "\n").encode())
            continue
        chunk = resp.get("chunk")
        if chunk:
            out.write(chunk)
            out.flush()
        if resp.get("end"):
            return bool(resp.get("exit"))
    return False


def attach_over(
    conn: socket.socket, prompt_in: Callable[[str], str | None], out: TextIO
) -> int:
    """Run an interactive attach session over an open connection.

    Sends the ``attach`` op, then loops: read an operator line via
    ``prompt_in(prompt)`` (a ``None`` return, EOF, ``Ctrl+C`` or a blank line
    ends the session), send it, and stream the reply -- passing `prompt_in` on
    so a wizard's ``ask`` frames prompt with their own text. Leaving the loop
    always returns to the shell (``0``): fully quitting the wrapped shell is the
    one-shot ``/skuggi exit``, handled by the shell hook before it reaches here.
    Split from ``attach`` so it is testable over a plain socket pair.
    """
    conn.sendall((json.dumps({"op": "attach"}) + "\n").encode())
    frames = _iter_lines(conn)
    while True:
        try:
            line = prompt_in(_PROMPT)
        except (EOFError, KeyboardInterrupt):
            out.write("\n")
            break
        if line is None:
            break
        line = line.strip()
        if not line:
            break
        conn.sendall((json.dumps(build_message(line)) + "\n").encode())
        if _stream_turn(frames, out, conn=conn, ask=prompt_in):
            break
    return 0


def attach(  # pragma: no cover -- interactive loop over a real socket
    sock_path: str, prompt_in: Callable[[str], str | None], out: TextIO
) -> int:
    """Connect to the daemon and run an interactive attach loop (see above)."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(sock_path)
            return attach_over(conn, prompt_in, out)
    except OSError as e:
        log.exception("cannot reach the harness over %s", sock_path)
        print(f"skuggi: cannot reach the harness: {e}", file=sys.stderr)
        return 1


def attach_once_over(
    conn: socket.socket,
    text: str,
    prompt_in: Callable[[str], str | None],
    out: TextIO,
) -> int:
    """Run ONE interactive verb over an open connection, then return.

    Like ``run_over`` but attaches first, so the daemon routes the verb through
    its interactive handlers (setup/wizard) and its ``{"ask"}``/``{"choose"}``
    round-trips reach the operator. Used for ``/skuggi setup`` &c. -- the verb
    runs to completion and control returns to the shell (it does not drop into
    the persistent chat loop). Split from ``attach_once`` so it is testable over
    a plain socket pair.
    """
    conn.sendall((json.dumps({"op": "attach", "mode": "once"}) + "\n").encode())
    frames = _iter_lines(conn)
    conn.sendall((json.dumps(build_message(text)) + "\n").encode())
    # These verbs never signal a shell exit; a True here means the operator
    # aborted (Ctrl-C), which returns to the shell just the same.
    _stream_turn(frames, out, conn=conn, ask=prompt_in)
    return 0


def attach_once(  # pragma: no cover -- opens a real socket
    sock_path: str, text: str, prompt_in: Callable[[str], str | None], out: TextIO
) -> int:
    """Connect to the daemon and run one interactive verb (see ``attach_once_over``)."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(sock_path)
            return attach_once_over(conn, text, prompt_in, out)
    except KeyboardInterrupt:
        out.write("\n")
        return 0
    except OSError as e:
        log.exception("cannot reach the harness over %s", sock_path)
        print(f"skuggi: cannot reach the harness: {e}", file=sys.stderr)
        return 1


def _stdin_prompt(prompt: str) -> str | None:  # pragma: no cover -- real terminal
    """Read one line from the operator, returning ``None`` on EOF or Ctrl-C.

    Ctrl-C must abort the current prompt (a wizard/setup question) cleanly, not
    tear the client down with a traceback: returning ``None`` makes the flow
    cancel and the connection close, which the daemon reads as an abort.
    """
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print()  # move off the prompt line so the next output is clean
        return None


def main() -> int:  # pragma: no cover -- console entry point
    """Console entry point invoked by the shell's ``/skuggi`` hook."""
    setup_logging()
    sock_path = os.environ.get("SKUGGI_SOCK")
    if not sock_path:
        print("skuggi: not running inside a skuggi shell", file=sys.stderr)
        return 1
    args = sys.argv[1:]
    if args and args[0] == "--record":  # shell hook logging a free-typed command
        return record(sock_path, " ".join(args[1:]))
    if not args:  # bare `/skuggi` -> attach an interactive loop to the warm daemon
        return attach(sock_path, _stdin_prompt, sys.stdout)
    if args[0] in _INTERACTIVE_VERBS:
        # Verbs that prompt (setup, the engagement wizard, login progress) need an
        # attach session so their ask/choose round-trips reach the operator --
        # `/skuggi setup` runs the flow instead of being refused as one-shot.
        return attach_once(sock_path, " ".join(args), _stdin_prompt, sys.stdout)
    return run(sock_path, " ".join(args), sys.stdout)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
