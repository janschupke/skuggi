"""Bounded subprocess execution for agent-proposed commands.

This is the *captured, non-interactive* path: the worker proposes an argv, the
engagement guard clears it, and (only in autonomous mode) it runs here and its
stdout/stderr/exit code are captured for the ledger. The operator's interactive
shell is a different path entirely -- see ``skuggi.shell`` -- because a live
terminal needs a PTY and its colours, while a captured tool result needs plain
text.

Two bounds mirror ``tools.py``'s discipline, and for the same reason (the argv
originates with the model): the command never runs through a shell
(``shell=False``, so there is no shell-injection surface -- the argv is exec'd
directly), and both output streams are byte-capped so a chatty scanner cannot
blow up the ledger or a prompt.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO

from skuggi.common.logs import get_logger

log = get_logger(__name__)

# The only environment variables an agent-proposed tool inherits. Model-proposed
# commands run third-party binaries against a (possibly hostile) target, so the
# harness hands them a minimal, non-secret environment rather than the operator's
# whole `os.environ` -- a provider API key must never reach a scanner that could
# log or exfiltrate it. PATH/HOME and friends keep ordinary tools working;
# proxy/CA vars keep networked tools honest. Prefixes catch LC_* etc.
_ENV_ALLOW = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "TERM",
        "TZ",
        "TMPDIR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
    }
)
_ENV_ALLOW_PREFIXES = ("LC_",)


def safe_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """A minimal, secret-free environment for a spawned tool.

    Allow-list, not deny-list: only the names in ``_ENV_ALLOW`` (plus ``LC_*``)
    survive, so a new secret in the operator's environment can never leak into a
    scanner by default. Reads ``os.environ`` when ``base`` is not given.
    """
    source = os.environ if base is None else base
    return {
        key: value
        for key, value in source.items()
        if key in _ENV_ALLOW or key.startswith(_ENV_ALLOW_PREFIXES)
    }


# A scan can emit megabytes; the ledger and any prompt that echoes a result
# both need this bounded. Shared with tools.file_read (same 256 KiB ceiling).
MAX_CAPTURE_BYTES = 262_144
_TRUNCATED = "\n...[truncated]"

# Wall-clock cap on any single autonomously executed command. One source of
# truth: both config.Settings.command_timeout_s and the graph's GraphDeps
# default reference this so the two can never drift apart.
DEFAULT_COMMAND_TIMEOUT_S = 120.0

# Sentinel exit codes for outcomes that are not a real process status. Negative
# so they cannot collide with a real exit status (0-255) or a signal (reported
# negative by Popen but never this large in magnitude).
_TIMEOUT_EXIT = -100
_SPAWN_ERROR_EXIT = -101


def _cap(text: str) -> str:
    """Byte-cap captured output, marking it when it was truncated."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_CAPTURE_BYTES:
        return text
    clipped = encoded[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    return clipped + _TRUNCATED


@dataclass(frozen=True, slots=True)
class CommandResult:
    """The outcome of one executed command."""

    command: str
    exit_code: int
    stdout: str
    stderr: str
    started_at: datetime
    finished_at: datetime

    @property
    def timed_out(self) -> bool:
        """Whether the command was killed for exceeding its timeout."""
        return self.exit_code == _TIMEOUT_EXIT


def run(
    argv: Sequence[str],
    *,
    timeout: float,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    display_command: str | None = None,
) -> CommandResult:
    """Execute `argv` directly (no shell), capturing output and timing.

    A timeout is a result, not an exception: the harness records a timed-out
    command like any other rather than letting it abort the turn.
    """
    started = datetime.now(UTC)
    # The rehydrated argv may carry a real secret (a vaulted credential is
    # rehydrated just before exec); log and record the caller-supplied
    # placeholder form instead, so the diagnostic log and the ledger never hold
    # a plaintext secret. Falls back to the argv join when none is given.
    command = display_command if display_command is not None else " ".join(argv)
    # Spool output to temp files rather than pipes read into memory: a chatty or
    # hostile tool can emit gigabytes within the timeout, and `capture_output`
    # would buffer all of it before `_cap` ever ran. Here only `MAX_CAPTURE_BYTES`
    # (+1, to detect overflow) is ever read back into memory; the rest stays on
    # disk and is discarded with the temp file. Disk use is bounded by runtime.
    with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
        try:
            proc = subprocess.Popen(  # noqa: S603 -- shell=False, argv is not model-shell-parsed
                list(argv),
                stdout=out_f,
                stderr=err_f,
                cwd=str(cwd),
                env=dict(env) if env is not None else None,
            )
        except (OSError, ValueError) as exc:
            # A missing binary or a bad argv is a failed command, not a crash.
            log.warning("could not spawn command %r: %s", command, exc)
            return CommandResult(
                command=command,
                exit_code=_SPAWN_ERROR_EXIT,
                stdout="",
                stderr=f"error: could not run command: {exc}",
                started_at=started,
                finished_at=datetime.now(UTC),
            )
        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            timed_out = True
        stdout = _cap(_read_capped(out_f))
        stderr = _read_capped(err_f)
        if timed_out:
            log.warning("command timed out after %ss: %s", timeout, command)
            stderr = _cap(stderr + f"\n[timed out after {timeout}s]")
            exit_code = _TIMEOUT_EXIT
        else:
            stderr = _cap(stderr)
            exit_code = proc.returncode
        return CommandResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            started_at=started,
            finished_at=datetime.now(UTC),
        )


def _read_capped(handle: IO[bytes]) -> str:
    """Read at most ``MAX_CAPTURE_BYTES`` + 1 bytes from a spool file, decoded.

    The +1 lets ``_cap`` tell "exactly at the ceiling" from "over it" and mark
    the latter truncated. Reading a bounded amount is what keeps a huge spool
    from being pulled into memory.
    """
    handle.seek(0)
    return handle.read(MAX_CAPTURE_BYTES + 1).decode("utf-8", errors="replace")
