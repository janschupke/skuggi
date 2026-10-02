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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

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
) -> CommandResult:
    """Execute `argv` directly (no shell), capturing output and timing.

    A timeout is a result, not an exception: the harness records a timed-out
    command like any other rather than letting it abort the turn.
    """
    started = datetime.now(UTC)
    command = " ".join(argv)
    try:
        completed = subprocess.run(  # noqa: S603 -- shell=False, argv is not model-shell-parsed
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd),
            env=dict(env) if env is not None else None,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        log.warning("command timed out after %ss: %s", timeout, command)
        return CommandResult(
            command=command,
            exit_code=_TIMEOUT_EXIT,
            stdout=_cap(_decode(exc.stdout)),
            stderr=_cap(_decode(exc.stderr) + f"\n[timed out after {timeout}s]"),
            started_at=started,
            finished_at=datetime.now(UTC),
        )
    except (OSError, ValueError) as exc:
        # A missing binary or a bad argv is a failed command, not a crash. Log it
        # so "tool not installed" is distinguishable from "tool ran and failed".
        log.warning("could not spawn command %r: %s", command, exc)
        return CommandResult(
            command=command,
            exit_code=_SPAWN_ERROR_EXIT,
            stdout="",
            stderr=f"error: could not run command: {exc}",
            started_at=started,
            finished_at=datetime.now(UTC),
        )
    return CommandResult(
        command=command,
        exit_code=completed.returncode,
        stdout=_cap(completed.stdout or ""),
        stderr=_cap(completed.stderr or ""),
        started_at=started,
        finished_at=datetime.now(UTC),
    )


def _decode(raw: str | bytes | None) -> str:
    """Coerce TimeoutExpired's partial output, which may be bytes or str."""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return raw
