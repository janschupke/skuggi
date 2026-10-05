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

import contextlib
import os
import signal
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Protocol, runtime_checkable

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


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """POSIX ``rlimit`` ceilings applied to a spawned tool (0/None = unset).

    A model-proposed tool runs third-party code; the host default bounds the one
    kind of runaway it can enforce without breaking legitimate tools -- a single
    file growing without bound (``RLIMIT_FSIZE``). Everything else is deliberately
    unset on the host, because each remaining ``rlimit`` breaks real tools when
    set as a blunt default:

    * ``RLIMIT_AS`` (virtual memory) -- JVM/Node/Python scanners reserve huge
      address space and die under a hard cap.
    * ``RLIMIT_CPU`` -- kills a legitimate long scan.
    * ``RLIMIT_NPROC`` -- is a *per-UID* process count, not per-session; on any
      machine already running many processes the child's first ``fork`` fails.
    * ``RLIMIT_NOFILE`` -- a high-concurrency scanner (masscan) needs thousands
      of fds; a blunt cap throttles it.

    Memory / CPU / process / fd / network bounding is the ``ContainerBackend``'s
    job (cgroups + ``--pids-limit`` + netns). On the host, the load-bearing
    containment of a runaway is the wall-clock timeout plus process-group reaping
    (``start_new_session`` + ``killpg``), not these ceilings. Callers that want a
    hard cap pass an explicit ``ResourceLimits``; the preexec sets soft == hard
    where it can and skips (never aborts on) a value above the inherited hard
    limit.
    """

    cpu_seconds: int | None = None
    address_space_bytes: int | None = None
    max_processes: int | None = None
    file_size_bytes: int | None = 1024 * 1024 * 1024  # 1 GiB any single file
    open_files: int | None = None

    @classmethod
    def unbounded(cls) -> ResourceLimits:
        """A limits object that sets nothing -- the pre-hardening behaviour."""
        return cls(
            cpu_seconds=None,
            address_space_bytes=None,
            max_processes=None,
            file_size_bytes=None,
            open_files=None,
        )


def _rlimit_preexec(limits: ResourceLimits) -> Callable[[], None] | None:
    """A ``preexec_fn`` that applies `limits` in the child, or None off POSIX.

    Imported lazily so the module stays importable on a platform without
    ``resource`` (Windows); returns None there so the caller simply spawns
    without ceilings rather than failing. The child is placed in its own session
    by ``start_new_session`` at the ``Popen`` call, not here, so a timeout kill
    can reap the whole process group.
    """
    try:
        import resource  # noqa: PLC0415 -- lazy; POSIX-only, keep off the import path
    except ImportError:
        return None

    pairs: list[tuple[int, int]] = []
    for attr, value in (
        ("RLIMIT_CPU", limits.cpu_seconds),
        ("RLIMIT_AS", limits.address_space_bytes),
        ("RLIMIT_NPROC", limits.max_processes),
        ("RLIMIT_FSIZE", limits.file_size_bytes),
        ("RLIMIT_NOFILE", limits.open_files),
    ):
        res = getattr(resource, attr, None)
        if res is not None and value is not None:
            pairs.append((res, value))
    if not pairs:
        return None

    def _apply() -> None:  # pragma: no cover -- runs in the forked child
        for res, value in pairs:
            # A ceiling above the inherited hard limit, or one the platform
            # refuses: skip it rather than abort the spawn. The wall-clock
            # timeout remains the backstop.
            with contextlib.suppress(ValueError, OSError):
                resource.setrlimit(res, (value, value))

    return _apply


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


def run(  # noqa: PLR0913 -- keyword-only knobs; a single exec entry point
    argv: Sequence[str],
    *,
    timeout: float,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    display_command: str | None = None,
    preexec_fn: Callable[[], None] | None = None,
) -> CommandResult:
    """Execute `argv` directly (no shell), capturing output and timing.

    A timeout is a result, not an exception: the harness records a timed-out
    command like any other rather than letting it abort the turn. The child is
    spawned in its own session (``start_new_session``) so a timeout kills the
    whole process group, not just the immediate child -- a tool that forks
    helpers (nmap's NSE, a shelled-out cracker) cannot outlive its deadline.
    ``preexec_fn`` applies resource ceilings in the child (see ``HostBackend``).
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
                start_new_session=True,
                preexec_fn=preexec_fn,  # noqa: PLW1509 -- POSIX rlimits; None off POSIX
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
            _kill_group(proc)
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


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    """Kill the child's whole process group, falling back to the child alone.

    ``start_new_session`` made the child a process-group leader, so signalling
    the group reaps any helper it forked. If the group is already gone (the
    child exited between the timeout and here) or the platform lacks ``killpg``,
    fall back to killing the child directly.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError, AttributeError):
        with contextlib.suppress(ProcessLookupError):
            proc.kill()


def _read_capped(handle: IO[bytes]) -> str:
    """Read at most ``MAX_CAPTURE_BYTES`` + 1 bytes from a spool file, decoded.

    The +1 lets ``_cap`` tell "exactly at the ceiling" from "over it" and mark
    the latter truncated. Reading a bounded amount is what keeps a huge spool
    from being pulled into memory.
    """
    handle.seek(0)
    return handle.read(MAX_CAPTURE_BYTES + 1).decode("utf-8", errors="replace")


@runtime_checkable
class ExecutionBackend(Protocol):
    """How a guarded, in-scope command is actually run.

    One method, so the guard/record path in ``agent.executor`` never knows (or
    cares) whether a command runs as a hardened host subprocess or inside a
    throwaway container with a network-namespace egress allow-list. The backend
    is resolved per engagement and carried on ``GraphDeps``; the executor calls
    ``backend.run(...)`` exactly where it used to call the module ``run``.
    """

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        display_command: str | None = None,
    ) -> CommandResult:
        """Execute `argv`, returning its captured, bounded result."""
        ...


@dataclass(frozen=True, slots=True)
class HostBackend:
    """The default backend: a hardened host subprocess (no container).

    Adds resource ceilings (``ResourceLimits``) and process-group reaping to the
    bare ``run``. It is *not* an OS sandbox -- a cleared command still runs as
    the operator's uid with host network reach -- so it is the right default for
    the dev loop and a single-operator box, with ``ContainerBackend`` the opt-in
    for untrusted targets or hard egress control. Egress on this backend is
    enforced (best-effort) by the proxy vars in ``safe_env`` when the operator
    configures a filtering proxy; see the egress gate.
    """

    limits: ResourceLimits = ResourceLimits()

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        display_command: str | None = None,
    ) -> CommandResult:
        """Run `argv` as a hardened host subprocess."""
        return run(
            argv,
            timeout=timeout,
            cwd=cwd,
            env=env,
            display_command=display_command,
            preexec_fn=_rlimit_preexec(self.limits),
        )
