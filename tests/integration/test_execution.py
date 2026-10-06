"""L2: real subprocess execution, plus the pure spool-read cap.

The spawning tests are marked `runs_commands`, which lifts the blanket
subprocess block. `_read_spool` needs a temp file, not a process, and stays
unmarked.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

from skuggi.common import execution
from skuggi.common.execution import MAX_CAPTURE_BYTES, _read_spool, run


def test_spool_read_keeps_head_and_tail_of_oversized_output() -> None:
    # The salient result of a verbose tool sits at the END (audit D4); a
    # head-only cap would discard it, so an over-ceiling spool keeps both ends.
    with tempfile.TemporaryFile() as handle:
        handle.write(b"HEAD" + b"x" * (MAX_CAPTURE_BYTES * 2) + b"TAIL")
        out = _read_spool(handle)
    assert out.startswith("HEAD")
    assert out.endswith("TAIL")
    assert "bytes elided" in out
    # head + tail sum to the ceiling; only the short elision marker is overhead.
    assert len(out.encode("utf-8")) <= MAX_CAPTURE_BYTES + 64


def test_spool_read_leaves_small_output_untouched() -> None:
    with tempfile.TemporaryFile() as handle:
        handle.write(b"hello")
        out = _read_spool(handle)
    assert out == "hello"


@pytest.mark.runs_commands
def test_echo_captures_stdout_and_exit(tmp_path: Path) -> None:
    result = run(["echo", "hello"], timeout=10, cwd=tmp_path)
    assert result.exit_code == 0
    assert "hello" in result.stdout
    assert result.finished_at >= result.started_at


@pytest.mark.runs_commands
def test_missing_binary_is_a_failed_command_not_a_crash(tmp_path: Path) -> None:
    result = run(["definitely-not-a-real-binary-zzz"], timeout=10, cwd=tmp_path)
    assert result.exit_code == execution._SPAWN_ERROR_EXIT
    assert "could not run" in result.stderr


@pytest.mark.runs_commands
def test_timeout_is_recorded_not_raised(tmp_path: Path) -> None:
    result = run(["sleep", "5"], timeout=0.5, cwd=tmp_path)
    assert result.timed_out
    assert "timed out" in result.stderr


# --- S2: spawned tools must not inherit the operator's secrets --------------


def test_safe_env_drops_secrets_keeps_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-other")
    monkeypatch.setenv("LC_ALL", "C")
    env = execution.safe_env()
    assert env["PATH"] == "/usr/bin"
    assert env["LC_ALL"] == "C"
    assert "ANTHROPIC_API_KEY" not in env
    assert "OPENAI_API_KEY" not in env


@pytest.mark.runs_commands
def test_spawned_process_never_sees_a_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: a tool run with safe_env() cannot read a provider key."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-super-secret-value")
    dump = (
        "import os, sys\n"
        "sys.stdout.write('\\n'.join(f'{k}={v}' for k, v in os.environ.items()))"
    )
    result = run(
        [sys.executable, "-c", dump],
        timeout=30,
        cwd=tmp_path,
        env=execution.safe_env(),
    )
    assert result.exit_code == 0
    assert "sk-super-secret-value" not in result.stdout
    assert "ANTHROPIC_API_KEY" not in result.stdout


# --- F1: a chatty tool must not be buffered unboundedly into memory ---------


@pytest.mark.runs_commands
def test_large_output_is_capped_not_buffered_whole(tmp_path: Path) -> None:
    """Emit ~4x the cap; a bounded head+tail slice with the END preserved."""
    body = f"'A' + 'x' * ({MAX_CAPTURE_BYTES} * 4) + 'Z'"
    program = f"import sys; sys.stdout.write({body})"
    result = run([sys.executable, "-c", program], timeout=30, cwd=tmp_path)
    assert result.exit_code == 0
    assert result.stdout.startswith("A")
    assert result.stdout.endswith("Z")  # the tail survives the cap (audit D4)
    assert "bytes elided" in result.stdout
    assert len(result.stdout.encode("utf-8")) <= MAX_CAPTURE_BYTES + 64


@pytest.mark.runs_commands
def test_timeout_still_captures_partial_output(tmp_path: Path) -> None:
    program = (
        "import sys, time\n"
        "sys.stdout.write('partial'); sys.stdout.flush()\n"
        "time.sleep(5)"
    )
    result = run([sys.executable, "-c", program], timeout=0.5, cwd=tmp_path)
    assert result.timed_out
    assert "partial" in result.stdout
    assert "timed out" in result.stderr


@pytest.mark.runs_commands
def test_display_command_is_recorded_not_the_rehydrated_argv(tmp_path: Path) -> None:
    """Command must be the placeholder form, not the secret argv (audit C2)."""
    result = run(
        ["echo", "s3cr3t-password"],
        timeout=10,
        cwd=tmp_path,
        display_command="echo \u00abSECRET:1\u00bb",
    )
    assert result.command == "echo \u00abSECRET:1\u00bb"
    assert "s3cr3t-password" not in result.command
    assert "s3cr3t-password" in result.stdout  # the real value still ran


# --- backend seam & host hardening ------------------------------------------


def test_resource_limits_unbounded_sets_nothing() -> None:
    """An unbounded limits object yields no preexec (the pre-hardening path)."""
    assert execution._rlimit_preexec(execution.ResourceLimits.unbounded()) is None


def test_rlimit_preexec_is_callable_on_posix() -> None:
    """On POSIX the default limits compile to an applicable preexec closure."""
    pytest.importorskip("resource")
    assert callable(execution._rlimit_preexec(execution.ResourceLimits()))


@pytest.mark.runs_commands
def test_host_backend_runs_like_the_module_run(tmp_path: Path) -> None:
    result = execution.HostBackend().run(["echo", "hi"], timeout=10, cwd=tmp_path)
    assert result.exit_code == 0
    assert "hi" in result.stdout


@pytest.mark.runs_commands
def test_host_backend_enforces_file_size_limit(tmp_path: Path) -> None:
    """A tool that writes past RLIMIT_FSIZE is stopped, not left to fill the disk."""
    pytest.importorskip("resource")
    backend = execution.HostBackend(
        limits=execution.ResourceLimits(
            cpu_seconds=None,
            address_space_bytes=None,
            max_processes=None,
            file_size_bytes=64 * 1024,  # 64 KiB
            open_files=None,
        )
    )
    program = (
        "f = open('big.bin', 'wb')\n"
        "f.write(b'x' * (4 * 1024 * 1024)); f.flush()\n"  # 4 MiB >> 64 KiB
    )
    result = backend.run([sys.executable, "-c", program], timeout=30, cwd=tmp_path)
    # The write is killed by SIGXFSZ (negative exit) or fails the write (nonzero);
    # either way the file never reaches the attempted 4 MiB.
    assert result.exit_code != 0
    written = (
        (tmp_path / "big.bin").stat().st_size if (tmp_path / "big.bin").exists() else 0
    )
    assert written <= 64 * 1024


@pytest.mark.runs_commands
def test_timeout_reaps_a_forked_grandchild(tmp_path: Path) -> None:
    """start_new_session + killpg: a helper the tool forks dies with its parent.

    The parent writes the grandchild's pid, forks a long sleeper, then sleeps
    itself past the deadline. After the timeout kill, the grandchild must be gone.
    """
    marker = tmp_path / "child.pid"
    program = (
        "import os, time, sys\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    time.sleep(60)\n"  # the grandchild
        "else:\n"
        f"    open({str(marker)!r}, 'w').write(str(pid))\n"
        "    time.sleep(60)\n"  # the parent, killed at timeout
    )
    result = execution.HostBackend().run(
        [sys.executable, "-c", program], timeout=1.0, cwd=tmp_path
    )
    assert result.timed_out
    time.sleep(0.3)  # let the SIGKILL propagate through the group
    child_pid = int(marker.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)  # 0 = existence probe; raises if already reaped
