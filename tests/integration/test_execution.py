"""L2: real subprocess execution, plus the pure output cap.

The spawning tests are marked `runs_commands`, which lifts the blanket
subprocess block. `_cap` needs no process and stays unmarked.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from skuggi.common import execution
from skuggi.common.execution import MAX_CAPTURE_BYTES, _cap, run


def test_cap_truncates_oversized_output() -> None:
    capped = _cap("x" * (MAX_CAPTURE_BYTES + 1000))
    assert capped.endswith("[truncated]")
    assert len(capped.encode("utf-8")) <= MAX_CAPTURE_BYTES + len("\n...[truncated]")


def test_cap_leaves_small_output_untouched() -> None:
    assert _cap("hello") == "hello"


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
