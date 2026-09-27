"""A thin, typed wrapper over ``docker compose`` for one lab stack.

Mirrors the subprocess discipline of ``tests/e2e/conftest.py::_compose``: a fixed
argv, ``shell=False``, ``check=False`` so the caller decides how to react. All
lab orchestration goes through here so the CLI never builds a docker argv itself.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path


def _run(
    compose_file: Path, *args: str, capture: bool = False
) -> subprocess.CompletedProcess[str]:
    """Run ``docker compose -f <compose_file> <args...>``.

    ``capture`` keeps stdout/stderr for inspection; otherwise the child streams
    straight to the operator's terminal (build logs, ``--wait`` progress).
    """
    argv = ["docker", "compose", "-f", str(compose_file), *args]
    return subprocess.run(
        argv,
        capture_output=capture,
        text=True,
        check=False,
    )


def up(compose_file: Path, *, build: bool = True) -> int:
    """Bring the stack up detached and wait for healthy; return the exit code."""
    args = ["up", "-d", "--wait"]
    if build:
        args.append("--build")
    return _run(compose_file, *args).returncode


def down(compose_file: Path, *, volumes: bool = False) -> int:
    """Stop the stack; drop volumes when ``volumes`` (a full planted-state reset)."""
    args = ["down"]
    if volumes:
        args.append("-v")
    return _run(compose_file, *args).returncode


def exec_in(compose_file: Path, service: str, argv: Sequence[str]) -> int:
    """Exec a command in a running service container; return its exit code."""
    return _run(compose_file, "exec", "-T", service, *argv).returncode


def exec_output(compose_file: Path, service: str, argv: Sequence[str]) -> str:
    """Exec in a service and return its stdout ('' on any failure)."""
    proc = _run(compose_file, "exec", "-T", service, *argv, capture=True)
    return proc.stdout if proc.returncode == 0 else ""


def is_up(compose_file: Path) -> bool:
    """Whether at least one service container is currently running."""
    proc = _run(compose_file, "ps", "--status", "running", "-q", capture=True)
    return proc.returncode == 0 and bool(proc.stdout.strip())
