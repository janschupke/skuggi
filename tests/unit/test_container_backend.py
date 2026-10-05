"""L1: the container backend builds a locked-down run argv (no live daemon).

The runtime invocation is captured through an injected ``run_fn`` so the test
asserts the isolation flags without a real docker/podman.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from skuggi.common.backends import ContainerBackend, ContainerConfig
from skuggi.common.execution import CommandResult


def _capture() -> tuple[list[list[str]], Any]:
    seen: list[list[str]] = []

    def fake(argv: list[str], **_k: Any) -> CommandResult:
        seen.append(argv)
        now = datetime.now(UTC)
        return CommandResult("cmd", 0, "ok", "", now, now)

    return seen, fake


def _backend(**cfg: Any) -> tuple[list[list[str]], ContainerBackend]:
    seen, fake = _capture()
    config = ContainerConfig(image="img:1", **cfg)
    return seen, ContainerBackend(config=config, run_fn=fake)


def test_wrap_applies_the_isolation_flags(tmp_path: Path) -> None:
    seen, backend = _backend()
    backend.run(["nmap", "-sV", "10.0.0.5"], timeout=30, cwd=tmp_path)
    [argv] = seen
    assert argv[:2] == ["docker", "run"]
    for flag in ("--rm", "--read-only", "--cap-drop", "--security-opt", "--pids-limit"):
        assert flag in argv
    assert "no-new-privileges" in argv
    # the tool argv comes after the image, in order
    assert argv[-3:] == ["nmap", "-sV", "10.0.0.5"]
    assert "img:1" in argv


def test_wrap_mounts_only_the_workspace_writable(tmp_path: Path) -> None:
    seen, backend = _backend()
    backend.run(["ls"], timeout=10, cwd=tmp_path)
    [argv] = seen
    mount = str(tmp_path.resolve())
    assert "-v" in argv
    assert f"{mount}:{mount}:rw" in argv
    # working dir is the mount
    assert argv[argv.index("-w") + 1] == mount


def test_network_none_is_the_default(tmp_path: Path) -> None:
    seen, backend = _backend()
    backend.run(["ls"], timeout=10, cwd=tmp_path)
    [argv] = seen
    assert argv[argv.index("--network") + 1] == "none"


def test_network_and_runtime_are_configurable(tmp_path: Path) -> None:
    seen, backend = _backend(runtime="podman", network="scoped-egress")
    backend.run(["ls"], timeout=10, cwd=tmp_path)
    [argv] = seen
    assert argv[0] == "podman"
    assert argv[argv.index("--network") + 1] == "scoped-egress"


def test_tool_env_is_injected_not_inherited(tmp_path: Path) -> None:
    seen, backend = _backend()
    backend.run(["ls"], timeout=10, cwd=tmp_path, env={"TARGET": "10.0.0.5"})
    [argv] = seen
    assert "-e" in argv
    assert "TARGET=10.0.0.5" in argv


def test_runs_as_the_invoking_uid(tmp_path: Path) -> None:
    if not hasattr(os, "getuid"):  # pragma: no cover -- POSIX only
        return
    seen, backend = _backend()
    backend.run(["ls"], timeout=10, cwd=tmp_path)
    [argv] = seen
    assert argv[argv.index("-u") + 1] == f"{os.getuid()}:{os.getgid()}"
