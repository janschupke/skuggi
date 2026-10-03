"""L3: an engagement survives a restart (cwd-local discovery)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from skuggi.agent.core import AgentCore
from skuggi.config.config import config_path
from skuggi.engagement.workspace import WorkspaceLayout, has_engagement
from tests.conftest import offline_settings, wire_offline_core


def test_cwd_engagement_is_auto_adopted_when_none_configured(
    tmp_path: Path, pentest_configs: Callable[..., Path]
) -> None:
    pentest_configs()  # writes ./scope.json (the engagement IS the cwd)
    # A fresh boot with NO engagement_root override adopts the engagement in the
    # current directory, so a restart finds it again.
    core = AgentCore(offline_settings(tmp_path))
    wire_offline_core(core)
    try:
        assert core.engagement is not None
        assert core.engagement.name == "test-eng"
    finally:
        core.close()


def test_adopt_engagement_does_not_write_the_root_to_config(
    tmp_path: Path, pentest_configs: Callable[..., Path]
) -> None:
    # An engagement is cwd-scoped, so adopting one must NOT persist its root to
    # the machine-global config.json (restart recovery is a cwd probe).
    pentest_configs()
    core = AgentCore(offline_settings(tmp_path))
    wire_offline_core(core)
    try:
        core.adopt_engagement(Path.cwd())
    finally:
        core.close()
    path = config_path()
    saved = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    assert "engagement_root" not in saved


def test_explicit_root_without_scope_falls_back_to_cwd(
    tmp_path: Path, pentest_configs: Callable[..., Path]
) -> None:
    pentest_configs()  # the engagement is in cwd
    # An engagement_root override that holds no scope.json is ignored in favour of
    # the engagement discovered in the current directory.
    empty = tmp_path / "empty-root"
    empty.mkdir()
    core = AgentCore(offline_settings(tmp_path, engagement_root=empty))
    wire_offline_core(core)
    try:
        assert core.engagement is not None
        assert core.engagement.name == "test-eng"
    finally:
        core.close()


def test_has_engagement_requires_a_scope_file(tmp_path: Path) -> None:
    half = tmp_path / "half-made"
    half.mkdir()  # no scope.json
    assert not has_engagement(half, WorkspaceLayout())
    assert not has_engagement(tmp_path / "does-not-exist")
    (half / "scope.json").write_text("{}", encoding="utf-8")
    assert has_engagement(half, WorkspaceLayout())
