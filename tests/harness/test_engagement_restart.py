"""L3: an engagement survives a restart (the bug the shakedown surfaced)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from skuggi.agent.core import AgentCore
from skuggi.config.config import config_path
from skuggi.engagement.workspace import WorkspaceLayout, list_engagements
from tests.conftest import offline_settings, wire_offline_core


def test_sole_engagement_is_auto_loaded_when_none_configured(
    tmp_path: Path, pentest_configs: Callable[..., Path]
) -> None:
    pentest_configs()  # writes ./engagements/test-eng/scope.json
    # A fresh boot with NO configured engagement adopts the one on disk (the
    # cwd-local recovery path), so a restart finds the engagement again.
    core = AgentCore(offline_settings(tmp_path))
    wire_offline_core(core)
    try:
        assert core.engagement is not None
        assert core.engagement.name == "test-eng"
    finally:
        core.close()


def test_load_engagement_persists_the_name_to_config(
    tmp_path: Path, pentest_configs: Callable[..., Path]
) -> None:
    pentest_configs()
    core = AgentCore(offline_settings(tmp_path, engagement="test-eng"))
    wire_offline_core(core)
    try:
        core.load_engagement("test-eng")
    finally:
        core.close()
    saved = json.loads(config_path().read_text(encoding="utf-8"))
    assert saved["engagement"] == "test-eng"


def test_stale_configured_name_falls_back_to_discovery(
    tmp_path: Path, pentest_configs: Callable[..., Path]
) -> None:
    pentest_configs()  # only test-eng exists on disk
    # A persisted name whose directory is absent in this cwd is ignored in favour
    # of the sole engagement actually present (engagements_dir is cwd-relative).
    core = AgentCore(offline_settings(tmp_path, engagement="gone-from-here"))
    wire_offline_core(core)
    try:
        assert core.engagement is not None
        assert core.engagement.name == "test-eng"
    finally:
        core.close()


def test_list_engagements_ignores_dirs_without_a_scope(
    tmp_path: Path, pentest_configs: Callable[..., Path]
) -> None:
    pentest_configs()
    (Path("engagements") / "half-made").mkdir(
        parents=True, exist_ok=True
    )  # no scope.json
    found = list_engagements(Path("engagements"), WorkspaceLayout())
    assert found == ["test-eng"]
    assert list_engagements(Path("does-not-exist")) == []
