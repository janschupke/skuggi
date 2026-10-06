"""L1: the presentation-free scope-scaffold outcome (used by `set engagement`)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skuggi.engagement.engagement import EngagementConfig
from skuggi.frontend import dispatch, outcomes


def test_scaffold_writes_a_minimal_scope(tmp_path: Path) -> None:
    match dispatch.run_scaffold(tmp_path):
        case outcomes.Scaffolded(path):
            assert path == tmp_path / "scope.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            # Minimal: just a name (from the dir) and a timezone; nothing else.
            assert set(data) == {"name", "timezone"}
            assert data["timezone"] == "UTC"
            # And it validates as a real engagement (every other field defaults).
            assert EngagementConfig.model_validate(data).name == data["name"]
        case other:  # pragma: no cover -- a clean write must succeed
            pytest.fail(f"expected Scaffolded, got {other}")


def test_scaffold_never_overwrites(tmp_path: Path) -> None:
    (tmp_path / "scope.json").write_text("mine", encoding="utf-8")
    assert isinstance(dispatch.run_scaffold(tmp_path), outcomes.ScaffoldExists)
    assert (tmp_path / "scope.json").read_text(encoding="utf-8") == "mine"


def test_scaffold_reports_an_os_error(tmp_path: Path) -> None:
    # A missing parent directory makes the write raise OSError (FileNotFoundError).
    missing = tmp_path / "does-not-exist"
    match dispatch.run_scaffold(missing):
        case outcomes.ScaffoldError(message):
            assert message
        case other:  # pragma: no cover -- must not succeed without a parent dir
            pytest.fail(f"expected ScaffoldError, got {other}")
