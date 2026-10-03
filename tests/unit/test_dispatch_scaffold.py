"""L1: the presentation-free scope-scaffold outcome (used by `set engagement`)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.frontend import dispatch


def test_scaffold_copies_the_template(tmp_path: Path) -> None:
    match dispatch.run_scaffold(tmp_path):
        case dispatch.Scaffolded(path):
            assert path == tmp_path / "scope.json"
            assert path.read_text(encoding="utf-8").strip()  # the template content
        case other:  # pragma: no cover -- a clean copy must succeed
            pytest.fail(f"expected Scaffolded, got {other}")


def test_scaffold_never_overwrites(tmp_path: Path) -> None:
    (tmp_path / "scope.json").write_text("mine", encoding="utf-8")
    assert isinstance(dispatch.run_scaffold(tmp_path), dispatch.ScaffoldExists)
    assert (tmp_path / "scope.json").read_text(encoding="utf-8") == "mine"


def test_scaffold_reports_an_os_error(tmp_path: Path) -> None:
    # A missing parent directory makes the write raise OSError (FileNotFoundError).
    missing = tmp_path / "does-not-exist"
    match dispatch.run_scaffold(missing):
        case dispatch.ScaffoldError(message):
            assert message
        case other:  # pragma: no cover -- must not succeed without a parent dir
            pytest.fail(f"expected ScaffoldError, got {other}")
