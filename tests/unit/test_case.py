"""L1: the forensics case config, probe, scaffold and workspace tree."""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.config.configs import ConfigError
from skuggi.engagement.case import build_case, has_case, load_case
from skuggi.engagement.workspace import Workspace


def test_build_case_stamps_created_at() -> None:
    case = build_case({"name": "demo"})
    assert case.name == "demo"
    assert case.created_at != ""


def test_build_case_rejects_missing_name() -> None:
    with pytest.raises(ConfigError):
        build_case({"description": "no name"})


def test_case_describe_includes_examiner_and_sources() -> None:
    case = build_case(
        {
            "name": "laptop-2026",
            "examiner": "jan",
            "evidence_sources": ["disk image dd"],
        }
    )
    summary = case.describe()
    assert "laptop-2026" in summary
    assert "jan" in summary
    assert "disk image dd" in summary


def test_has_case_and_load_case_round_trip(tmp_path: Path) -> None:
    root = tmp_path / "case1"
    root.mkdir()
    assert has_case(root) is False
    case = build_case({"name": "case1"})
    (root / "case.json").write_text(case.model_dump_json(), encoding="utf-8")
    assert has_case(root) is True
    assert load_case(root / "case.json").name == "case1"


def test_load_case_raises_on_invalid_json(tmp_path: Path) -> None:
    bad = tmp_path / "case.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_case(bad)


def test_ensure_case_creates_only_forensic_dirs(tmp_path: Path) -> None:
    """A case tree has evidence/forensics/reports but no offensive recon/loot dirs."""
    ws = Workspace.at(tmp_path / "case1")
    ws.ensure_case()
    assert ws.evidence_dir.is_dir()
    assert ws.forensics_dir.is_dir()
    assert ws.reports_dir.is_dir()
    assert not (ws.root / "recon").exists()
    assert not (ws.root / "loot").exists()
    assert not (ws.root / "scripts").exists()


def test_case_ledger_path_is_separate_from_engagement_ledger(tmp_path: Path) -> None:
    ws = Workspace.at(tmp_path / "case1")
    assert ws.case_ledger_path.name == "case.db"
    assert ws.ledger_path.name == "ledger.db"
    assert ws.case_ledger_path != ws.ledger_path
