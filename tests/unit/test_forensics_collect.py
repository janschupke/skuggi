"""L1: the deterministic collect phase -- custody recording + the media battery."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from skuggi.engagement.workspace import Workspace
from skuggi.forensics.collect import collect_evidence
from skuggi.forensics.deps import ForensicsDeps
from skuggi.forensics.report import _integrity_block
from skuggi.persistence.ledger import open_ledger


def _deps(ws: Workspace, ledger: object, **kw: object) -> ForensicsDeps:
    base: dict[str, object] = {
        "workspace": ws,
        "ledger": ledger,
        "session_id": "s1",
        "output_root": ws.forensics_dir,
        "vision": False,
    }
    base.update(kw)
    return ForensicsDeps(**base)  # type: ignore[arg-type]


def test_collect_runs_the_binary_battery_and_records_custody(tmp_path: Path) -> None:
    ws = Workspace.at(tmp_path / "case1")
    ws.ensure_case()
    (ws.evidence_dir / "blob.bin").write_bytes(b"\x00\x01ELFjunk\xff" * 10)
    with open_ledger(ws.case_ledger_path) as ledger:
        ledger.start_session("s1", engagement_name="case:c", mode="forensics")
        results = collect_evidence(_deps(ws, ledger))
        assert len(results) == 1
        ops = {p.operation for p in ledger.procedure_for("s1")}
        # the binary branch runs hex/entropy in addition to hash/magic/strings
        assert {"hash", "magic", "strings", "hexdump", "entropy"} <= ops
        assert len(ledger.evidence_for("s1")) == 1
    assert list(ws.forensics_dir.rglob("*.json"))


def test_collect_runs_ocr_on_an_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pil = pytest.importorskip("PIL.Image")
    pytesseract = pytest.importorskip("pytesseract")
    monkeypatch.setattr(pytesseract, "image_to_string", lambda _img: "on-screen text")
    ws = Workspace.at(tmp_path / "case1")
    ws.ensure_case()
    pil.new("RGB", (8, 8), "white").save(ws.evidence_dir / "shot.png")
    with open_ledger(ws.case_ledger_path) as ledger:
        ledger.start_session("s1", engagement_name="case:c", mode="forensics")
        [result] = collect_evidence(_deps(ws, ledger))
        assert "ocr" in {p.operation for p in ledger.procedure_for("s1")}
        assert any(i.kind == "ocr" for i in result.items)


def test_collect_with_no_evidence_is_empty(tmp_path: Path) -> None:
    ws = Workspace.at(tmp_path / "case1")
    ws.ensure_case()
    with open_ledger(ws.case_ledger_path) as ledger:
        ledger.start_session("s1", engagement_name="case:c", mode="forensics")
        assert collect_evidence(_deps(ws, ledger)) == []


def test_collect_without_a_workspace_is_empty() -> None:
    assert collect_evidence(ForensicsDeps()) == []


def test_vision_is_a_speculative_observation_not_a_custody_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AI-vision stays out of the custody log but still informs the report (E22)."""
    pil = pytest.importorskip("PIL.Image")

    monkeypatch.setattr("skuggi.agent.vision.vision_available", lambda _p: True)
    monkeypatch.setattr(
        "skuggi.agent.vision.describe_image",
        lambda *_a, **_k: SimpleNamespace(
            observations=[SimpleNamespace(text="a login screen", speculative=True)]
        ),
    )
    ws = Workspace.at(tmp_path / "case1")
    ws.ensure_case()
    pil.new("RGB", (8, 8), "white").save(ws.evidence_dir / "shot.png")
    with open_ledger(ws.case_ledger_path) as ledger:
        ledger.start_session("s1", engagement_name="case:c", mode="forensics")
        [result] = collect_evidence(_deps(ws, ledger, vision=True, provider="openai"))
        ops = {p.operation for p in ledger.procedure_for("s1")}
        assert "vision" not in ops  # never a custody row
        assert any(i.kind == "vision" for i in result.items)  # but kept for the report


def test_collect_records_examiner_and_tool_version_with_a_custody_chain(
    tmp_path: Path,
) -> None:
    """Procedure rows carry provenance and join a verifiable custody chain (E20/E21)."""
    ws = Workspace.at(tmp_path / "case1")
    ws.ensure_case()
    (ws.evidence_dir / "blob.bin").write_bytes(b"ELFjunk" * 20)
    with open_ledger(ws.case_ledger_path) as ledger:
        ledger.custody_key = b"k" * 32  # the CaseManager normally sets this
        ledger.start_session("s1", engagement_name="case:c", mode="forensics")
        collect_evidence(_deps(ws, ledger, examiner="Jan"))
        procs = ledger.procedure_for("s1")
        assert all(p.examiner == "Jan" for p in procs)
        assert all(p.tool_version.startswith("skuggi ") for p in procs)
        # the chain written during collection re-verifies intact
        assert ledger.verify_custody("s1").ok


def test_report_integrity_section_flags_a_changed_evidence_file(tmp_path: Path) -> None:
    """Closeout re-hashing detects evidence altered after acquisition (E21)."""
    ws = Workspace.at(tmp_path / "case1")
    ws.ensure_case()
    evidence = ws.evidence_dir / "blob.bin"
    evidence.write_bytes(b"original")
    with open_ledger(ws.case_ledger_path) as ledger:
        ledger.custody_key = b"k" * 32
        ledger.start_session("s1", engagement_name="case:c", mode="forensics")
        collect_evidence(_deps(ws, ledger, examiner="Jan"))
        rows = ledger.evidence_for("s1")
        clean_block = _integrity_block(_deps(ws, ledger, examiner="Jan"), rows)
        assert "all 1 files match" in clean_block
        assert "Examiner:** Jan" in clean_block
        # Tamper with the evidence on disk, then re-verify at closeout.
        evidence.write_bytes(b"tampered")
        dirty_block = _integrity_block(_deps(ws, ledger, examiner="Jan"), rows)
        assert "SHA-256 changed since acquisition" in dirty_block
