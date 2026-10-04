"""L3: the forensics case plane on a live (offline) AgentCore.

Covers that ``set case`` adopts an engagement-free case with its own ledger, that
forensic records land in the case ledger and never in the engagement ledger, and
that ``show case`` reports the adopted case.
"""

from __future__ import annotations

from pathlib import Path

from skuggi.agent.core import AgentCore
from tests.conftest import offline_settings


def test_set_case_adopts_an_engagement_free_case(tmp_path: Path) -> None:
    core = AgentCore(offline_settings(tmp_path))
    try:
        core.set_mode("forensics")
        caseroot = tmp_path / "case1"
        case = core.set_case(caseroot)
        assert case.name == "case1"
        assert core.case is not None
        assert core.describe_case() is not None
        # the case tree + its separate ledger exist; no engagement scope is implied
        assert (caseroot / "case.json").is_file()
        assert (caseroot / "case.db").is_file()
        assert (caseroot / "evidence").is_dir()
        assert not (caseroot / "scope.json").exists()
    finally:
        core.close()


def test_case_ledger_is_isolated_from_the_engagement_ledger(tmp_path: Path) -> None:
    core = AgentCore(offline_settings(tmp_path))
    try:
        core.set_case(tmp_path / "case1")
        assert core.case_mgr is not None
        cm = core.case_mgr
        cm.ledger.record_evidence(
            session_id=cm.session_id,
            source_path="evidence/a.bin",
            sha256="deadbeef",
            size=10,
        )
        # the forensic row is in the case ledger, under a forensics session
        assert len(cm.ledger.evidence_for(cm.session_id)) == 1
        session = cm.ledger.session(cm.session_id)
        assert session is not None
        assert session.mode == "forensics"
        # and nothing leaked into the engagement ledger
        assert core.ledger.evidence_for(core.session_id) == []
    finally:
        core.close()


def test_adopting_a_second_case_closes_the_first(tmp_path: Path) -> None:
    core = AgentCore(offline_settings(tmp_path))
    try:
        core.set_case(tmp_path / "case1")
        first = core.case_mgr
        core.set_case(tmp_path / "case2")
        assert core.case_mgr is not first
        assert core.case is not None
        assert core.case.name == "case2"
    finally:
        core.close()
