"""L1: the wrapped shell's exit session summary renderer."""

from __future__ import annotations

from skuggi.persistence.ledger import CommandRow, FindingRow
from skuggi.persistence.session_summary import _fmt_duration, render_session_summary


def _cmd(status: str, *, exit_code: int | None = 0) -> CommandRow:
    return CommandRow(
        id=1,
        session_id="s1",
        thread_id="t1",
        command="nmap 10.0.0.5",
        binary="nmap",
        method="scan",
        status=status,
        exit_code=exit_code,
        stdout="",
        stderr="",
        reason="",
        started_at="2026-10-03T00:00:00+00:00",
        finished_at="2026-10-03T00:00:01+00:00",
        turn_event_id=None,
    )


def _finding(severity: str) -> FindingRow:
    return FindingRow(
        id=1,
        session_id="s1",
        command_id=None,
        title="t",
        severity=severity,
        description="d",
        evidence="",
        cvss_version=None,
        cvss_vector=None,
        cvss_base=None,
        cvss_temporal=None,
        cvss_environmental=None,
        cvss_score=None,
        cvss_severity=None,
        author="operator",
        status="approved",
        review_reason="",
        reviewed_at=None,
        cvss_tm_version=None,
        cvss_scored_at=None,
        created_at="2026-10-03T00:00:00+00:00",
    )


def test_fmt_duration_scales_seconds_minutes_hours() -> None:
    assert _fmt_duration(None) == "unknown"
    assert _fmt_duration(45) == "45s"
    assert _fmt_duration(14 * 60 + 2) == "14m 02s"
    assert _fmt_duration(2 * 3600 + 5 * 60) == "2h 05m"


def test_summary_reports_header_duration_turns_and_command_breakdown() -> None:
    out = render_session_summary(
        engagement_name="acme",
        mode="pentest",
        elapsed_s=842,
        turns=7,
        commands=[_cmd("executed"), _cmd("executed"), _cmd("blocked")],
        findings=[],
        notes=0,
        loot=0,
    )
    assert "skuggi session ended" in out
    assert "acme" in out
    assert "pentest" in out
    assert "14m 02s" in out
    assert "turns" in out
    assert "7" in out
    assert "2 executed" in out
    assert "1 blocked" in out
    assert "session closed · ledger saved" in out


def test_summary_groups_findings_by_severity() -> None:
    out = render_session_summary(
        engagement_name="acme",
        mode="pentest",
        elapsed_s=10,
        turns=1,
        commands=[_cmd("executed")],
        findings=[_finding("high"), _finding("medium"), _finding("high")],
        notes=0,
        loot=0,
    )
    assert "2 high" in out
    assert "1 medium" in out


def test_summary_omits_journal_line_when_empty_and_shows_it_otherwise() -> None:
    empty = render_session_summary(
        engagement_name="acme",
        mode="pentest",
        elapsed_s=10,
        turns=1,
        commands=[_cmd("executed")],
        findings=[],
        notes=0,
        loot=0,
    )
    assert "notes" not in empty
    with_journal = render_session_summary(
        engagement_name="acme",
        mode="pentest",
        elapsed_s=10,
        turns=1,
        commands=[_cmd("executed")],
        findings=[],
        notes=4,
        loot=1,
    )
    assert "notes 4 · loot 1" in with_journal


def test_summary_is_agent_only_when_unscoped() -> None:
    out = render_session_summary(
        engagement_name=None,
        mode="recon",
        elapsed_s=10,
        turns=1,
        commands=[_cmd("executed")],
        findings=[],
        notes=0,
        loot=0,
    )
    assert "agent-only" in out


def test_summary_collapses_to_sign_off_for_an_empty_session() -> None:
    out = render_session_summary(
        engagement_name="acme",
        mode="pentest",
        elapsed_s=3,
        turns=0,
        commands=[],
        findings=[],
        notes=0,
        loot=0,
    )
    assert "session closed · ledger saved" in out
    assert "ran for" not in out
    assert "turns" not in out
