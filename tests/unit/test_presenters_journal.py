"""L1: the journal-verb presenters (report / visualize / ingest), both surfaces."""

from __future__ import annotations

from pathlib import Path

from skuggi.frontend import outcomes, presenters_journal
from skuggi.frontend.render import Styled, to_markup
from skuggi.persistence.ledger import FindingRow, SessionRow


def _texts(lines: Styled) -> list[str]:
    return [line.text for line in lines]


def _finding(
    severity: str, *, command_id: int | None = None, tm: int | None = None
) -> FindingRow:
    return FindingRow(
        id=7,
        session_id="s1",
        command_id=command_id,
        title="SQLi in login",
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
        cvss_tm_version=tm,
        cvss_scored_at=None,
        impact="",
        remediation="",
        affected_host="",
        affected_port="",
        affected_url="",
        affected_param="",
        created_at="2026-10-03T00:00:00+00:00",
    )


def test_present_report_note_usage_and_added() -> None:
    assert _texts(
        presenters_journal.present_report(outcomes.ReportNoteUsage(), "repl")
    )[0].startswith("usage:")
    added = presenters_journal.present_report(
        outcomes.ReportNoteAdded(Path("reports/CHANGELOG.md")), "shell"
    )
    assert _texts(added) == ["changelog: reports/CHANGELOG.md"]


def test_present_report_written_lines() -> None:
    lines = presenters_journal.present_report(
        outcomes.ReportWritten(("wrote report.md", "wrote report.pdf")), "shell"
    )
    assert _texts(lines) == ["wrote report.md", "wrote report.pdf"]
    assert all(line.style == "success" for line in lines)


def test_present_visualize_lines() -> None:
    lines = presenters_journal.present_visualize(
        outcomes.VisualizeWritten(("wrote graph.html",))
    )
    assert _texts(lines) == ["wrote graph.html"]


def test_present_ingest_usage_and_count() -> None:
    assert _texts(presenters_journal.present_ingest(outcomes.IngestUsage(), "repl"))[
        0
    ].startswith("usage:")
    assert _texts(presenters_journal.present_ingest(outcomes.Indexed(7), "shell")) == [
        "indexed 7 chunk(s)"
    ]


def test_present_findings_list_empty_and_painted() -> None:
    assert _texts(presenters_journal.present_findings_list([], None)) == [
        "(no findings yet)"
    ]
    [line] = presenters_journal.present_findings_list(
        [_finding("high", command_id=3)], None
    )
    # One spans line: severity painted, the rest plain; plain text is the full row.
    assert line.spans is not None
    assert line.text == "HIGH [7] SQLi in login — operator/approved (cmd:3)"
    assert to_markup(line) != line.text  # colour applied to the severity token


def test_present_findings_list_flags_outdated_against_current_version() -> None:
    [line] = presenters_journal.present_findings_list([_finding("low", tm=1)], 2)
    assert "⚠ outdated" in line.text


def test_present_finding_recorded_prefixes_recorded() -> None:
    [line] = presenters_journal.present_finding_recorded(_finding("medium"))
    assert line.text == "recorded MEDIUM [7] SQLi in login — operator/approved"
    assert line.spans is not None


def test_present_replay_list_empty_and_rows() -> None:
    assert _texts(presenters_journal.present_replay_list(outcomes.ReplayEmpty())) == [
        "(no sessions)"
    ]
    rows = [
        SessionRow("aaaa1111-x", "acme", "pentest", "2026-10-03T00:00:00+00:00"),
        SessionRow("bbbb2222-y", "acme", "redteam", "2026-10-04T00:00:00+00:00"),
    ]
    lines = presenters_journal.present_replay_list(
        outcomes.ReplayList(rows, current_id="bbbb2222-y")
    )
    assert lines[0].text == "aaaa1111  2026-10-03T00:00:00+00:00  pentest"
    assert lines[1].text.endswith(" *")  # the current session is marked
    assert all(line.spans is not None for line in lines)  # id painted on both surfaces
