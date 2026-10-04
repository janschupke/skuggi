"""L1: the journal-verb presenters (report / visualize / ingest), both surfaces."""

from __future__ import annotations

from pathlib import Path

from skuggi.frontend import outcomes, presenters_journal
from skuggi.frontend.render import Styled


def _texts(lines: Styled) -> list[str]:
    return [line.text for line in lines]


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
