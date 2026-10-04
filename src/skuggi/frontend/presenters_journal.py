"""Rendering for the journal / engagement-artifact verbs: outcome -> styled lines.

Split from :mod:`skuggi.frontend.presenters` (which sat near the file-size cap):
the report, visualize and ingest presenters, and -- as they are centralized -- the
findings/replay presenters that build on the shared ``finding_line``. Same contract
as the parent module: each ``present_*`` maps a typed outcome from
:mod:`skuggi.frontend.outcomes` to a ``render.Styled`` phrased for a
``verbs.Surface``, so the REPL and the daemon render these verbs identically.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from skuggi.common import palette
from skuggi.frontend import presenters, render, verbs
from skuggi.frontend.outcomes import (
    Indexed,
    IngestOutcome,
    IngestUsage,
    ReportNoteAdded,
    ReportNoteUsage,
    ReportOutcome,
    ReportWritten,
    VisualizeWritten,
)
from skuggi.frontend.render import Styled

if TYPE_CHECKING:
    from collections.abc import Sequence

    from skuggi.persistence.ledger import FindingRow


def present_report(outcome: ReportOutcome, surface: verbs.Surface) -> Styled:
    """Render a ``report`` outcome identically on both surfaces."""
    match outcome:
        case ReportNoteUsage():
            return presenters.usage("report note <text>", surface)
        case ReportNoteAdded(path):
            return [render.success(f"changelog: {path}")]
        case ReportWritten(lines):
            return [render.success(line) for line in lines]


def present_visualize(outcome: VisualizeWritten) -> Styled:
    """Render a ``visualize`` outcome: the written-file lines."""
    return [render.success(line) for line in outcome.lines]


def present_ingest(outcome: IngestOutcome, surface: verbs.Surface) -> Styled:
    """Render an ``ingest`` outcome: usage, or the indexed-chunk count."""
    match outcome:
        case IngestUsage():
            return presenters.usage("ingest <path>", surface)
        case Indexed(count):
            return [render.info(f"indexed {count} chunk(s)")]


def _finding_parts(row: FindingRow, *, outdated: bool = False) -> tuple[str, str]:
    """``(severity token, the rest of the line)`` for a finding summary.

    Split so the severity can be painted its own colour in a ``render.spans`` line
    (on both surfaces) while the remainder stays unpainted; the plain concatenation
    is ``SEV [id] title — author/status (cmd:N)``.
    """
    link = f" (cmd:{row.command_id})" if row.command_id is not None else ""
    stale = " ⚠ outdated" if outdated else ""
    rest = f" [{row.id}] {row.title} — {row.author}/{row.status}{stale}{link}"
    return row.severity.upper(), rest


def _finding_span(row: FindingRow, *, outdated: bool = False) -> render.Line:
    """One finding as a spans line: severity painted its colour, the rest plain."""
    sev, rest = _finding_parts(row, outdated=outdated)
    return render.spans([(sev, palette.severity_style(row.severity)), (rest, None)])


def present_findings_list(
    rows: Sequence[FindingRow], current_version: int | None
) -> Styled:
    """Render ``show findings``: one severity-painted line per finding.

    A finding whose CVSS score predates `current_version` (the engagement's current
    threat-model version) is flagged ``⚠ outdated``. Painting rides ``render.spans``
    so the severity token is coloured on the REPL *and* the shell daemon, where it
    was previously plain.
    """
    if not rows:
        return presenters.empty("findings")
    return [
        _finding_span(
            f,
            outdated=f.cvss_tm_version is not None
            and f.cvss_tm_version != current_version,
        )
        for f in rows
    ]


def present_finding_recorded(row: FindingRow) -> Styled:
    """Render a just-recorded finding: ``recorded`` + the painted finding line."""
    sev, rest = _finding_parts(row)
    return [
        render.spans(
            [
                ("recorded ", palette.SUCCESS),
                (sev, palette.severity_style(row.severity)),
                (rest, None),
            ]
        )
    ]
