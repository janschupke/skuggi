"""Rendering for the journal / engagement-artifact verbs: outcome -> styled lines.

Split from :mod:`skuggi.frontend.presenters` (which sat near the file-size cap):
the report, visualize and ingest presenters, and -- as they are centralized -- the
findings/replay presenters that build on the shared ``finding_line``. Same contract
as the parent module: each ``present_*`` maps a typed outcome from
:mod:`skuggi.frontend.outcomes` to a ``render.Styled`` phrased for a
``verbs.Surface``, so the REPL and the daemon render these verbs identically.
"""

from __future__ import annotations

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
