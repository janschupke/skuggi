"""Reconstruct a cross-evidence timeline from the collected observations (F5).

Pure post-processing: it harvests every timestamp the deterministic battery already
produced -- log-line times (``logparse``), event-log spans (``evtx``), capture spans
(``pcap``), registry last-written times -- plus each artifact's acquisition time from
the ledger, parses them to comparable UTC datetimes, and returns them in
chronological order. Timestamps it cannot parse are left out of the ordering (the
raw observation still lives in the per-file JSON artifact), so the timeline never
mis-orders on a format it does not understand. No new parse or network path.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from skuggi.intel.schema import IntelResult
from skuggi.persistence.ledger_schema import EvidenceRow

# Observation attribute keys that carry an event timestamp, in report wording.
_TS_KEYS = (
    "timestamp",
    "event_start",
    "event_end",
    "capture_start",
    "capture_end",
    "last_written",
)
# Non-ISO formats worth a best-effort parse (Common Log Format).
_FALLBACK_FORMATS = ("%d/%b/%Y:%H:%M:%S %z",)
_MAX_DETAIL = 80


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    """One dated event on the reconstructed timeline."""

    when: datetime
    source: str  # the evidence ID the event came from
    kind: str
    detail: str


def _parse(value: str) -> datetime | None:
    """Parse an ISO-8601 (or CLF) timestamp to an aware UTC datetime, else None."""
    text = value.strip()
    if not text:
        return None
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in _FALLBACK_FORMATS:
            try:
                # Every _FALLBACK_FORMATS entry includes %z; tz is normalised below.
                parsed = datetime.strptime(text, fmt)  # noqa: DTZ007
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def build_timeline(
    results: list[IntelResult], evidence: list[EvidenceRow]
) -> list[TimelineEntry]:
    """Collect every parseable event time across the evidence, chronologically."""
    entries: list[TimelineEntry] = []
    for ev in evidence:
        when = _parse(ev.acquired_at)
        if when is not None:
            entries.append(
                TimelineEntry(when, ev.note or str(ev.id), "acquired", ev.source_path)
            )
    for result in results:
        for item in result.items:
            for key in _TS_KEYS:
                when = _parse(item.attributes.get(key, ""))
                if when is None:
                    continue
                detail = f"{key}: {item.value}"[:_MAX_DETAIL]
                entries.append(TimelineEntry(when, result.task_id, item.kind, detail))
    entries.sort(key=lambda e: e.when)
    return entries
