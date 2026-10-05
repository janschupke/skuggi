"""L1: the cross-evidence timeline reconstruction + report block -- F5."""

from __future__ import annotations

from skuggi.forensics import report as report_mod
from skuggi.forensics.timeline import build_timeline
from skuggi.intel.schema import IntelItem, IntelResult
from skuggi.persistence.ledger_schema import EvidenceRow


def _evidence(acquired_at: str, note: str = "E1") -> EvidenceRow:
    return EvidenceRow(
        id=1,
        session_id="s1",
        source_path="disk/log.txt",
        sha256="deadbeef",
        size=10,
        media_type="text/plain",
        acquired_at=acquired_at,
        note=note,
    )


def _result(task_id: str, *items: IntelItem) -> IntelResult:
    return IntelResult(task_id=task_id, source="analyzers", subject="x", items=items)


def test_timeline_merges_and_orders_events_across_evidence() -> None:
    results = [
        _result(
            "E1",
            IntelItem(
                kind="evtx-records",
                value="5 events",
                attributes={
                    "event_start": "2026-02-01T10:00:00+00:00",
                },
            ),
            IntelItem(
                kind="log",
                value="auth failure",
                attributes={
                    "timestamp": "2026-01-15T08:30:00",
                },
            ),
        ),
        _result(
            "E2",
            IntelItem(
                kind="pcap",
                value="pcap capture",
                attributes={
                    "capture_start": "2026-01-20T12:00:00+00:00",
                },
            ),
            # An unparseable syslog-style timestamp is excluded from the ordering.
            IntelItem(
                kind="log", value="noise", attributes={"timestamp": "Jan 2 03:04:05"}
            ),
        ),
    ]
    evidence = [_evidence("2026-03-01T00:00:00+00:00")]
    entries = build_timeline(results, evidence)
    # four parseable events (evtx, log-iso, pcap, acquired); the syslog one dropped
    assert len(entries) == 4
    whens = [e.when.isoformat() for e in entries]
    assert whens == sorted(whens)
    assert whens[0].startswith("2026-01-15")  # earliest parsed log line first
    kinds = {e.kind for e in entries}
    assert {"evtx-records", "log", "pcap", "acquired"} == kinds


def test_timeline_block_renders_a_table() -> None:
    results = [
        _result(
            "E1",
            IntelItem(
                kind="log",
                value="pipe | in message",
                attributes={
                    "timestamp": "2026-01-15T08:30:00+00:00",
                },
            ),
        )
    ]
    block = report_mod._timeline_block(build_timeline(results, []))
    assert "## Timeline (reconstructed)" in block
    assert "| When | Evidence | Kind | Detail |" in block
    assert "pipe \\| in message" in block  # a literal pipe is escaped for the table


def test_empty_timeline_is_blank() -> None:
    assert report_mod._timeline_block([]) == ""
    assert build_timeline([], []) == []
