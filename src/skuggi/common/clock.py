"""The harness's single wall-clock timestamp format."""

from __future__ import annotations

from datetime import UTC, datetime

# The compact UTC stamp for a generated-artifact *filename* (a report, a
# dashboard). One definition so the report and visualize names cannot drift.
FILE_STAMP_FORMAT = "%Y%m%dT%H%M%SZ"


def now_iso() -> str:
    """Current UTC time as an ISO-8601 string.

    One definition for every store that stamps a row (the ledger and the
    preferences table), so their timestamps can never drift in format.
    """
    return datetime.now(UTC).isoformat()


def file_stamp() -> str:
    """Current UTC time as a compact, filename-safe stamp (``20260102T030405Z``)."""
    return datetime.now(UTC).strftime(FILE_STAMP_FORMAT)
