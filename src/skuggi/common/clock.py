"""The harness's single wall-clock timestamp format."""

from __future__ import annotations

from datetime import UTC, datetime


def now_iso() -> str:
    """Current UTC time as an ISO-8601 string.

    One definition for every store that stamps a row (the ledger and the
    preferences table), so their timestamps can never drift in format.
    """
    return datetime.now(UTC).isoformat()
