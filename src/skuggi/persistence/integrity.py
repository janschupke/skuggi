"""Tamper-evidence for the engagement timeline (commands/findings/events/audit).

The forensics *case* ledger hash-chains its custody tables; this is the engagement
analogue for the pentest record. Each insert into one of the four timeline tables
is linked into a per-table, per-session HMAC chain -- ``row_hmac = HMAC(key,
prev_hash || canonical)`` -- so a later edit, reorder, deletion or truncation is
detectable by re-walking (``verify_timeline``). It reuses the chain primitives
(:meth:`_chain`/:meth:`_last_hmac`) and the per-session key the
:class:`~skuggi.persistence.custody.CustodyLedgerMixin` already provides on the same
``Ledger`` instance -- this mixin adds no new key, just more chained tables.

What each table commits to:

* ``commands`` / ``events`` / ``audit`` -- every content column. These tables are
  insert-only (the DB triggers enforce it), so the full row is immutable.
* ``findings`` -- the IMMUTABLE substance only (title, description, evidence,
  intrinsic CVSS vector, affected asset, …), NOT the review/rescore fields
  (``status``/``severity``/environmental score/…). A finding's review lifecycle
  mutates those in place by design, so chaining them would make a legitimate
  ``set_finding_status``/``rescore_finding`` read as tampering. The trade-off:
  deletion and proof-tampering are caught; a rescore is not itself chain-pinned.

An unkeyed ledger (no engagement workspace) chains to ``""`` and ``verify_timeline``
is vacuously ok -- there is nothing to protect. A row written before the key existed
(legacy ``row_hmac == ""``) is skipped on verify; the chain resumes from the first
keyed row.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from skuggi.persistence.custody import CustodyVerdict
from skuggi.persistence.ledger_schema import (
    _AUDIT_COLS,
    _COMMAND_COLS,
    _EVENT_COLS,
    _FINDING_COLS,
)

if TYPE_CHECKING:
    import sqlite3
    import threading

    from skuggi.persistence.ledger_schema import (
        AuditRow,
        CommandRow,
        EventRow,
        FindingRow,
    )

# The finding columns the review/rescore lifecycle mutates in place -- excluded
# from the chain so those legitimate edits never look like tampering.
_FINDING_MUTABLE = frozenset(
    {
        "severity",
        "cvss_environmental",
        "cvss_score",
        "cvss_severity",
        "cvss_tm_version",
        "cvss_scored_at",
        "status",
        "review_reason",
        "reviewed_at",
    }
)


def _content(cols: tuple[str, ...]) -> tuple[str, ...]:
    """A row type's content columns: all but ``id`` and the two trailing chain cols."""
    return cols[1:-2]


# The insert-tuple column order per table (dataclass field order, minus id and the
# chain columns) -- the single source so the chained-value selection cannot drift
# from what record_* actually inserts.
_CONTENT: dict[str, tuple[str, ...]] = {
    "commands": _content(_COMMAND_COLS),
    "findings": _content(_FINDING_COLS),
    "events": _content(_EVENT_COLS),
    "audit": _content(_AUDIT_COLS),
}

# The subset each table's chain commits to (see module docstring).
_CHAINED: dict[str, tuple[str, ...]] = {
    "commands": _CONTENT["commands"],
    "events": _CONTENT["events"],
    "audit": _CONTENT["audit"],
    "findings": tuple(c for c in _CONTENT["findings"] if c not in _FINDING_MUTABLE),
}


class TimelineIntegrityMixin:
    """Hash-chains timeline inserts and verifies the chain (engagement ledger)."""

    # Provided by the Ledger / CustodyLedgerMixin this is mixed into.
    if TYPE_CHECKING:
        _conn: sqlite3.Connection
        _lock: threading.Lock
        custody_key: bytes | None

        # Provided by the Ledger / CustodyLedgerMixin -- declared for the type
        # checker only; the real implementations live there.
        def _chain(self, prev_hash: str, canonical: str) -> str: ...
        def _last_hmac(self, table: str, session_id: str) -> str: ...
        def commands_for(self, session_id: str) -> list[CommandRow]: ...  # noqa: D102
        def findings_for(  # noqa: D102
            self, session_id: str, *, status: str | None = ...
        ) -> list[FindingRow]: ...
        def events_for(self, session_id: str) -> list[EventRow]: ...  # noqa: D102
        def audit_for(self, session_id: str) -> list[AuditRow]: ...  # noqa: D102

    def _timeline_chain(
        self, table: str, session_id: str, content_values: tuple[object, ...]
    ) -> tuple[str, str]:
        """``(prev_hash, row_hmac)`` for an about-to-be-inserted row.

        ``content_values`` is the insert tuple (``_CONTENT[table]`` order). The
        canonical string joins only the chained subset, so a mutable finding column
        changing later does not break the chain. The caller holds the lock.
        """
        values = dict(zip(_CONTENT[table], content_values, strict=True))
        canonical = "\x1f".join(str(values[c]) for c in _CHAINED[table])
        prev = self._last_hmac(table, session_id)
        return prev, self._chain(prev, canonical)

    def verify_timeline(self, session_id: str) -> CustodyVerdict:
        """Re-walk the four timeline chains; report the first break (audit E22).

        Vacuously ok on an unkeyed ledger. A row with an empty ``row_hmac`` predates
        the key and is skipped (not a break). The verdict's ``checked`` counts the
        keyed rows actually verified.
        """
        if self.custody_key is None:
            return CustodyVerdict(ok=True, checked=0)
        tables = (
            ("commands", self.commands_for(session_id)),
            ("findings", self.findings_for(session_id)),
            ("events", self.events_for(session_id)),
            ("audit", self.audit_for(session_id)),
        )
        checked = 0
        for table, rows in tables:
            chained = _CHAINED[table]
            for row in rows:
                if not row.row_hmac:  # legacy / unkeyed row -- cannot verify
                    continue
                canonical = "\x1f".join(str(getattr(row, c)) for c in chained)
                checked += 1
                if self._chain(row.prev_hash, canonical) != row.row_hmac:
                    return CustodyVerdict(False, checked, f"{table} row {row.id}")
        return CustodyVerdict(ok=True, checked=checked)
