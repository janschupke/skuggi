"""The finding-review lifecycle: the two deliberate in-place edits to a finding.

Split from :mod:`skuggi.persistence.ledger` as its own mixin because these are the
*only* in-place mutations of a recorded finding -- the draft->approved/rejected
status change and an explicit CVSS rescore -- and grouping them makes that
boundary legible. Both touch only the review/score columns, which the timeline
hash chain deliberately excludes (see :mod:`skuggi.persistence.integrity`), so a
legitimate review edit never reads as tampering. Runs on the ``Ledger``'s own
connection and lock; never instantiated alone.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import TYPE_CHECKING

from skuggi.common.clock import now_iso
from skuggi.persistence.ledger_schema import effective_score

if TYPE_CHECKING:
    from skuggi.persistence.ledger_schema import FindingRow


class ReviewLedgerMixin:
    """The finding review/rescore lifecycle (the only in-place finding edits)."""

    # Provided by the Ledger this is mixed into.
    if TYPE_CHECKING:
        _conn: sqlite3.Connection
        _lock: threading.Lock

        def finding(self, finding_id: int) -> FindingRow | None: ...  # noqa: D102

    def set_finding_status(
        self, finding_id: int, status: str, *, reason: str = ""
    ) -> None:
        """Move a finding to ``status`` ('approved'|'rejected'|'draft'), stamping it.

        A rejection carries its ``reason`` (shown to the operator and fed back to
        the agent); approving clears any prior reason.
        """
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE findings SET status = ?, review_reason = ?, reviewed_at = ?"
                " WHERE id = ?",
                (status, reason, now_iso(), finding_id),
            )

    def rescore_finding(
        self, finding_id: int, env_metrics: dict[str, str], tm_version: int | None
    ) -> bool:
        """Recompute a finding's env/overall score from its stored base vector.

        Deliberate and explicit (the operator runs it) -- a recorded score changes
        only here. Returns False when the finding has no vector to rescore.
        """
        row = self.finding(finding_id)
        if row is None or not row.cvss_vector:
            return False
        eff = effective_score(row.cvss_vector, env_metrics)
        assert eff is not None  # noqa: S101 -- guaranteed by the vector check above
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE findings SET cvss_environmental = ?, cvss_score = ?,"
                " cvss_severity = ?, severity = ?, cvss_tm_version = ?,"
                " cvss_scored_at = ? WHERE id = ?",
                (
                    eff.environmental,
                    eff.overall,
                    eff.severity,
                    eff.severity,
                    tm_version,
                    now_iso(),
                    finding_id,
                ),
            )
        return True
