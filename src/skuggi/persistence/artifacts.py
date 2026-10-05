"""Engagement-artifact slices of the ledger: methodology coverage + credentials.

Extracted from :mod:`skuggi.persistence.ledger` as its own mixin, alongside the
custody mixin, to keep the ledger module focused and under the file-size cap. These
are the recorded *products* of an engagement -- which methodology ids were
exercised (audit E7) and which credentials were captured (audit E8/E9) -- as
opposed to the command/finding/event spine. The mixin runs on the ``Ledger``'s own
connection and lock and is never instantiated on its own.
"""

from __future__ import annotations

import sqlite3
import threading

from skuggi.common.clock import now_iso
from skuggi.persistence.ledger_schema import (
    _COVERAGE_COLS,
    _CREDENTIAL_COLS,
    CoverageRow,
    CredentialRow,
    _insert_sql,
    _select_sql,
)


class ArtifactsLedgerMixin:
    """Coverage + credential methods mixed into ``Ledger`` (engagement artifacts)."""

    # Provided by the Ledger this is mixed into (same connection + lock).
    _conn: sqlite3.Connection
    _lock: threading.Lock

    def record_coverage(
        self,
        *,
        session_id: str,
        framework: str,
        ref_id: str,
        status: str = "exercised",
        note: str = "",
    ) -> None:
        """Mark a methodology id exercised/skipped for a session, idempotently (E7)."""
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO coverage"
                " (session_id, framework, ref_id, status, note, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, framework, ref_id, status, note, now_iso()),
            )

    def coverage_for(self, session_id: str) -> list[CoverageRow]:
        """Every recorded coverage id for a session, framework then id order (E7)."""
        with self._lock:
            rows = self._conn.execute(
                _select_sql(
                    "coverage",
                    _COVERAGE_COLS,
                    "WHERE session_id = ? ORDER BY framework, ref_id",
                ),
                (session_id,),
            ).fetchall()
        return [CoverageRow(*row) for row in rows]

    def record_credential(  # noqa: PLR0913 -- keyword-only ledger columns
        self,
        *,
        session_id: str,
        host: str = "",
        service: str = "",
        username: str = "",
        secret_ref: str = "",
        source: str = "",
        validated: bool = False,
    ) -> int:
        """Record a captured credential; ``secret_ref`` is a vault placeholder (E8/E9).

        The plaintext secret is NEVER stored here -- the caller interns it in the
        engagement vault and passes the resulting ``«CRED:id»`` placeholder, which a
        command the worker runs rehydrates at exec like any other vaulted secret.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                _insert_sql("credentials", _CREDENTIAL_COLS[1:]),
                (
                    session_id,
                    host,
                    service,
                    username,
                    secret_ref,
                    source,
                    int(validated),
                    now_iso(),
                ),
            )
            return int(cur.lastrowid or 0)

    def credentials_for(self, session_id: str) -> list[CredentialRow]:
        """Every captured credential in the session, in capture order (E8/E9)."""
        with self._lock:
            rows = self._conn.execute(
                _select_sql(
                    "credentials",
                    _CREDENTIAL_COLS,
                    "WHERE session_id = ? ORDER BY id",
                ),
                (session_id,),
            ).fetchall()
        return [CredentialRow(*row) for row in rows]
