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
    _FOOTHOLD_COLS,
    CoverageRow,
    CredentialRow,
    FootholdRow,
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

    def record_foothold(  # noqa: PLR0913 -- keyword-only ledger columns
        self,
        *,
        session_id: str,
        host: str,
        transport: str = "command",
        template: str = "",
        secret_ref: str = "",
        reachable_networks: str = "",
        reachable_hosts: str = "",
    ) -> int:
        """Register a foothold host as a runtime execution channel (pivot).

        ``secret_ref`` is a vault placeholder, never the plaintext secret -- the
        caller interns it in the engagement vault, mirroring ``record_credential``.
        ``transport`` is ``command`` (run through an RCE/shell template) or
        ``tunnel`` (route through a proxy). Returns the new row id.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                _insert_sql("footholds", _FOOTHOLD_COLS[1:]),
                (
                    session_id,
                    host,
                    transport,
                    template,
                    secret_ref,
                    reachable_networks,
                    reachable_hosts,
                    now_iso(),
                ),
            )
            return int(cur.lastrowid or 0)

    def footholds_for(self, session_id: str) -> list[FootholdRow]:
        """Every registered foothold in the session, in registration order (pivot)."""
        with self._lock:
            rows = self._conn.execute(
                _select_sql(
                    "footholds",
                    _FOOTHOLD_COLS,
                    "WHERE session_id = ? ORDER BY id",
                ),
                (session_id,),
            ).fetchall()
        return [FootholdRow(*row) for row in rows]

    def footholds_for_engagement(self, engagement_name: str) -> list[FootholdRow]:
        """Every foothold across all of an engagement's sessions (pivot/P4).

        Joins each session's footholds by engagement name so the engagement report's
        access-path section spans the whole engagement, not one session.
        """
        with self._lock:
            rows = self._conn.execute(
                _select_sql(
                    "footholds f JOIN sessions s ON f.session_id = s.session_id",
                    tuple(f"f.{c}" for c in _FOOTHOLD_COLS),
                    "WHERE s.engagement_name = ? ORDER BY s.started_at, f.id",
                ),
                (engagement_name,),
            ).fetchall()
        return [FootholdRow(*row) for row in rows]

    def clear_footholds(self, session_id: str) -> int:
        """Remove every foothold registered in the session; return how many (pivot).

        Footholds are volatile runtime state (unlike append-only custody), so the
        operator can drop them -- e.g. when access is lost -- via the ``clear
        foothold`` verb. Returns the number of rows deleted.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM footholds WHERE session_id = ?", (session_id,)
            )
            return int(cur.rowcount or 0)
