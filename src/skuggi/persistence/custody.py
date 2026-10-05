"""The forensics chain-of-custody slice of the ledger (evidence + procedure).

Extracted from :mod:`skuggi.persistence.ledger` as its own mixin: the acquisition
records and the ordered examination log are a cohesive concern (and the one that
grows with the evidentiary-integrity work), so keeping them here keeps the ledger
module focused and under the file-size cap. The mixin runs on the same connection
and lock the ``Ledger`` owns; it is never instantiated on its own.
"""

from __future__ import annotations

import sqlite3
import threading

from skuggi.common.clock import now_iso
from skuggi.persistence.ledger_schema import (
    _EVIDENCE_COLS,
    _PROCEDURE_COLS,
    EvidenceRow,
    ProcedureRow,
    _insert_sql,
    _select_sql,
)


class CustodyLedgerMixin:
    """Evidence/procedure custody methods mixed into ``Ledger`` (forensics)."""

    # Provided by the Ledger this is mixed into (same connection + lock).
    _conn: sqlite3.Connection
    _lock: threading.Lock

    def record_evidence(  # noqa: PLR0913 -- keyword-only ledger columns
        self,
        *,
        session_id: str,
        source_path: str,
        sha256: str,
        size: int,
        media_type: str = "",
        note: str = "",
    ) -> int:
        """Record one acquired evidence artifact (forensics) and return its id.

        The acquisition record for the chain of custody: ``sha256`` pins the
        content at examination time so any later report can prove integrity.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                _insert_sql("evidence", _EVIDENCE_COLS[1:]),
                (session_id, source_path, sha256, size, media_type, now_iso(), note),
            )
            return int(cur.lastrowid or 0)

    def record_procedure(  # noqa: PLR0913 -- keyword-only ledger columns
        self,
        *,
        session_id: str,
        step: int,
        operation: str,
        actor: str,
        argv: str = "",
        input_sha256: str = "",
        output_digest: str = "",
        note: str = "",
    ) -> int:
        """Record one examination step in the procedure log (forensics).

        ``actor`` is ``in-process`` (a pure-Python analyzer) or ``tool`` (a gated
        read-only external utility, whose exact ``argv`` is stored verbatim).
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                _insert_sql("procedure", _PROCEDURE_COLS[1:]),
                (
                    session_id,
                    step,
                    operation,
                    actor,
                    argv,
                    input_sha256,
                    output_digest,
                    now_iso(),
                    note,
                ),
            )
            return int(cur.lastrowid or 0)

    def evidence_for(self, session_id: str) -> list[EvidenceRow]:
        """Every acquired evidence artifact in the session, in acquisition order."""
        with self._lock:
            rows = self._conn.execute(
                _select_sql(
                    "evidence", _EVIDENCE_COLS, "WHERE session_id = ? ORDER BY id"
                ),
                (session_id,),
            ).fetchall()
        return [EvidenceRow(*row) for row in rows]

    def procedure_for(self, session_id: str) -> list[ProcedureRow]:
        """Every examination step in the session, in step order (the custody log)."""
        with self._lock:
            rows = self._conn.execute(
                _select_sql(
                    "procedure",
                    _PROCEDURE_COLS,
                    "WHERE session_id = ? ORDER BY step, id",
                ),
                (session_id,),
            ).fetchall()
        return [ProcedureRow(*row) for row in rows]
