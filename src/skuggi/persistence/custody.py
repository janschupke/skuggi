"""The forensics chain-of-custody slice of the ledger (evidence + procedure).

Extracted from :mod:`skuggi.persistence.ledger` as its own mixin: the acquisition
records and the ordered examination log are a cohesive concern, and the one that
carries the evidentiary-integrity machinery. Each row is linked into a per-table
tamper-evident hash chain -- ``row_hmac = HMAC(case_key, prev_hash || canonical)``
with ``prev_hash`` the previous row's ``row_hmac`` -- so a later edit, reorder or
truncation is detectable by re-walking the chain (``verify_custody``), and the
database itself rejects any UPDATE/DELETE on these tables (audit E20). The case key
lives in a 0600 file beside the case DB, never in the DB, so an attacker who can
write the DB still cannot forge the chain. The mixin runs on the ``Ledger``'s own
connection and lock and is never instantiated on its own.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from skuggi.common.clock import now_iso
from skuggi.common.paths import ensure_parent
from skuggi.persistence.ledger_schema import (
    _EVIDENCE_COLS,
    _PROCEDURE_COLS,
    EvidenceRow,
    ProcedureRow,
    _insert_sql,
    _select_sql,
)


@dataclass(frozen=True, slots=True)
class CustodyVerdict:
    """The result of re-walking a session's chain of custody (audit E20)."""

    ok: bool
    checked: int
    broken_at: str = ""  # a human locus of the first break, or "" when intact


def _canonical_evidence(row: tuple[object, ...]) -> str:
    """The content of an evidence row that the chain commits to (not id/chain cols)."""
    # row is the INSERT tuple: session_id, source_path, sha256, size, media_type,
    # acquired_at, note (prev_hash/row_hmac are appended after and excluded).
    return "\x1f".join(str(v) for v in row)


class CustodyLedgerMixin:
    """Append-only, tamper-evident evidence/procedure custody (forensics)."""

    # Provided by the Ledger this is mixed into (same connection + lock).
    _conn: sqlite3.Connection
    _lock: threading.Lock
    # The per-case HMAC key, set by the CaseManager after open; None for a ledger
    # that is not a forensics case (those tables stay empty), which chains to "".
    custody_key: bytes | None = None

    def _chain(self, prev_hash: str, canonical: str) -> str:
        """``HMAC(key, prev_hash||canonical)`` hex, or "" when no case key is set."""
        if self.custody_key is None:
            return ""
        msg = f"{prev_hash}\x1e{canonical}".encode()
        return hmac.new(self.custody_key, msg, hashlib.sha256).hexdigest()

    def _last_hmac(self, table: str, session_id: str) -> str:
        """The row_hmac of the most recent row for this session+table (or "")."""
        row = self._conn.execute(
            f"SELECT row_hmac FROM {table} WHERE session_id = ?"  # noqa: S608
            " ORDER BY id DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        return str(row[0]) if row else ""

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
        """Record one acquired evidence artifact, chained for tamper-evidence (E20).

        ``sha256`` pins the content at acquisition; the row is linked into the
        session's evidence hash chain so a later edit is detectable.
        """
        acquired_at = now_iso()
        content = (session_id, source_path, sha256, size, media_type, acquired_at, note)
        with self._lock, self._conn:
            prev = self._last_hmac("evidence", session_id)
            row_hmac = self._chain(prev, _canonical_evidence(content))
            cur = self._conn.execute(
                _insert_sql("evidence", _EVIDENCE_COLS[1:]),
                (*content, prev, row_hmac),
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
        examiner: str = "",
        tool_version: str = "",
    ) -> int:
        """Record one examination step with provenance, chained for integrity (E20).

        ``actor`` is ``in-process`` or ``tool``; ``examiner``/``tool_version`` carry
        provenance for the report. The row joins the session's procedure hash chain.
        """
        created_at = now_iso()
        content = (
            session_id,
            step,
            operation,
            actor,
            argv,
            input_sha256,
            output_digest,
            created_at,
            note,
            examiner,
            tool_version,
        )
        with self._lock, self._conn:
            prev = self._last_hmac("procedure", session_id)
            row_hmac = self._chain(prev, "\x1f".join(str(v) for v in content))
            cur = self._conn.execute(
                _insert_sql("procedure", _PROCEDURE_COLS[1:]),
                (*content, prev, row_hmac),
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

    def verify_custody(self, session_id: str) -> CustodyVerdict:
        """Re-walk the evidence + procedure chains; report the first break (E20).

        Without a case key set, the chain was never written, so there is nothing to
        verify and the verdict is vacuously ok with ``checked == 0``.
        """
        if self.custody_key is None:
            return CustodyVerdict(ok=True, checked=0)
        checked = 0
        for ev in self.evidence_for(session_id):
            content = (
                ev.session_id,
                ev.source_path,
                ev.sha256,
                ev.size,
                ev.media_type,
                ev.acquired_at,
                ev.note,
            )
            expected = self._chain(ev.prev_hash, _canonical_evidence(content))
            checked += 1
            if expected != ev.row_hmac:
                return CustodyVerdict(False, checked, f"evidence row {ev.id}")
        for pr in self.procedure_for(session_id):
            pcontent = (
                pr.session_id,
                pr.step,
                pr.operation,
                pr.actor,
                pr.argv,
                pr.input_sha256,
                pr.output_digest,
                pr.created_at,
                pr.note,
                pr.examiner,
                pr.tool_version,
            )
            expected = self._chain(pr.prev_hash, "\x1f".join(str(v) for v in pcontent))
            checked += 1
            if expected != pr.row_hmac:
                return CustodyVerdict(False, checked, f"procedure row {pr.id}")
        return CustodyVerdict(ok=True, checked=checked)


def load_or_create_custody_key(path: Path) -> bytes:
    """The per-case HMAC key at ``path``, created 0600 on first use (audit E20).

    The key is kept in a file beside -- never inside -- the case DB, so the chain is
    forgeable only by someone who holds this file, not merely by someone who can
    write the database. Stable across reopen so ``verify_custody`` keeps working.
    """
    expanded = path.expanduser()
    with suppress(OSError):
        data = expanded.read_bytes()
        if data:
            return data
    key = secrets.token_bytes(32)
    ensure_parent(expanded)
    expanded.write_bytes(key)
    with suppress(OSError):
        expanded.chmod(0o600)
    return key
