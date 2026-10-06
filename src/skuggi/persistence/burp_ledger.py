"""The Burp-action ledger: recording and reading agent-driven Burp actions.

Split from :mod:`skuggi.persistence.ledger` as its own mixin -- Burp actions are a
distinct timeline from process ``commands`` (no argv/binary/exit code; they carry
an async task ``handle`` instead), so grouping their one writer and one reader
keeps that boundary legible and the main ledger module under its size cap. The
rows are insert-only and hash-chained exactly like commands (the DB triggers +
:mod:`skuggi.persistence.integrity`). Runs on the ``Ledger``'s own connection and
lock; never instantiated alone.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import TYPE_CHECKING

from skuggi.common.clock import now_iso
from skuggi.persistence.ledger_schema import (
    _BURP_ACTION_COLS,
    BurpActionRow,
    EventKind,
    _insert_sql,
    _select_sql,
)

if TYPE_CHECKING:

    class _LedgerBase:
        """The Ledger surface this mixin relies on (declared for the type checker)."""

        _conn: sqlite3.Connection
        _lock: threading.Lock

        def _timeline_chain(
            self, table: str, session_id: str, content_values: tuple[object, ...]
        ) -> tuple[str, str]: ...

        def _event_locked(  # noqa: PLR0913
            self,
            *,
            session_id: str,
            thread_id: str | None,
            kind: str,
            ref_id: int | None = ...,
            text: str = ...,
            created_at: str | None = ...,
        ) -> int: ...
else:
    _LedgerBase = object


class BurpLedgerMixin(_LedgerBase):
    """Record and read agent-driven Burp actions on the engagement timeline."""

    def record_burp_action(  # noqa: PLR0913 -- keyword-only ledger columns
        self,
        *,
        session_id: str,
        thread_id: str,
        action: str,
        status: str,
        target: str = "",
        params: str = "",
        risk_tier: str = "",
        authority: str = "",
        handle: str = "",
        result_summary: str = "",
        reason: str = "",
    ) -> int:
        """Insert a Burp-action row (plus its timeline event) and return its id.

        The Burp analogue of ``record_command``: ``status`` is ``proposed`` /
        ``blocked`` / ``executed``; ``handle`` carries Burp's task id for an
        in-flight scan/attack. A matching ``burp`` timeline event is written in the
        same transaction so the action appears on the ordered session spine.
        """
        created_at = now_iso()
        content = (
            session_id,
            thread_id,
            action,
            target,
            params,
            status,
            risk_tier,
            authority,
            handle,
            result_summary,
            reason,
            created_at,
        )
        with self._lock, self._conn:
            prev, row_hmac = self._timeline_chain("burp_actions", session_id, content)
            cur = self._conn.execute(
                _insert_sql("burp_actions", _BURP_ACTION_COLS[1:]),
                (*content, prev, row_hmac),
            )
            aid = int(cur.lastrowid or 0)
            self._event_locked(
                session_id=session_id,
                thread_id=thread_id,
                kind=EventKind.BURP,
                ref_id=aid,
                created_at=created_at,
            )
            return aid

    def burp_actions_for(self, session_id: str) -> list[BurpActionRow]:
        """Every Burp action in the session, oldest first."""
        with self._lock:
            rows = self._conn.execute(
                _select_sql(
                    "burp_actions",
                    _BURP_ACTION_COLS,
                    "WHERE session_id = ? ORDER BY id",
                ),
                (session_id,),
            ).fetchall()
        return [BurpActionRow(*row) for row in rows]
