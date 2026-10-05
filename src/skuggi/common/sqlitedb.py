"""Shared hardening for the local SQLite databases (ledger, preferences, history).

Single-user, but these files hold harvested target output and full session state,
so they are created ``0600`` like the vault rather than at the process umask
(audit C3), and opened in WAL mode with a ``busy_timeout`` so a second connection
-- a client process, the report/PDF path, or the operator's own ``sqlite3`` session
-- gets a short wait instead of an immediate "database is locked" (audit B6).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from skuggi.common.logs import get_logger

log = get_logger(__name__)

# A momentary writer contention should wait briefly, not fail instantly.
_BUSY_TIMEOUT_MS = 5000


def harden(conn: sqlite3.Connection, path: Path) -> None:
    """Put `conn` in WAL mode with a busy timeout and restrict `path` to 0600."""
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
    except sqlite3.Error as exc:  # a pragma failure must not stop the session
        log.warning("could not set sqlite pragmas on %s: %s", path, exc)
    restrict(path)


def restrict(path: Path) -> None:
    """Restrict `path` to 0600 (best effort; a failure is logged, not fatal)."""
    try:
        Path(path).chmod(0o600)
    except OSError as exc:
        log.warning("could not restrict permissions on %s: %s", path, exc)
