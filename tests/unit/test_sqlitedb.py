"""L1: the shared SQLite hardening (WAL + busy timeout + 0600 perms)."""

from __future__ import annotations

import sqlite3
import stat
from pathlib import Path

from skuggi.common.sqlitedb import harden, restrict


def test_harden_sets_wal_and_restricts_permissions(tmp_path: Path) -> None:
    db = tmp_path / "x.db"
    conn = sqlite3.connect(str(db))
    try:
        harden(conn, db)
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] > 0
    finally:
        conn.close()
    assert stat.S_IMODE(db.stat().st_mode) == 0o600


def test_restrict_tolerates_a_missing_file(tmp_path: Path) -> None:
    # A chmod failure must be logged, not raised (it never blocks a session).
    restrict(tmp_path / "does-not-exist")
