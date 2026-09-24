"""SQLite ledger for sessions, commands and findings.

A separate database from the LangGraph checkpointer (``memory.py``), with a
schema we own -- the checkpointer's tables are private and not ours to depend
on, and keeping them apart lets langgraph evolve freely. This is the "file DB"
the harness persists to: every command the agent proposes, blocks or runs lands
in ``commands`` with timestamps, and every finding links back to the session
and to the source command it came from, which is what makes a finding
traceable.

``open_ledger`` mirrors ``memory.open_checkpointer``: a context manager that
creates the file and its parent and yields a live handle for the session.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from skuggi.execution import CommandResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    engagement_name TEXT NOT NULL,
    mode            TEXT NOT NULL,
    started_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    thread_id   TEXT NOT NULL,
    command     TEXT NOT NULL,
    binary      TEXT NOT NULL,
    method      TEXT,
    status      TEXT NOT NULL,
    exit_code   INTEGER,
    stdout      TEXT NOT NULL DEFAULT '',
    stderr      TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT '',
    started_at  TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    command_id  INTEGER REFERENCES commands(id),
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence    TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
"""


@dataclass(frozen=True, slots=True)
class SessionRow:
    """One engagement session."""

    session_id: str
    engagement_name: str
    mode: str
    started_at: str


@dataclass(frozen=True, slots=True)
class CommandRow:
    """One recorded command (proposed, blocked or executed)."""

    id: int
    session_id: str
    thread_id: str
    command: str
    binary: str
    method: str | None
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    reason: str
    started_at: str
    finished_at: str | None


@dataclass(frozen=True, slots=True)
class FindingRow:
    """One finding, linked to its session and (optionally) source command."""

    id: int
    session_id: str
    command_id: int | None
    title: str
    severity: str
    description: str
    evidence: str
    created_at: str


def _now() -> str:
    return datetime.now(UTC).isoformat()


class Ledger:
    """A thin, typed wrapper over the ledger database."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        # LangGraph runs graph nodes on a worker-thread pool, and a tool that
        # calls the ledger therefore touches this connection from a thread other
        # than the one that opened it. The connection is opened with
        # check_same_thread=False (see open_ledger) and every access is guarded
        # by this lock, which is what makes cross-thread writes safe.
        self._conn = conn
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def start_session(
        self, session_id: str, *, engagement_name: str, mode: str
    ) -> None:
        """Record the start of a session (idempotent on session_id)."""
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO sessions"
                " (session_id, engagement_name, mode, started_at) VALUES (?, ?, ?, ?)",
                (session_id, engagement_name, mode, _now()),
            )
            self._conn.commit()

    def record_command(  # noqa: PLR0913 -- keyword-only ledger columns
        self,
        *,
        session_id: str,
        thread_id: str,
        command: str,
        binary: str,
        method: str | None,
        status: str,
        reason: str = "",
        result: CommandResult | None = None,
    ) -> int:
        """Insert a command row and return its id.

        `status` is ``proposed`` / ``blocked`` / ``executed`` / ``passthrough``.
        A `result` fills the execution fields; without one (proposed/blocked)
        only the start time is stamped.
        """
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO commands (session_id, thread_id, command, binary, method,"
                " status, exit_code, stdout, stderr, reason, started_at, finished_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    thread_id,
                    command,
                    binary,
                    method,
                    status,
                    result.exit_code if result else None,
                    result.stdout if result else "",
                    result.stderr if result else "",
                    reason,
                    result.started_at.isoformat() if result else _now(),
                    result.finished_at.isoformat() if result else None,
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def record_finding(  # noqa: PLR0913 -- keyword-only ledger columns
        self,
        *,
        session_id: str,
        title: str,
        severity: str,
        description: str,
        evidence: str = "",
        command_id: int | None = None,
    ) -> int:
        """Insert a finding row and return its id."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO findings (session_id, command_id, title, severity,"
                " description, evidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    command_id,
                    title,
                    severity,
                    description,
                    evidence,
                    _now(),
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def latest_command_id(self, session_id: str) -> int | None:
        """The id of the most recently recorded command in this session."""
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM commands WHERE session_id = ? ORDER BY id DESC LIMIT 1",
                (session_id,),
            ).fetchone()
        return int(row[0]) if row else None

    def session(self, session_id: str) -> SessionRow | None:
        """The session row, or None if it was never started."""
        with self._lock:
            row = self._conn.execute(
                "SELECT session_id, engagement_name, mode, started_at"
                " FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return SessionRow(*row) if row else None

    def commands_for(self, session_id: str) -> list[CommandRow]:
        """Every command in the session, oldest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, session_id, thread_id, command, binary, method, status,"
                " exit_code, stdout, stderr, reason, started_at, finished_at"
                " FROM commands WHERE session_id = ? ORDER BY id",
                (session_id,),
            ).fetchall()
        return [CommandRow(*row) for row in rows]

    def findings_for(self, session_id: str) -> list[FindingRow]:
        """Every finding in the session, oldest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, session_id, command_id, title, severity, description,"
                " evidence, created_at FROM findings WHERE session_id = ? ORDER BY id",
                (session_id,),
            ).fetchall()
        return [FindingRow(*row) for row in rows]


@contextmanager
def open_ledger(path: Path) -> Iterator[Ledger]:
    """Open a `Ledger` over `path`, creating the file and its parent.

    Hold this open for the lifetime of the session, like the checkpointer.
    """
    path.expanduser().parent.mkdir(parents=True, exist_ok=True)
    # check_same_thread=False because graph nodes (and thus ledger-writing tools)
    # run on a worker-thread pool; Ledger serializes every access with a lock.
    conn = sqlite3.connect(str(path.expanduser()), check_same_thread=False)
    try:
        yield Ledger(conn)
    finally:
        conn.close()
