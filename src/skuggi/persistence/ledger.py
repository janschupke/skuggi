"""SQLite ledger for sessions, commands, findings, events and audit.

A separate database from the LangGraph checkpointer (``memory.py``), with a
schema we own -- the checkpointer's tables are private and not ours to depend
on, and keeping them apart lets langgraph evolve freely. This is the "file DB"
the harness persists to.

Two logs live here, deliberately separated:

* The **engagement timeline** -- ``events`` is its ordered spine (one row per
  operator prompt, agent response, command or finding, in the order they
  happened), with ``commands`` and ``findings`` holding the detail an event of
  that kind points at (``events.ref_id``). Every command the agent proposes,
  blocks, runs -- or that the operator free-types (``passthrough``) -- lands in
  ``commands`` with timestamps; every finding links back to the command it came
  from (``findings.command_id``) and, transitively, to the prompt that drove it
  (``commands.turn_event_id``). Rendering the events in order *is* the
  replayable session transcript; ``reports.render_report`` reads only
  ``commands``/``findings``, so the outward-facing report never leaks prompts.
* The **harness-interaction audit** -- ``audit`` records ``/skuggi`` control
  verbs, filtered CLI noise, and the private LLM session review. It is logged
  separately from the timeline and is never part of a client-facing report.

``open_ledger`` mirrors ``memory.open_checkpointer``: a context manager that
creates the file and its parent and yields a live handle for the session.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from pathlib import Path

from skuggi.common.execution import CommandResult

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
    finished_at TEXT,
    turn_event_id INTEGER            -- -> events(id): the prompt that drove it
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
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    thread_id   TEXT,
    kind        TEXT NOT NULL,       -- prompt | response | command | finding
    ref_id      INTEGER,             -- -> commands(id) / findings(id) by kind
    text        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    kind        TEXT NOT NULL,       -- control | cli | review
    verb        TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
"""

# Columns added to `commands` after the initial release; each is applied to an
# already-created table with ADD COLUMN when missing (a fresh DB gets them from
# the schema above). Kept plain (no REFERENCES) so ADD COLUMN is always legal.
_COMMAND_MIGRATIONS = (("turn_event_id", "INTEGER"),)


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
    turn_event_id: int | None


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


@dataclass(frozen=True, slots=True)
class EventRow:
    """One entry on the engagement timeline (the ordered session spine).

    ``kind`` is ``prompt`` / ``response`` (``text`` holds the operator directive
    or agent answer) or ``command`` / ``finding`` (``ref_id`` points at the
    ``commands`` / ``findings`` row carrying the detail).
    """

    id: int
    session_id: str
    thread_id: str | None
    kind: str
    ref_id: int | None
    text: str
    created_at: str


@dataclass(frozen=True, slots=True)
class AuditRow:
    """One harness-interaction record (a control verb, CLI noise, or a review)."""

    id: int
    session_id: str
    kind: str
    verb: str
    detail: str
    created_at: str


def finding_line(
    row: FindingRow, paint: Callable[[str, str], str] | None = None
) -> str:
    """One-line summary of a finding: ``SEV [id] title (cmd:N)``.

    Shared by the REPL and the shell daemon so the row shape and the command
    link never drift. ``paint`` styles the severity token (the REPL passes the
    palette; the plaintext daemon passes nothing).
    """
    severity = row.severity.upper()
    if paint is not None:
        severity = paint(severity, row.severity)
    link = f" (cmd:{row.command_id})" if row.command_id is not None else ""
    return f"{severity} [{row.id}] {row.title}{link}"


def _now() -> str:
    return datetime.now(UTC).isoformat()


# Column lists derived from the row dataclasses, so SELECT order (and the
# positional Row(*row) unpacking) can never drift from the field order. The
# INSERT lists drop the autoincrement id.
_SESSION_COLS = tuple(f.name for f in fields(SessionRow))
_COMMAND_COLS = tuple(f.name for f in fields(CommandRow))
_FINDING_COLS = tuple(f.name for f in fields(FindingRow))
_EVENT_COLS = tuple(f.name for f in fields(EventRow))
_AUDIT_COLS = tuple(f.name for f in fields(AuditRow))


# The column names interpolated below are code-defined dataclass field names
# (never user input), so the S608 string-building warning does not apply.
def _insert_sql(table: str, columns: tuple[str, ...]) -> str:
    """An INSERT statement for `columns` with positional placeholders."""
    placeholders = ", ".join("?" * len(columns))
    cols = ", ".join(columns)
    return f"INSERT INTO {table} ({cols}) VALUES ({placeholders})"  # noqa: S608


def _select_sql(table: str, columns: tuple[str, ...], clause: str) -> str:
    """A SELECT of `columns` from `table` with a trailing WHERE/ORDER clause."""
    cols = ", ".join(columns)
    return f"SELECT {cols} FROM {table} {clause}"  # noqa: S608


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
            self._migrate_commands()
            self._conn.commit()

    def _migrate_commands(self) -> None:
        """Add any post-release ``commands`` columns missing from an older DB.

        A fresh database gets these from ``_SCHEMA``; a ledger created before the
        column existed is upgraded in place with ADD COLUMN. Idempotent -- run on
        every open. The caller holds the lock.
        """
        have = {row[1] for row in self._conn.execute("PRAGMA table_info(commands)")}
        for name, decl in _COMMAND_MIGRATIONS:
            if name not in have:
                self._conn.execute(f"ALTER TABLE commands ADD COLUMN {name} {decl}")

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
        turn_event_id: int | None = None,
    ) -> int:
        """Insert a command row (plus its timeline event) and return its id.

        `status` is ``proposed`` / ``blocked`` / ``executed`` / ``passthrough``.
        A `result` fills the execution fields; without one (proposed/blocked)
        only the start time is stamped. `turn_event_id` links the command to the
        prompt event that drove it (``None`` for an operator-initiated command).
        A matching ``command`` event is written in the same transaction, so the
        command always appears on the ordered timeline.
        """
        started_at = result.started_at.isoformat() if result else _now()
        with self._lock:
            cur = self._conn.execute(
                _insert_sql("commands", _COMMAND_COLS[1:]),
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
                    started_at,
                    result.finished_at.isoformat() if result else None,
                    turn_event_id,
                ),
            )
            cid = int(cur.lastrowid or 0)
            self._event_locked(
                session_id=session_id,
                thread_id=thread_id,
                kind="command",
                ref_id=cid,
                created_at=started_at,
            )
            self._conn.commit()
            return cid

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
        """Insert a finding row (plus its timeline event) and return its id."""
        created_at = _now()
        with self._lock:
            cur = self._conn.execute(
                _insert_sql("findings", _FINDING_COLS[1:]),
                (
                    session_id,
                    command_id,
                    title,
                    severity,
                    description,
                    evidence,
                    created_at,
                ),
            )
            fid = int(cur.lastrowid or 0)
            self._event_locked(
                session_id=session_id,
                thread_id=None,
                kind="finding",
                ref_id=fid,
                created_at=created_at,
            )
            self._conn.commit()
            return fid

    def _event_locked(  # noqa: PLR0913 -- keyword-only event columns
        self,
        *,
        session_id: str,
        thread_id: str | None,
        kind: str,
        ref_id: int | None = None,
        text: str = "",
        created_at: str | None = None,
    ) -> int:
        """Insert one timeline event. The caller holds the lock and commits."""
        cur = self._conn.execute(
            _insert_sql("events", _EVENT_COLS[1:]),
            (session_id, thread_id, kind, ref_id, text, created_at or _now()),
        )
        return int(cur.lastrowid or 0)

    def record_event(
        self,
        *,
        session_id: str,
        thread_id: str | None,
        kind: str,
        text: str = "",
    ) -> int:
        """Record a ``prompt`` / ``response`` timeline event and return its id.

        Command and finding events are written by ``record_command`` /
        ``record_finding``; this is the entry point for the operator prompt and
        the agent's answer, which have no separate detail row.
        """
        with self._lock:
            eid = self._event_locked(
                session_id=session_id, thread_id=thread_id, kind=kind, text=text
            )
            self._conn.commit()
            return eid

    def record_audit(
        self,
        *,
        session_id: str,
        kind: str,
        verb: str = "",
        detail: str = "",
    ) -> int:
        """Record a harness-interaction entry (control verb, CLI noise, review).

        Separate from the engagement timeline: ``reports.render_report`` never
        reads this table, so nothing here reaches a client-facing report.
        """
        with self._lock:
            cur = self._conn.execute(
                _insert_sql("audit", _AUDIT_COLS[1:]),
                (session_id, kind, verb, detail, _now()),
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
                _select_sql("sessions", _SESSION_COLS, "WHERE session_id = ?"),
                (session_id,),
            ).fetchone()
        return SessionRow(*row) if row else None

    def sessions(self) -> list[SessionRow]:
        """Every session in this ledger, most recent first (for retrieval)."""
        with self._lock:
            rows = self._conn.execute(
                _select_sql("sessions", _SESSION_COLS, "ORDER BY started_at DESC")
            ).fetchall()
        return [SessionRow(*row) for row in rows]

    def command(self, command_id: int) -> CommandRow | None:
        """One command row by id, or None."""
        with self._lock:
            row = self._conn.execute(
                _select_sql("commands", _COMMAND_COLS, "WHERE id = ?"),
                (command_id,),
            ).fetchone()
        return CommandRow(*row) if row else None

    def finding(self, finding_id: int) -> FindingRow | None:
        """One finding row by id, or None."""
        with self._lock:
            row = self._conn.execute(
                _select_sql("findings", _FINDING_COLS, "WHERE id = ?"),
                (finding_id,),
            ).fetchone()
        return FindingRow(*row) if row else None

    def events_for(self, session_id: str) -> list[EventRow]:
        """The session's timeline events, in order (the replay spine)."""
        with self._lock:
            rows = self._conn.execute(
                _select_sql("events", _EVENT_COLS, "WHERE session_id = ? ORDER BY id"),
                (session_id,),
            ).fetchall()
        return [EventRow(*row) for row in rows]

    def audit_for(self, session_id: str) -> list[AuditRow]:
        """The session's harness-interaction audit entries, oldest first."""
        with self._lock:
            rows = self._conn.execute(
                _select_sql("audit", _AUDIT_COLS, "WHERE session_id = ? ORDER BY id"),
                (session_id,),
            ).fetchall()
        return [AuditRow(*row) for row in rows]

    def commands_for(self, session_id: str) -> list[CommandRow]:
        """Every command in the session, oldest first."""
        with self._lock:
            rows = self._conn.execute(
                _select_sql(
                    "commands", _COMMAND_COLS, "WHERE session_id = ? ORDER BY id"
                ),
                (session_id,),
            ).fetchall()
        return [CommandRow(*row) for row in rows]

    def findings_for(self, session_id: str) -> list[FindingRow]:
        """Every finding in the session, oldest first."""
        with self._lock:
            rows = self._conn.execute(
                _select_sql(
                    "findings", _FINDING_COLS, "WHERE session_id = ? ORDER BY id"
                ),
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
