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
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from skuggi.common.clock import now_iso
from skuggi.common.execution import CommandResult
from skuggi.common.paths import ensure_parent
from skuggi.common.sqlitedb import harden
from skuggi.frameworks import cvss, registry
from skuggi.persistence.ledger_schema import (
    _AUDIT_COLS,
    _COMMAND_COLS,
    _COMMAND_MIGRATIONS,
    _EVENT_COLS,
    _EVIDENCE_COLS,
    _FINDING_COLS,
    _FINDING_MIGRATIONS,
    _FINDING_REF_COLS,
    _INDEXES,
    _PROCEDURE_COLS,
    _SCHEMA,
    _SESSION_COLS,
    _TM_VERSION_COLS,
    AuditKind,
    AuditRow,
    CommandRow,
    CommandStatus,
    EventKind,
    EventRow,
    EvidenceRow,
    FindingAuthor,
    FindingRefInput,
    FindingRefRow,
    FindingRow,
    FindingStatus,
    ProcedureRow,
    SessionRow,
    ThreadSummary,
    ThreatModelVersionRow,
)

# The row types and status/kind vocabularies live in ``ledger_schema`` (a pure,
# connection-free module) but ``ledger`` stays their public home: re-export them so
# the ~20 ``from skuggi.persistence.ledger import <Row>`` sites need no change.
__all__ = [
    "AuditKind",
    "AuditRow",
    "CommandRow",
    "CommandStatus",
    "EventKind",
    "EventRow",
    "EvidenceRow",
    "FindingAuthor",
    "FindingRefInput",
    "FindingRefRow",
    "FindingRow",
    "FindingStatus",
    "Ledger",
    "ProcedureRow",
    "SessionRow",
    "ThreadSummary",
    "ThreatModelVersionRow",
    "open_ledger",
]


# The column names interpolated below are code-defined dataclass field names
# (never user input), so the S608 string-building warning does not apply.
def _effective_score(
    vector: str | None, env_metrics: dict[str, str] | None
) -> cvss.Score | None:
    """Score ``vector`` with the threat-model env overlay applied (not baked in)."""
    if not vector:
        return None
    effective = cvss.merged(vector, env_metrics) if env_metrics else vector
    return cvss.score(effective)


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
            self._migrate("commands", _COMMAND_MIGRATIONS)
            self._migrate("findings", _FINDING_MIGRATIONS)
            self._conn.executescript(_INDEXES)
            self._conn.commit()

    def _migrate(self, table: str, migrations: tuple[tuple[str, str], ...]) -> None:
        """Add any post-release columns missing from an older DB's ``table``.

        A fresh database gets these from ``_SCHEMA``; a ledger created before a
        column existed is upgraded in place with ADD COLUMN. Idempotent -- run on
        every open. The caller holds the lock. The ``table``/column names are
        code-defined (never user input), so S608 string-building does not apply.
        """
        have = {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in migrations:
            if name not in have:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    def start_session(
        self, session_id: str, *, engagement_name: str, mode: str
    ) -> None:
        """Record the start of a session (idempotent on session_id)."""
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO sessions"
                " (session_id, engagement_name, mode, started_at) VALUES (?, ?, ?, ?)",
                (session_id, engagement_name, mode, now_iso()),
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
        started_at = result.started_at.isoformat() if result else now_iso()
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
                kind=EventKind.COMMAND,
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
        description: str,
        severity: str | None = None,
        evidence: str = "",
        command_id: int | None = None,
        cvss_vector: str | None = None,
        env_metrics: dict[str, str] | None = None,
        tm_version: int | None = None,
        refs: Sequence[FindingRefInput] = (),
        author: str = FindingAuthor.AGENT,
    ) -> int:
        """Insert a finding (plus its timeline event and any refs); return its id.

        ``cvss_vector`` is the worker's intrinsic vector, stored **verbatim** (base +
        any temporal) so it can be rescored. ``env_metrics`` (the engagement threat
        model's CR/IR/AR) is overlaid only to derive the environmental/overall score;
        it is never baked into the stored vector, and ``tm_version`` records which
        threat-model version that overlay came from (so the score can be flagged
        outdated and recomputed later -- see :meth:`rescore_finding`). ``severity``
        may be omitted when a vector is present (it then takes the effective CVSS
        band). Every finding is born ``status='draft'``; ``author`` is 'agent' or
        'operator'. Only an approved finding reaches a report.
        """
        base = cvss.score(cvss_vector) if cvss_vector else None
        eff = _effective_score(cvss_vector, env_metrics)
        if severity is None:
            if eff is None:
                msg = "record_finding needs either a severity or a cvss_vector"
                raise ValueError(msg)
            severity = eff.severity
        created_at = now_iso()
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
                    base.version if base else None,
                    base.vector if base else None,
                    base.base if base else None,
                    base.temporal if base else None,
                    eff.environmental if eff else None,
                    eff.overall if eff else None,
                    eff.severity if eff else None,
                    author,
                    FindingStatus.DRAFT,
                    "",
                    None,
                    tm_version if base else None,
                    created_at if base else None,
                    created_at,
                ),
            )
            fid = int(cur.lastrowid or 0)
            for ref in refs:
                resolved = (
                    registry.resolve(ref.framework, ref.ref_id)
                    if ref.framework in registry.FRAMEWORKS
                    else None
                )
                self._conn.execute(
                    _insert_sql("finding_refs", _FINDING_REF_COLS[1:]),
                    (
                        fid,
                        ref.framework,
                        ref.ref_id,
                        resolved.title if resolved else "",
                        resolved.url if resolved else "",
                        int(ref.is_primary),
                    ),
                )
            self._event_locked(
                session_id=session_id,
                thread_id=None,
                kind=EventKind.FINDING,
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
            (session_id, thread_id, kind, ref_id, text, created_at or now_iso()),
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
                (session_id, kind, verb, detail, now_iso()),
            )
            self._conn.commit()
            return int(cur.lastrowid or 0)

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
        with self._lock:
            cur = self._conn.execute(
                _insert_sql("evidence", _EVIDENCE_COLS[1:]),
                (session_id, source_path, sha256, size, media_type, now_iso(), note),
            )
            self._conn.commit()
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
        with self._lock:
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
            self._conn.commit()
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

    def thread_summaries(self) -> list[ThreadSummary]:
        """Per-thread summaries (first prompt, turn count, last activity).

        Most-recently-active first. Built from the ``events`` table because the
        langgraph checkpointer exposes only thread ids; this is what makes
        ``show threads`` actionable for ``set thread``.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT thread_id, kind, text, created_at FROM events "
                "WHERE thread_id IS NOT NULL ORDER BY id"
            ).fetchall()
        turns: dict[str, int] = {}
        first: dict[str, str] = {}
        last: dict[str, str] = {}
        order: list[str] = []
        for thread_id, kind, text, created_at in rows:
            if thread_id not in turns:
                turns[thread_id], first[thread_id] = 0, ""
                order.append(thread_id)
            last[thread_id] = created_at  # ordered by id -> last row wins
            if kind == EventKind.PROMPT:
                turns[thread_id] += 1
                if not first[thread_id]:
                    first[thread_id] = text
        summaries = [
            ThreadSummary(tid, turns[tid], first[tid], last[tid]) for tid in order
        ]
        summaries.sort(key=lambda s: s.last_activity, reverse=True)
        return summaries

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

    def findings_for(
        self, session_id: str, *, status: str | None = None
    ) -> list[FindingRow]:
        """Every finding in the session, oldest first; optionally one status only."""
        clause = "WHERE session_id = ? ORDER BY id"
        params: tuple[object, ...] = (session_id,)
        if status is not None:
            clause = "WHERE session_id = ? AND status = ? ORDER BY id"
            params = (session_id, status)
        with self._lock:
            rows = self._conn.execute(
                _select_sql("findings", _FINDING_COLS, clause), params
            ).fetchall()
        return [FindingRow(*row) for row in rows]

    def approved_findings_for(self, session_id: str) -> list[FindingRow]:
        """Only the approved findings -- what a report is allowed to contain."""
        return self.findings_for(session_id, status=FindingStatus.APPROVED)

    def set_finding_status(
        self, finding_id: int, status: str, *, reason: str = ""
    ) -> None:
        """Move a finding to ``status`` ('approved'|'rejected'|'draft'), stamping it.

        A rejection carries its ``reason`` (shown to the operator and fed back to
        the agent); approving clears any prior reason.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE findings SET status = ?, review_reason = ?, reviewed_at = ?"
                " WHERE id = ?",
                (status, reason, now_iso(), finding_id),
            )
            self._conn.commit()

    def finding_refs_for(self, finding_id: int) -> list[FindingRefRow]:
        """The framework citations attached to a finding (primary first)."""
        with self._lock:
            rows = self._conn.execute(
                _select_sql(
                    "finding_refs",
                    _FINDING_REF_COLS,
                    "WHERE finding_id = ? ORDER BY is_primary DESC, id",
                ),
                (finding_id,),
            ).fetchall()
        return [FindingRefRow(*row) for row in rows]

    # ----- threat-model versioning ------------------------------------------

    def record_threat_model(self, snapshot: str, *, note: str = "") -> int:
        """Append a threat-model version (the snapshot env scores are tagged by)."""
        created_at = now_iso()
        with self._lock:
            cur = self._conn.execute(
                _insert_sql("threat_model_versions", _TM_VERSION_COLS[1:]),
                (snapshot, note, created_at),
            )
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def current_threat_model_version(self) -> int:
        """The latest recorded threat-model version, or 0 when none is recorded."""
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(version) FROM threat_model_versions"
            ).fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def threat_model_history(self) -> list[ThreatModelVersionRow]:
        """Every recorded threat-model version, oldest first (the change log)."""
        with self._lock:
            rows = self._conn.execute(
                _select_sql(
                    "threat_model_versions", _TM_VERSION_COLS, "ORDER BY version"
                )
            ).fetchall()
        return [ThreatModelVersionRow(*row) for row in rows]

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
        eff = _effective_score(row.cvss_vector, env_metrics)
        assert eff is not None  # noqa: S101 -- guaranteed by the vector check above
        with self._lock:
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
            self._conn.commit()
        return True


@contextmanager
def open_ledger(path: Path) -> Iterator[Ledger]:
    """Open a `Ledger` over `path`, creating the file and its parent.

    Hold this open for the lifetime of the session, like the checkpointer.
    """
    expanded = ensure_parent(path)
    # check_same_thread=False because graph nodes (and thus ledger-writing tools)
    # run on a worker-thread pool; Ledger serializes every access with a lock.
    conn = sqlite3.connect(str(expanded), check_same_thread=False)
    harden(conn, expanded)
    try:
        yield Ledger(conn)
    finally:
        conn.close()
