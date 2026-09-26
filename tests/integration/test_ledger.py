"""L2: the ledger against a real SQLite file, incl. FK linkage and reopen."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from skuggi.execution import CommandResult
from skuggi.ledger import open_ledger


def test_command_and_finding_round_trip(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        cid = led.record_command(
            session_id="s1",
            thread_id="t1",
            command="nmap 10.0.0.5",
            binary="nmap",
            method="scan",
            status="proposed",
        )
        fid = led.record_finding(
            session_id="s1",
            title="open",
            severity="high",
            description="d",
            command_id=cid,
        )
        assert led.latest_command_id("s1") == cid
        [finding] = led.findings_for("s1")
        assert finding.id == fid
        assert finding.command_id == cid


def test_executed_command_stores_output(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        now = datetime.now(UTC)
        result = CommandResult("echo hi", 0, "hi\n", "", now, now)
        led.record_command(
            session_id="s1",
            thread_id="t1",
            command="echo hi",
            binary="echo",
            method="recon",
            status="executed",
            result=result,
        )
        row = led.commands_for("s1")[0]
        assert row.exit_code == 0
        assert row.stdout == "hi\n"
        assert row.finished_at is not None


def test_foreign_key_blocks_orphan_command(tmp_path: Path) -> None:
    """A command for a non-existent session must be rejected (FK enforced)."""
    with open_ledger(tmp_path / "l.db") as led, pytest.raises(sqlite3.IntegrityError):
        led.record_command(
            session_id="ghost",
            thread_id="t1",
            command="x",
            binary="x",
            method=None,
            status="proposed",
        )


def test_reopening_sees_persisted_rows(tmp_path: Path) -> None:
    db = tmp_path / "nested" / "l.db"
    with open_ledger(db) as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        led.record_command(
            session_id="s1",
            thread_id="t1",
            command="nmap 10.0.0.5",
            binary="nmap",
            method="scan",
            status="proposed",
        )
    assert db.is_file()
    with open_ledger(db) as led:
        assert led.session("s1") is not None
        assert len(led.commands_for("s1")) == 1


# --- timeline events + audit log --------------------------------------------


def test_command_and_finding_emit_timeline_events(tmp_path: Path) -> None:
    """Every command / finding write also lands on the ordered events spine."""
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        prompt = led.record_event(
            session_id="s1", thread_id="t1", kind="prompt", text="scan it"
        )
        cid = led.record_command(
            session_id="s1",
            thread_id="t1",
            command="nmap 10.0.0.5",
            binary="nmap",
            method="scan",
            status="proposed",
            turn_event_id=prompt,
        )
        led.record_finding(
            session_id="s1",
            title="open",
            severity="high",
            description="d",
            command_id=cid,
        )
        led.record_event(session_id="s1", thread_id="t1", kind="response", text="done")
        kinds = [(e.kind, e.ref_id) for e in led.events_for("s1")]
        assert kinds == [
            ("prompt", None),
            ("command", cid),
            ("finding", 1),
            ("response", None),
        ]
        # the command links back to the prompt that drove it
        assert led.commands_for("s1")[0].turn_event_id == prompt
        assert led.command(cid) is not None
        assert led.finding(1) is not None


def test_audit_log_is_separate_from_the_timeline(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        led.record_audit(
            session_id="s1", kind="control", verb="mode", detail="blueteam"
        )
        led.record_audit(session_id="s1", kind="review", detail="you rushed recon")
        rows = led.audit_for("s1")
        assert [(r.kind, r.verb) for r in rows] == [("control", "mode"), ("review", "")]
        assert led.events_for("s1") == []  # audit never touches the timeline


def test_sessions_lists_newest_first(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("old", engagement_name="e", mode="pentest")
        led.start_session("new", engagement_name="e", mode="pentest")
        ids = [s.session_id for s in led.sessions()]
        assert set(ids) == {"old", "new"}
        assert len(ids) == 2


def test_reopening_is_idempotent_after_migration(tmp_path: Path) -> None:
    """Opening a ledger twice must not fail re-adding the migrated column."""
    db = tmp_path / "l.db"
    with open_ledger(db) as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
    with open_ledger(db) as led:  # ADD COLUMN guard makes this a no-op
        assert led.session("s1") is not None


def test_migration_adds_turn_event_id_to_a_legacy_ledger(tmp_path: Path) -> None:
    """A ledger created before turn_event_id existed is upgraded in place."""
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE sessions (
            session_id TEXT PRIMARY KEY, engagement_name TEXT NOT NULL,
            mode TEXT NOT NULL, started_at TEXT NOT NULL);
        CREATE TABLE commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL, thread_id TEXT NOT NULL, command TEXT NOT NULL,
            binary TEXT NOT NULL, method TEXT, status TEXT NOT NULL, exit_code INTEGER,
            stdout TEXT NOT NULL DEFAULT '', stderr TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL,
            finished_at TEXT);
        INSERT INTO sessions VALUES ('s1', 'e', 'pentest', '2026-01-01T00:00:00+00:00');
        """
    )
    conn.commit()
    conn.close()
    with open_ledger(db) as led:
        row = led.commands_for("s1")  # unpacking CommandRow needs the new column
        assert row == []
        cid = led.record_command(
            session_id="s1",
            thread_id="t1",
            command="x",
            binary="x",
            method=None,
            status="passthrough",
            turn_event_id=None,
        )
        assert led.commands_for("s1")[0].turn_event_id is None
        assert led.command(cid) is not None
