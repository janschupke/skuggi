"""L2: the ledger against a real SQLite file, incl. FK linkage and reopen."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from skuggi.common.execution import CommandResult
from skuggi.frameworks import cvss
from skuggi.persistence.ledger import FindingRefInput, open_ledger


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


def test_cvss_finding_stores_full_breakdown_and_refs(tmp_path: Path) -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"  # reflected XSS, 6.1
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        fid = led.record_finding(
            session_id="s1",
            title="Reflected XSS in /search",
            description="user input reflected unencoded",
            cvss_vector=vector,  # no severity passed -> derived from CVSS
            refs=[
                FindingRefInput("wstg", "WSTG-CLNT-01", is_primary=True),
                FindingRefInput("attack", "T1189"),
            ],
        )
        [finding] = led.findings_for("s1")
        assert finding.id == fid
        assert finding.severity == "medium"  # derived from the 6.1 band
        assert finding.cvss_version == "3.1"
        assert finding.cvss_base == 6.1
        assert finding.cvss_score == 6.1
        assert finding.cvss_severity == "medium"
        # Reproducible from the stored row alone -- no turn context.
        assert cvss.score(finding.cvss_vector).overall == finding.cvss_score  # type: ignore[arg-type]

        refs = led.finding_refs_for(fid)
        assert [(r.framework, r.ref_id, r.is_primary) for r in refs] == [
            ("wstg", "WSTG-CLNT-01", 1),  # primary first
            ("attack", "T1189", 0),
        ]
        wstg = refs[0]
        assert wstg.title  # resolved from the vendored taxonomy
        assert wstg.url.startswith("https://owasp.org/")


def test_finding_without_severity_or_vector_is_rejected(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        with pytest.raises(ValueError, match="severity or a cvss_vector"):
            led.record_finding(session_id="s1", title="x", description="d")


def test_migrates_a_pre_cvss_ledger(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE sessions (session_id TEXT PRIMARY KEY, engagement_name TEXT
            NOT NULL, mode TEXT NOT NULL, started_at TEXT NOT NULL);
        CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT
            NOT NULL, command_id INTEGER, title TEXT NOT NULL, severity TEXT NOT NULL,
            description TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL);
        INSERT INTO sessions VALUES ('s1', 'e', 'pentest', 't');
        INSERT INTO findings (session_id, title, severity, description, evidence,
            created_at) VALUES ('s1', 'old finding', 'low', 'd', '', 't');
        """
    )
    conn.commit()
    conn.close()

    # Opening it migrates in place: the old row reads back with NULL cvss fields,
    # and new CVSS findings + refs work against the upgraded DB.
    with open_ledger(path) as led:
        [old] = led.findings_for("s1")
        assert old.title == "old finding"
        assert old.severity == "low"
        assert old.cvss_vector is None
        assert old.cvss_score is None
        new = led.record_finding(
            session_id="s1",
            title="new",
            description="d",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        assert led.finding(new).cvss_score == 9.8  # type: ignore[union-attr]
