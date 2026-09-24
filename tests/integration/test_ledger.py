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
