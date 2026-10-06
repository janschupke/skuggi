"""L1: the engagement timeline's tamper-evidence hash chain (integrity.py).

A keyed in-memory ledger is driven through the four chained tables; the chain is
verified clean, legitimate finding-lifecycle edits leave it clean, and an
out-of-band edit/deletion is caught by the re-walk or the DB triggers.
"""

from __future__ import annotations

import secrets
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from skuggi.common.execution import CommandResult
from skuggi.persistence.ledger import Ledger


def _ledger(path: Path) -> Ledger:
    # Construct directly (not via open_ledger's context manager, whose temporary
    # would be GC'd and close the connection mid-test).
    return Ledger(sqlite3.connect(str(path), check_same_thread=False))


def _keyed(path: Path) -> Ledger:
    led = _ledger(path)
    led.custody_key = secrets.token_bytes(32)
    led.start_session("s1", engagement_name="e", mode="pentest")
    return led


def _a_command(led: Ledger) -> int:
    now = datetime.now(UTC)
    return led.record_command(
        session_id="s1",
        thread_id="t",
        command="nmap 10.0.0.5",
        binary="nmap",
        method="scan",
        status="executed",
        result=CommandResult("nmap 10.0.0.5", 0, "open", "", now, now),
        risk_tier="active",
        authority="autonomous",
    )


def _a_finding(led: Ledger, command_id: int) -> int:
    return led.record_finding(
        session_id="s1",
        title="telnet open",
        description="d",
        severity="high",
        evidence="proof",
        command_id=command_id,
    )


def test_timeline_chain_verifies_clean(tmp_path: Path) -> None:
    led = _keyed(tmp_path / "l.db")
    cid = _a_command(led)
    _a_finding(led, cid)
    led.record_audit(session_id="s1", kind="control", verb="set", detail="scope x")
    verdict = led.verify_timeline("s1")
    assert verdict.ok is True
    assert verdict.checked >= 4  # command, finding, their events, audit


def test_finding_lifecycle_does_not_break_the_chain(tmp_path: Path) -> None:
    led = _keyed(tmp_path / "l.db")
    fid = _a_finding(led, _a_command(led))
    led.set_finding_status(fid, "approved")  # draft -> approved, in place
    assert led.verify_timeline("s1").ok is True


def test_forged_finding_substance_is_detected(tmp_path: Path) -> None:
    led = _keyed(tmp_path / "l.db")
    fid = _a_finding(led, _a_command(led))
    # UPDATE is allowed on findings (no no_update trigger) but title is chained.
    led._conn.execute("UPDATE findings SET title = 'forged' WHERE id = ?", (fid,))
    led._conn.commit()
    verdict = led.verify_timeline("s1")
    assert verdict.ok is False
    assert verdict.broken_at == f"findings row {fid}"


def test_append_only_triggers_block_tampering(tmp_path: Path) -> None:
    led = _keyed(tmp_path / "l.db")
    cid = _a_command(led)
    fid = _a_finding(led, cid)
    with pytest.raises(sqlite3.IntegrityError):
        led._conn.execute("UPDATE commands SET command = 'x' WHERE id = ?", (cid,))
    with pytest.raises(sqlite3.IntegrityError):
        led._conn.execute("DELETE FROM commands WHERE id = ?", (cid,))
    with pytest.raises(sqlite3.IntegrityError):
        led._conn.execute("DELETE FROM findings WHERE id = ?", (fid,))
    # but the review lifecycle (in-place UPDATE on findings) is allowed, not blocked
    led.set_finding_status(fid, "approved")
    assert led.verify_timeline("s1").ok is True


def test_legacy_unkeyed_row_is_skipped(tmp_path: Path) -> None:
    led = _ledger(tmp_path / "l.db")
    led.start_session("s1", engagement_name="e", mode="pentest")
    _a_command(led)  # written with NO key -> row_hmac == '' (legacy)
    led.custody_key = secrets.token_bytes(32)
    _a_command(led)  # written WITH the key -> chained
    verdict = led.verify_timeline("s1")
    assert verdict.ok is True
    assert verdict.checked >= 1  # only the keyed rows counted


def test_keyless_ledger_is_vacuously_ok(tmp_path: Path) -> None:
    led = _ledger(tmp_path / "l.db")
    led.start_session("s1", engagement_name="e", mode="pentest")
    _a_command(led)
    verdict = led.verify_timeline("s1")
    assert verdict.ok is True
    assert verdict.checked == 0


def _a_burp_action(led: Ledger, *, status: str = "executed") -> int:
    return led.record_burp_action(
        session_id="s1",
        thread_id="t",
        action="active_scan",
        status=status,
        target="10.0.0.5",
        params="scan https://10.0.0.5/",
        risk_tier="active",
        authority="autonomous",
        handle="scan-7",
        result_summary="2 issues",
    )


def test_burp_action_is_chained_and_verifies_clean(tmp_path: Path) -> None:
    led = _keyed(tmp_path / "l.db")
    _a_burp_action(led)
    verdict = led.verify_timeline("s1")
    assert verdict.ok is True
    # the action + its timeline event are both chained
    assert verdict.checked >= 2
    rows = led.burp_actions_for("s1")
    assert rows[0].handle == "scan-7"
    assert rows[0].action == "active_scan"


def test_forged_burp_action_is_detected(tmp_path: Path) -> None:
    led = _keyed(tmp_path / "l.db")
    aid = _a_burp_action(led)
    # UPDATE is blocked by the append-only trigger, so forge via a raw rewrite
    # with the trigger temporarily unavailable is not possible; instead prove the
    # DB trigger refuses the tamper outright.
    with pytest.raises(sqlite3.IntegrityError):
        led._conn.execute(
            "UPDATE burp_actions SET target = 'evil.com' WHERE id = ?", (aid,)
        )


def test_burp_action_delete_is_blocked(tmp_path: Path) -> None:
    led = _keyed(tmp_path / "l.db")
    aid = _a_burp_action(led)
    with pytest.raises(sqlite3.IntegrityError):
        led._conn.execute("DELETE FROM burp_actions WHERE id = ?", (aid,))
