"""L1: the gated Burp action runner (gate -> record -> execute|propose|block).

Drives a real keyed in-memory ledger so the recording + tamper-chain are exercised
end to end, and a fake execute closure so no client/network is touched. Pins the
three authorization outcomes and that only a cleared action runs the closure.
"""

from __future__ import annotations

import secrets
import sqlite3
from pathlib import Path

from skuggi.burp.actions import BurpOutcome, run_burp_action
from skuggi.engagement.scope import BurpScope, EngagementConfig
from skuggi.persistence.ledger import Ledger
from skuggi.tooling.registry import RiskTier


def _ledger(path: Path) -> Ledger:
    led = Ledger(sqlite3.connect(str(path), check_same_thread=False))
    led.custody_key = secrets.token_bytes(32)
    led.start_session("s1", engagement_name="e", mode="pentest")
    return led


def _eng(scope: BurpScope | None) -> EngagementConfig:
    raw: dict[str, object] = {
        "name": "e",
        "timezone": "UTC",
        "target_networks": ["10.0.0.0/24"],
        "burp": scope,
    }
    return EngagementConfig(**raw)  # type: ignore[arg-type]


def _scope(**kw: object) -> BurpScope:
    base: dict[str, object] = {
        "allowed_actions": frozenset({"scan_issues", "repeater", "active_scan"}),
        "passive_only": False,
        "autonomous_ceiling": RiskTier.active,
    }
    base.update(kw)
    return BurpScope(**base)  # type: ignore[arg-type]


def _run(
    led: Ledger, eng: EngagementConfig, action: str, host: str, **kw: object
) -> tuple[BurpOutcome, list[int]]:
    calls: list[int] = []

    def _execute() -> tuple[str, str]:
        calls.append(1)
        return ("ran", kw.get("handle", ""))  # type: ignore[return-value]

    outcome = run_burp_action(
        engagement=eng,
        ledger=led,
        session_id="s1",
        thread_id="t",
        action=action,  # type: ignore[arg-type]
        target_host=host,
        params=f"{action} {host}",
        autonomous=bool(kw.get("autonomous", True)),
        execute=_execute,
    )
    return outcome, calls


def test_out_of_scope_traffic_is_blocked_and_recorded(tmp_path: Path) -> None:
    led = _ledger(tmp_path / "l.db")
    outcome, calls = _run(led, _eng(_scope()), "repeater", "8.8.8.8")
    assert outcome.status == "blocked"
    assert not calls  # the closure never ran
    row = led.burp_actions_for("s1")[0]
    assert row.status == "blocked"
    assert "hard block" in outcome.summary


def test_above_ceiling_is_proposed(tmp_path: Path) -> None:
    led = _ledger(tmp_path / "l.db")
    # ceiling recon: an active repeater is in scope but over the ceiling
    eng = _eng(_scope(autonomous_ceiling=RiskTier.recon))
    outcome, calls = _run(led, eng, "repeater", "10.0.0.5")
    assert outcome.status == "proposed"
    assert not calls
    row = led.burp_actions_for("s1")[0]
    assert row.status == "proposed"
    assert row.risk_tier == "active"


def test_non_autonomous_is_proposed(tmp_path: Path) -> None:
    led = _ledger(tmp_path / "l.db")
    outcome, _ = _run(led, _eng(_scope()), "repeater", "10.0.0.5", autonomous=False)
    assert outcome.status == "proposed"
    assert "not armed" in outcome.summary


def test_cleared_action_runs_and_records_executed(tmp_path: Path) -> None:
    led = _ledger(tmp_path / "l.db")
    outcome, calls = _run(
        led, _eng(_scope()), "active_scan", "10.0.0.5", handle="scan-9"
    )
    assert outcome.status == "executed"
    assert outcome.ran
    assert outcome.handle == "scan-9"
    assert calls == [1]
    row = led.burp_actions_for("s1")[0]
    assert row.status == "executed"
    assert row.authority == "autonomous"
    assert row.handle == "scan-9"
    assert led.verify_timeline("s1").ok  # the chain stays intact


def test_read_action_needs_no_host(tmp_path: Path) -> None:
    led = _ledger(tmp_path / "l.db")
    outcome, calls = _run(led, _eng(_scope()), "scan_issues", "")
    assert outcome.status == "executed"
    assert calls == [1]
