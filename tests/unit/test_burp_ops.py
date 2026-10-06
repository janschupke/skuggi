"""L1: the burp_ops orchestration (scan / pull / scans), offline.

Drives a real keyed ledger + a fake client so the gate->record path, the
issue->finding ingestion and the cross-pull dedup are pinned without a live Burp.
"""

from __future__ import annotations

import secrets
import sqlite3
from pathlib import Path

from skuggi.agent import burp_ops
from skuggi.burp.client import BurpClient
from skuggi.burp.models import ScanIssue
from skuggi.engagement.scope import BurpScope, EngagementConfig
from skuggi.persistence.ledger import Ledger
from skuggi.tooling.registry import RiskTier


class _FakeClient:
    def __init__(self, issues: tuple[ScanIssue, ...] = ()) -> None:
        self._issues = issues
        self.scanned: list[str] = []

    def start_scan(self, url: str) -> str:
        self.scanned.append(url)
        return "scan-42"

    def scan_issues(self, *, host_filter: str = "") -> tuple[ScanIssue, ...]:
        return self._issues


def _ledger(path: Path) -> Ledger:
    led = Ledger(sqlite3.connect(str(path), check_same_thread=False))
    led.custody_key = secrets.token_bytes(32)
    led.start_session("s1", engagement_name="e", mode="pentest")
    return led


def _eng() -> EngagementConfig:
    raw: dict[str, object] = {
        "name": "e",
        "timezone": "UTC",
        "target_networks": ["10.0.0.0/24"],
        "autonomous": True,
        "burp": BurpScope(
            allowed_actions=frozenset({"scan_issues", "active_scan"}),
            passive_only=False,
            autonomous_ceiling=RiskTier.active,
        ),
    }
    return EngagementConfig(**raw)  # type: ignore[arg-type]


def _issue(name: str = "XSS") -> ScanIssue:
    return ScanIssue(
        issue_type=name.lower(),
        name=name,
        severity="medium",
        confidence="firm",
        host="10.0.0.5",
        protocol="https",
        path="/q",
        parameter="term",
    )


def _as_client(obj: _FakeClient) -> BurpClient:
    return obj  # type: ignore[return-value]


def test_scan_gates_runs_and_reports_handle(tmp_path: Path) -> None:
    led = _ledger(tmp_path / "l.db")
    client = _FakeClient()
    lines = burp_ops.scan(
        _as_client(client),
        _eng(),
        led,
        session_id="s1",
        thread_id="t",
        autonomous=True,
        url="https://10.0.0.5/app",
    )
    assert client.scanned == ["https://10.0.0.5/app"]
    assert "handle scan-42" in lines[0]
    assert led.burp_actions_for("s1")[0].handle == "scan-42"


def test_scan_out_of_scope_is_blocked(tmp_path: Path) -> None:
    led = _ledger(tmp_path / "l.db")
    client = _FakeClient()
    lines = burp_ops.scan(
        _as_client(client),
        _eng(),
        led,
        session_id="s1",
        thread_id="t",
        autonomous=True,
        url="https://8.8.8.8/",
    )
    assert client.scanned == []  # never reached the client
    assert "hard block" in lines[0]


def test_pull_records_new_findings_then_dedupes(tmp_path: Path) -> None:
    led = _ledger(tmp_path / "l.db")
    client = _FakeClient(issues=(_issue("XSS"), _issue("SQLi")))
    first = burp_ops.pull(
        _as_client(client), _eng(), led, session_id="s1", thread_id="t", autonomous=True
    )
    assert "recorded 2 new findings" in first[0]
    assert len(led.findings_for("s1")) == 2
    # a second pull of the same issues records nothing new
    second = burp_ops.pull(
        _as_client(client), _eng(), led, session_id="s1", thread_id="t", autonomous=True
    )
    assert "recorded 0 new findings" in second[0]
    assert len(led.findings_for("s1")) == 2


def test_scans_lists_recorded_actions(tmp_path: Path) -> None:
    led = _ledger(tmp_path / "l.db")
    client = _FakeClient()
    burp_ops.scan(
        _as_client(client),
        _eng(),
        led,
        session_id="s1",
        thread_id="t",
        autonomous=True,
        url="https://10.0.0.5/",
    )
    lines = burp_ops.scans(led, session_id="s1")
    assert any("active_scan" in line and "scan-42" in line for line in lines)


def test_scans_empty(tmp_path: Path) -> None:
    led = _ledger(tmp_path / "l.db")
    assert burp_ops.scans(led, session_id="s1") == [
        "burp: no actions recorded this session"
    ]
