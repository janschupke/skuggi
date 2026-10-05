"""L1: foothold persistence + runtime reachability routing (pivot, P0)."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from skuggi.agent.executor import _run_or_propose
from skuggi.agent.graph import GraphDeps
from skuggi.common import execution
from skuggi.engagement.pivot import route_for
from skuggi.engagement.scope import EngagementConfig
from skuggi.persistence.ledger import Ledger, open_ledger
from skuggi.persistence.ledger_schema import FootholdRow
from skuggi.tooling.registry import RiskTier, ToolRegistry, ToolSpec


def _foothold(**kw: object) -> FootholdRow:
    base: dict[str, object] = {
        "id": 1,
        "session_id": "s1",
        "host": "portal.bastion.lab",
        "transport": "command",
        "template": "python3 -c '{cmd}'",
        "secret_ref": "",
        "reachable_networks": "10.9.0.0/24",
        "reachable_hosts": "admin.internal",
        "created_at": "2026-10-05T00:00:00+00:00",
    }
    base.update(kw)
    return FootholdRow(**base)  # type: ignore[arg-type]


def test_route_via_foothold_for_an_internal_host() -> None:
    fh = _foothold()
    assert route_for("admin.internal", [fh]).foothold is fh  # exact host match
    assert route_for("10.9.0.10", [fh]).foothold is fh  # inside a reachable CIDR


def test_route_is_direct_for_a_reachable_or_unknown_target() -> None:
    fh = _foothold()
    assert route_for("10.9.9.9", [fh]).foothold is None  # outside the reachable net
    assert route_for("example.com", [fh]).foothold is None  # unlisted host
    assert route_for("", [fh]).foothold is None  # no target
    assert route_for("admin.internal", []).foothold is None  # no footholds


def test_first_reaching_foothold_wins() -> None:
    a = _foothold(id=1, host="dmz-a", reachable_networks="10.9.0.0/24")
    b = _foothold(id=2, host="dmz-b", reachable_networks="10.9.0.0/24")
    assert route_for("10.9.0.5", [a, b]).foothold is a


def test_ledger_records_a_foothold_without_storing_the_secret(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with open_ledger(path) as ledger:
        ledger.start_session("s1", engagement_name="e", mode="pentest")
        fid = ledger.record_foothold(
            session_id="s1",
            host="portal.bastion.lab",
            template="ssh root@portal -- {cmd}",
            secret_ref="«CRED:ab12cd»",
            reachable_networks="10.9.0.0/24",
            reachable_hosts="admin.internal",
        )
        assert fid > 0
        [fh] = ledger.footholds_for("s1")
        assert fh.host == "portal.bastion.lab"
        assert fh.reachable_hosts == "admin.internal"
        assert fh.secret_ref == "«CRED:ab12cd»"
    # Only the vault placeholder is stored (a real secret never reaches this table;
    # the journal interns it first -- covered end-to-end in the pivot verb tests).
    assert "«CRED:ab12cd»".encode() in path.read_bytes()


def test_ledger_clears_footholds(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "ledger.db") as ledger:
        ledger.start_session("s1", engagement_name="e", mode="pentest")
        ledger.record_foothold(session_id="s1", host="a")
        ledger.record_foothold(session_id="s1", host="b")
        assert len(ledger.footholds_for("s1")) == 2
        assert ledger.clear_footholds("s1") == 2
        assert ledger.footholds_for("s1") == []


# --- P1: transport-aware execution routing ---------------------------------

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
_REGISTRY = ToolRegistry(tools=(ToolSpec(name="nmap", binary="nmap", method="scan"),))


def _engagement(*, ceiling: RiskTier = RiskTier.active) -> EngagementConfig:
    return EngagementConfig.model_validate(
        {
            "name": "e",
            "timezone": "UTC",
            "target_networks": ("10.9.0.0/24",),
            "allowed_hosts": frozenset({"admin.internal"}),
            "allowed_tools": frozenset({"nmap"}),
            "allowed_methods": frozenset({"scan"}),
            "autonomous": True,
            "autonomous_ceiling": ceiling,
        }
    )


def _deps(ledger: object, *, ceiling: RiskTier = RiskTier.active) -> GraphDeps:
    return GraphDeps(
        engagement=_engagement(ceiling=ceiling),
        ledger=ledger,  # type: ignore[arg-type]
        registry=_REGISTRY,
        session_id="s1",
    )


def _ledger_with_foothold(tmp_path: Path, **kw: object) -> object:
    led = Ledger(sqlite3.connect(str(tmp_path / "ledger.db"), check_same_thread=False))
    led.start_session("s1", engagement_name="e", mode="pentest")
    base: dict[str, object] = {
        "session_id": "s1",
        "host": "portal.bastion.lab",
        "template": "ssh root@portal -- {cmd}",
        "reachable_networks": "10.9.0.0/24",
        "reachable_hosts": "admin.internal",
    }
    base.update(kw)
    led.record_foothold(**base)  # type: ignore[arg-type]
    return led


def test_pivoted_command_is_held_proposed_at_the_default_ceiling(
    tmp_path: Path,
) -> None:
    led = _ledger_with_foothold(tmp_path)
    _cid, brief, ran = _run_or_propose(_deps(led), "nmap 10.9.0.10", tmp_path, now=_NOW)
    assert ran is False
    assert brief.status == "proposed"
    assert "routes via foothold portal.bastion.lab" in brief.summary


def test_out_of_scope_target_is_denied_even_with_a_matching_foothold(
    tmp_path: Path,
) -> None:
    # A foothold that reaches an out-of-scope network must not smuggle it past the
    # guard: authorization precedes routing.
    led = _ledger_with_foothold(tmp_path, reachable_networks="172.16.0.0/24")
    _cid, brief, ran = _run_or_propose(
        _deps(led), "nmap 172.16.0.5", tmp_path, now=_NOW
    )
    assert ran is False
    assert brief.status == "blocked"


def test_pivoted_command_wraps_the_argv_and_keeps_the_inner_display(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run(argv: Sequence[str], **kw: object) -> execution.CommandResult:
        captured["argv"] = list(argv)
        captured["display"] = kw.get("display_command")
        return execution.CommandResult(
            command=str(kw.get("display_command")),
            exit_code=0,
            stdout="open",
            stderr="",
            started_at=_NOW,
            finished_at=_NOW,
        )

    monkeypatch.setattr("skuggi.agent.executor.execution.run", fake_run)
    led = _ledger_with_foothold(tmp_path)
    # Raise the ceiling so the (pivot-elevated) command auto-runs.
    _cid, brief, ran = _run_or_propose(
        _deps(led, ceiling=RiskTier.intrusive), "nmap 10.9.0.10", tmp_path, now=_NOW
    )
    assert ran is True
    assert brief.status == "executed"
    # The wrapped argv runs locally; the recorded/model-facing command stays inner.
    assert captured["argv"] == ["ssh", "root@portal", "--", "nmap", "10.9.0.10"]
    assert captured["display"] == "nmap 10.9.0.10"
    assert brief.command == "nmap 10.9.0.10"
    assert "[via foothold portal.bastion.lab]" in brief.summary


def test_direct_command_is_unwrapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run(argv: Sequence[str], **kw: object) -> execution.CommandResult:
        captured["argv"] = list(argv)
        return execution.CommandResult(
            command="x",
            exit_code=0,
            stdout="",
            stderr="",
            started_at=_NOW,
            finished_at=_NOW,
        )

    monkeypatch.setattr("skuggi.agent.executor.execution.run", fake_run)
    # A foothold exists but does not reach this target -> a direct, unwrapped run.
    led = _ledger_with_foothold(tmp_path, reachable_hosts="", reachable_networks="")
    _cid, brief, ran = _run_or_propose(_deps(led), "nmap 10.9.0.10", tmp_path, now=_NOW)
    assert ran is True
    assert captured["argv"] == ["nmap", "10.9.0.10"]
    assert "[via foothold" not in brief.summary
