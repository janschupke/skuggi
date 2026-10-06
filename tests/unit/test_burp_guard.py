"""L1: the Burp action guard + the host_in_scope helper it reuses, offline.

Pins the deny-by-default chain: connector-enabled, action allow-list, the
network/host boundary for traffic actions (reusing the command guard's scope
machinery incl. RoE exclusion deny-wins), and the passive-only gate. The ceiling
is deliberately NOT a gate here (it is the caller's ESCALATION decision).
"""

from __future__ import annotations

from skuggi.engagement.burp_guard import action_tier, check_burp_action
from skuggi.engagement.guard import host_in_scope
from skuggi.engagement.scope import BurpScope, EngagementConfig
from skuggi.tooling.registry import RiskTier


def _eng(**kw: object) -> EngagementConfig:
    base: dict[str, object] = {
        "name": "burp-eng",
        "timezone": "UTC",
        "target_networks": ["10.0.0.0/24"],
        "allowed_hosts": ["app.local"],
    }
    base.update(kw)
    return EngagementConfig(**base)  # type: ignore[arg-type]


def _scope(**kw: object) -> BurpScope:
    base: dict[str, object] = {
        "allowed_actions": frozenset(
            {"scan_issues", "repeater", "active_scan", "intruder"}
        ),
        "passive_only": False,
    }
    base.update(kw)
    return BurpScope(**base)  # type: ignore[arg-type]


def test_disabled_connector_denies() -> None:
    verdict = check_burp_action("scan_issues", "", _eng())
    assert not verdict.allowed
    assert "not enabled" in verdict.reason


def test_action_not_on_allow_list_denies() -> None:
    eng = _eng(burp=_scope(allowed_actions=frozenset({"scan_issues"})))
    verdict = check_burp_action("repeater", "10.0.0.5", eng)
    assert not verdict.allowed
    assert "not permitted" in verdict.reason


def test_read_action_allowed_without_host() -> None:
    eng = _eng(burp=_scope())
    assert check_burp_action("scan_issues", "", eng).allowed


def test_traffic_action_in_scope_allowed() -> None:
    eng = _eng(burp=_scope())
    assert check_burp_action("repeater", "10.0.0.5", eng).allowed


def test_traffic_action_out_of_scope_denied() -> None:
    eng = _eng(burp=_scope())
    verdict = check_burp_action("repeater", "8.8.8.8", eng)
    assert not verdict.allowed
    assert "outside the authorized scope" in verdict.reason


def test_traffic_action_excluded_host_denied() -> None:
    eng = _eng(
        burp=_scope(),
        rules_of_engagement={"excluded_hosts": ["10.0.0.9"]},
    )
    verdict = check_burp_action("active_scan", "10.0.0.9", eng)
    assert not verdict.allowed
    assert "exclusion list" in verdict.reason


def test_passive_only_forbids_active_action() -> None:
    eng = _eng(burp=_scope(passive_only=True))
    # a read still passes under passive-only...
    assert check_burp_action("scan_issues", "", eng).allowed
    # ...but an active-traffic action does not.
    verdict = check_burp_action("repeater", "10.0.0.5", eng)
    assert not verdict.allowed
    assert "passive-only" in verdict.reason


def test_action_tiers() -> None:
    assert action_tier("scan_issues") is RiskTier.recon
    assert action_tier("repeater") is RiskTier.active
    assert action_tier("intruder") is RiskTier.intrusive


def test_host_in_scope_helper() -> None:
    eng = _eng()
    assert host_in_scope("10.0.0.5", eng).allowed
    assert host_in_scope("app.local", eng).allowed
    assert not host_in_scope("", eng).allowed
    assert not host_in_scope("1.2.3.4", eng).allowed
