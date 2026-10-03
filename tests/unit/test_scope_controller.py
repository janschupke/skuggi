"""L1: natural-language scope editing -- pure edit/diff helpers and the controller."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast

import pytest

from skuggi.agent.core import AgentCore
from skuggi.agent.protocol import ScopeEdit, ScopeProposal
from skuggi.agent.scope_controller import (
    ScopeController,
    apply_scope_edits,
    scope_diff,
)
from skuggi.engagement.engagement import EngagementConfig
from skuggi.tooling.registry import RiskTier


def _engagement(**overrides: object) -> EngagementConfig:
    base: dict[str, object] = {
        "name": "e",
        "timezone": "UTC",
        "authorized_start": datetime(2026, 1, 1, tzinfo=UTC),
        "authorized_end": datetime(2026, 12, 31, 23, 59, tzinfo=UTC),
        "target_networks": ("10.0.0.0/8",),
        "allowed_hosts": frozenset({"scanme.example.com"}),
        "allowed_tools": frozenset({"nmap"}),
        "allowed_methods": frozenset({"scan"}),
    }
    base.update(overrides)
    return EngagementConfig.model_validate(base)


def test_add_and_remove_set_fields() -> None:
    eng = _engagement()
    after = apply_scope_edits(
        eng,
        (
            ScopeEdit(field="allowed_hosts", action="add", value="new.example.com"),
            ScopeEdit(field="allowed_tools", action="add", value="nikto"),
            ScopeEdit(field="allowed_methods", action="remove", value="scan"),
        ),
    )
    assert "new.example.com" in after.allowed_hosts
    assert after.allowed_tools == frozenset({"nmap", "nikto"})
    assert after.allowed_methods == frozenset()


def test_add_a_network_is_revalidated() -> None:
    after = apply_scope_edits(
        _engagement(),
        (ScopeEdit(field="target_networks", action="add", value="192.168.0.0/16"),),
    )
    assert any(str(n) == "192.168.0.0/16" for n in after.target_networks)


def test_set_the_autonomous_ceiling() -> None:
    after = apply_scope_edits(
        _engagement(),
        (ScopeEdit(field="autonomous_ceiling", action="set", value="intrusive"),),
    )
    assert after.autonomous_ceiling is RiskTier.intrusive


def test_an_invalid_cidr_is_rejected_not_written() -> None:
    with pytest.raises(ValueError, match=r"network|value"):
        apply_scope_edits(
            _engagement(),
            (ScopeEdit(field="target_networks", action="add", value="not-a-cidr"),),
        )


def test_an_invalid_tier_is_rejected() -> None:
    with pytest.raises(ValueError, match=r"risk tier|value"):
        apply_scope_edits(
            _engagement(),
            (ScopeEdit(field="autonomous_ceiling", action="set", value="nuclear"),),
        )


def test_scope_diff_reports_only_changed_fields() -> None:
    eng = _engagement()
    after = apply_scope_edits(
        eng, (ScopeEdit(field="allowed_tools", action="add", value="nikto"),)
    )
    rows = scope_diff(eng, after)
    assert [field for field, _, _ in rows] == ["allowed_tools"]
    _field, old, new = rows[0]
    assert "nmap" in old
    assert "nikto" in new


# --- the controller ---------------------------------------------------------


def _controller(
    engagement: EngagementConfig | None, applied: list[object]
) -> ScopeController:
    core = SimpleNamespace(
        engagement=engagement,
        apply_engagement_scope=applied.append,
    )
    return ScopeController(cast("AgentCore", core))


def test_propose_keeps_only_well_formed_edits(monkeypatch: pytest.MonkeyPatch) -> None:
    proposal = ScopeProposal(
        edits=(
            ScopeEdit(field="allowed_tools", action="add", value="nikto"),  # valid
            ScopeEdit(field="allowed_tools", action="set", value="x"),  # set on a set
            ScopeEdit(field="autonomous_ceiling", action="add", value="recon"),  # bad
        )
    )
    monkeypatch.setattr(
        "skuggi.agent.scope_controller.structured_invoke",
        lambda *_a, **_k: proposal,
    )
    core = SimpleNamespace(
        ensure_llm=object,
        settings=SimpleNamespace(supports_structured_output=lambda: False),
    )
    kept = ScopeController(cast("AgentCore", core)).propose("add nikto")
    assert kept == [ScopeEdit(field="allowed_tools", action="add", value="nikto")]


def test_preview_and_apply_round_trip() -> None:
    applied: list[object] = []
    ctrl = _controller(_engagement(), applied)
    edits = [ScopeEdit(field="allowed_tools", action="add", value="nikto")]
    assert [f for f, _, _ in ctrl.preview(edits)] == ["allowed_tools"]
    summary = ctrl.apply(edits)
    assert "1 field" in summary
    assert len(applied) == 1  # the edited engagement was handed to the core to persist


def test_apply_without_engagement_raises() -> None:
    ctrl = _controller(None, [])
    with pytest.raises(ValueError, match="no engagement"):
        ctrl.apply([ScopeEdit(field="allowed_tools", action="add", value="nikto")])
