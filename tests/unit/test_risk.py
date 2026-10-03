"""L1: deterministic command risk tiering (no LLM in the safety gate)."""

from __future__ import annotations

import pytest

from skuggi.engagement.risk import risk_tier
from skuggi.tooling.registry import RiskTier, ToolSpec


def _spec(method: str, *, risk: RiskTier | None = None) -> ToolSpec:
    return ToolSpec(name="t", binary="t", method=method, risk=risk)


@pytest.mark.parametrize(
    ("method", "expected"),
    [
        ("recon", RiskTier.recon),
        ("scan", RiskTier.active),
        ("enumerate", RiskTier.active),
        ("bruteforce", RiskTier.intrusive),
        ("crack", RiskTier.intrusive),
        ("exploit", RiskTier.destructive),
    ],
)
def test_method_sets_the_base_tier(method: str, expected: RiskTier) -> None:
    assert risk_tier(_spec(method), ["t", "x"]) == expected


def test_unknown_method_is_destructive() -> None:
    assert risk_tier(_spec("mystery"), ["t"]) == RiskTier.destructive


def test_no_spec_is_destructive() -> None:
    assert risk_tier(None, ["whatever"]) == RiskTier.destructive


def test_explicit_risk_overrides_method() -> None:
    # nc-like: a `recon` tool flagged destructive (a shell/pivot primitive).
    assert risk_tier(_spec("recon", risk=RiskTier.destructive), ["nc"]) == (
        RiskTier.destructive
    )


def test_explicit_risk_can_be_below_method_default() -> None:
    assert risk_tier(_spec("exploit", risk=RiskTier.recon), ["t"]) == RiskTier.recon


def test_sudo_raises_to_destructive() -> None:
    assert risk_tier(_spec("recon"), ["sudo", "tcpdump"]) == RiskTier.destructive


def test_os_shell_flag_raises_to_destructive() -> None:
    assert risk_tier(_spec("enumerate"), ["sqlmap", "--os-shell"]) == (
        RiskTier.destructive
    )


def test_dump_flag_raises_to_intrusive_only() -> None:
    # A `--dump` on an `active` tool reaches intrusive, not destructive.
    assert risk_tier(_spec("enumerate"), ["sqlmap", "--dump"]) == RiskTier.intrusive


def test_flag_with_value_compares_on_the_head() -> None:
    assert risk_tier(_spec("enumerate"), ["sqlmap", "--file-write=/tmp/x"]) == (
        RiskTier.destructive
    )


def test_heuristics_only_raise_never_lower() -> None:
    # An exploit tool with a benign argv stays destructive (no flag lowers it).
    assert risk_tier(_spec("exploit"), ["msfconsole", "-q"]) == RiskTier.destructive


def test_tier_serializes_to_its_name() -> None:
    spec = ToolSpec(name="t", binary="t", method="recon", risk=RiskTier.destructive)
    assert '"risk":"destructive"' in spec.model_dump_json().replace(" ", "")


def test_tier_validates_from_name_and_rank() -> None:
    assert (
        ToolSpec.model_validate(
            {"name": "t", "binary": "t", "method": "recon", "risk": "intrusive"}
        ).risk
        is RiskTier.intrusive
    )
    assert (
        ToolSpec.model_validate(
            {"name": "t", "binary": "t", "method": "recon", "risk": 2}
        ).risk
        is RiskTier.intrusive
    )


def test_unknown_tier_name_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown risk tier"):
        ToolSpec.model_validate(
            {"name": "t", "binary": "t", "method": "recon", "risk": "nuclear"}
        )
