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


def _bin(name: str, method: str) -> ToolSpec:
    return ToolSpec(name=name, binary=name, method=method)


def test_nmap_vuln_script_is_intrusive() -> None:
    got = risk_tier(_bin("nmap", "scan"), ["nmap", "--script", "vuln", "h"])
    assert got == RiskTier.intrusive


def test_nmap_exploit_script_is_destructive() -> None:
    assert risk_tier(_bin("nmap", "scan"), ["nmap", "--script=exploit", "h"]) == (
        RiskTier.destructive
    )


def test_nmap_plain_scan_stays_active() -> None:
    assert risk_tier(_bin("nmap", "scan"), ["nmap", "-sV", "h"]) == RiskTier.active
    assert risk_tier(_bin("nmap", "scan"), ["nmap", "--script=default", "h"]) == (
        RiskTier.active
    )


def test_curl_write_requests_are_intrusive() -> None:
    curl = _bin("curl", "recon")
    assert risk_tier(curl, ["curl", "-X", "POST", "http://h"]) == RiskTier.intrusive
    assert risk_tier(curl, ["curl", "--data", "a=b", "http://h"]) == RiskTier.intrusive
    assert risk_tier(curl, ["curl", "-T", "f", "http://h"]) == RiskTier.intrusive


def test_curl_get_stays_recon() -> None:
    got = risk_tier(_bin("curl", "recon"), ["curl", "http://h/x"])
    assert got == RiskTier.recon


def test_sqlmap_and_nikto_baseline_are_intrusive() -> None:
    sqlmap = risk_tier(_bin("sqlmap", "enumerate"), ["sqlmap", "-u", "http://h"])
    assert sqlmap == RiskTier.intrusive
    nikto = risk_tier(_bin("nikto", "scan"), ["nikto", "-h", "http://h"])
    assert nikto == RiskTier.intrusive


def test_explicit_risk_still_wins_over_binary_base() -> None:
    spec = ToolSpec(
        name="sqlmap", binary="sqlmap", method="enumerate", risk=RiskTier.active
    )
    assert risk_tier(spec, ["sqlmap", "-u", "http://h"]) == RiskTier.active
