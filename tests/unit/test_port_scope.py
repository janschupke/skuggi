"""L1: the engagement guard's optional port-scope dimension (allowed_ports).

Split from test_engagement.py (file-size cap): port scoping is its own concern,
with its own nmap spec carrying ``port_flags``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from skuggi.engagement.engagement import EngagementConfig, check_command, parse_command
from skuggi.tooling.registry import ToolRegistry, ToolSpec

REGISTRY = ToolRegistry(
    tools=(
        ToolSpec(
            name="nmap",
            binary="nmap",
            method="scan",
            port_flags=("-p", "--ports"),
        ),
    )
)

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def _engagement(**overrides: object) -> EngagementConfig:
    base: dict[str, object] = {
        "name": "e",
        "timezone": "UTC",
        "target_networks": ("10.0.0.0/8",),
        "allowed_tools": frozenset({"nmap"}),
        "allowed_methods": frozenset({"scan"}),
    }
    base.update(overrides)
    return EngagementConfig.model_validate(base)


# --- port scope (allowed_ports) ---------------------------------------------


def test_parse_ports_expands_lists_and_ranges() -> None:
    cmd = parse_command("nmap -p 22,80,8000-8002 10.0.0.5", REGISTRY)
    assert cmd.ports == (22, 80, 8000, 8001, 8002)
    assert cmd.ports_unresolved is False


def test_parse_ports_strips_nmap_proto_prefix() -> None:
    cmd = parse_command("nmap -p T:22,U:53 10.0.0.5", REGISTRY)
    assert set(cmd.ports) == {22, 53}


def test_parse_ports_flags_an_unresolvable_spec() -> None:
    assert parse_command("nmap -p 1- 10.0.0.5", REGISTRY).ports_unresolved is True
    assert parse_command("nmap -p http 10.0.0.5", REGISTRY).ports_unresolved is True


def test_port_scope_unset_allows_any_port() -> None:
    verdict = check_command(
        parse_command("nmap -p 1-65535 10.0.0.5", REGISTRY), _engagement(), now=NOW
    )
    assert verdict.allowed is True  # allowed_ports empty = every port


def test_port_scope_allows_in_scope_ports() -> None:
    eng = _engagement(allowed_ports=frozenset({80, 443}))
    verdict = check_command(
        parse_command("nmap -p 80,443 10.0.0.5", REGISTRY), eng, now=NOW
    )
    assert verdict.allowed is True


def test_port_scope_denies_an_out_of_scope_port() -> None:
    eng = _engagement(allowed_ports=frozenset({80, 443}))
    verdict = check_command(
        parse_command("nmap -p 22,80 10.0.0.5", REGISTRY), eng, now=NOW
    )
    assert verdict.allowed is False
    assert "22" in verdict.reason


def test_port_scope_denies_an_unresolvable_spec_when_scoped() -> None:
    eng = _engagement(allowed_ports=frozenset({80}))
    verdict = check_command(
        parse_command("nmap -p 1- 10.0.0.5", REGISTRY), eng, now=NOW
    )
    assert verdict.allowed is False
    assert "could not be resolved" in verdict.reason


def test_port_scope_allows_a_portless_command() -> None:
    """A command naming no port uses tool defaults and is unaffected by the gate."""
    eng = _engagement(allowed_ports=frozenset({80}))
    verdict = check_command(parse_command("nmap 10.0.0.5", REGISTRY), eng, now=NOW)
    assert verdict.allowed is True
