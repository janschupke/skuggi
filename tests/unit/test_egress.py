"""L1: the network-egress boundary -- SSRF deny-list and scope-bound posture.

All resolution is either a literal IP (no DNS) or a monkeypatched ``_resolve``,
so the suite never performs a real lookup under the blanket network block.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable

import pytest

from skuggi.engagement import egress
from skuggi.engagement.egress import EgressPolicy, _IpAddress
from skuggi.engagement.scope import EngagementConfig, RulesOfEngagement

_Resolver = Callable[[str], "tuple[_IpAddress, ...] | None"]


def _fixed_resolve(host_to_ips: dict[str, tuple[str, ...]]) -> _Resolver:
    def _resolve(host: str) -> tuple[_IpAddress, ...] | None:
        ips = host_to_ips.get(host)
        return tuple(ipaddress.ip_address(ip) for ip in ips) if ips else None

    return _resolve


# --- public-recon posture ---------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",  # loopback
        "169.254.169.254",  # cloud metadata
        "10.1.2.3",  # RFC-1918
        "192.168.0.5",
        "172.16.9.9",
        "0.0.0.0",  # unspecified  # noqa: S104
        "::1",  # IPv6 loopback
        "fd00::1",  # IPv6 ULA
        "::ffff:127.0.0.1",  # IPv4-mapped loopback must not slip past
    ],
)
def test_public_recon_denies_sensitive_literals(ip: str) -> None:
    assert EgressPolicy.public_recon().check_host(ip).allowed is False


def test_public_recon_allows_a_public_literal() -> None:
    assert EgressPolicy.public_recon().check_host("93.184.216.34").allowed is True


def test_public_recon_denies_a_name_resolving_to_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        egress, "_resolve", _fixed_resolve({"evil.example": ("169.254.169.254",)})
    )
    decision = EgressPolicy.public_recon().check_url("http://evil.example/latest/")
    assert decision.allowed is False
    assert "non-public" in decision.reason


def test_public_recon_allows_a_name_resolving_public(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        egress, "_resolve", _fixed_resolve({"example.com": ("93.184.216.34",)})
    )
    assert EgressPolicy.public_recon().check_url("https://example.com/x").allowed


def test_unresolvable_host_is_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(egress, "_resolve", _fixed_resolve({}))
    assert EgressPolicy.public_recon().check_host("nope.invalid").allowed is False


def test_empty_host_is_denied() -> None:
    assert EgressPolicy.public_recon().check_url("file:///etc/passwd").allowed is False


# --- scope-bound posture ----------------------------------------------------


def test_from_engagement_allows_in_scope_private_but_not_others() -> None:
    engagement = EngagementConfig(
        name="e",
        timezone="UTC",
        target_networks=("10.0.0.0/24",),  # type: ignore[arg-type]
        allowed_hosts=frozenset({"box.lab"}),
        rules_of_engagement=RulesOfEngagement(excluded_hosts=frozenset({"10.0.0.9"})),
    )
    policy = EgressPolicy.from_engagement(engagement)
    assert policy.check_host("10.0.0.5").allowed is True  # in scope (private OK here)
    assert policy.check_host("10.0.0.9").allowed is False  # excluded: deny wins
    assert policy.check_host("8.8.8.8").allowed is False  # out of scope
