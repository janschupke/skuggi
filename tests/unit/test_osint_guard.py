"""L1: the OSINT guard -- deny-by-default, every gate pinned.

The OSINT analogue of test_engagement's allow/deny matrix: the guard must be
conservative, so there is one case per deny gate (source disabled, subject out of
scope, active source under passive-only, tier over ceiling) plus the allow.
"""

from __future__ import annotations

import pytest

from skuggi.engagement.osint_guard import check_osint_task, source_tier
from skuggi.engagement.scope import OsintScope, OsintSource
from skuggi.tooling.registry import RiskTier


def _scope(**kw: object) -> OsintScope:
    base: dict[str, object] = {
        "domains": frozenset({"acme.com"}),
        "organizations": frozenset({"Acme Corp"}),
        "enabled_sources": frozenset({"crtsh", "github", "linkedin"}),
        "passive_only": True,
        "autonomous_ceiling": RiskTier.recon,
    }
    base.update(kw)
    return OsintScope(**base)  # type: ignore[arg-type]


def test_passive_source_in_scope_is_allowed() -> None:
    verdict = check_osint_task("crtsh", "acme.com", _scope())
    assert verdict.allowed
    assert verdict.reason == "in scope"


def test_subdomain_subject_is_allowed() -> None:
    assert check_osint_task("github", "mail.acme.com", _scope()).allowed


def test_disabled_source_is_denied() -> None:
    verdict = check_osint_task("dns", "acme.com", _scope())
    assert not verdict.allowed
    assert "not enabled" in verdict.reason


def test_out_of_scope_subject_is_denied() -> None:
    verdict = check_osint_task("crtsh", "evil.com", _scope())
    assert not verdict.allowed
    assert "outside the authorized OSINT scope" in verdict.reason


def test_active_source_denied_under_passive_only() -> None:
    # linkedin is enabled and the subject is in scope, but it is an active source.
    verdict = check_osint_task("linkedin", "acme.com", _scope(passive_only=True))
    assert not verdict.allowed
    assert "passive-only" in verdict.reason


def test_active_source_allowed_when_not_passive_and_ceiling_raised() -> None:
    scope = _scope(passive_only=False, autonomous_ceiling=RiskTier.active)
    assert check_osint_task("linkedin", "acme.com", scope).allowed


def test_active_source_denied_above_ceiling_even_when_not_passive() -> None:
    scope = _scope(passive_only=False, autonomous_ceiling=RiskTier.recon)
    verdict = check_osint_task("linkedin", "acme.com", scope)
    assert not verdict.allowed
    assert "exceeds the OSINT ceiling" in verdict.reason


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("crtsh", RiskTier.recon),
        ("dns", RiskTier.recon),
        ("github", RiskTier.recon),
        ("websearch", RiskTier.recon),
        ("shodan", RiskTier.recon),
        ("linkedin", RiskTier.active),
        ("ats", RiskTier.active),
        ("social", RiskTier.active),
    ],
)
def test_source_tier_mapping(source: OsintSource, expected: RiskTier) -> None:
    assert source_tier(source) is expected
