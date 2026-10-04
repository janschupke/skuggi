"""L1: the OSINT scope dimension -- subject matching + JSON round-trip.

``subject_in_scope`` is the OSINT analogue of the command guard's
``_target_in_scope``: a false allow is a real authorization bug, so every
branch (apex, subdomain, member, miss, empty) is pinned. The round-trip proves
the sub-model persists into scope.json unchanged, so an engagement reload keeps
the OSINT boundary intact.
"""

from __future__ import annotations

import pytest

from skuggi.engagement.scope import EngagementConfig, OsintScope
from skuggi.tooling.registry import RiskTier


def _osint(**kw: object) -> OsintScope:
    base: dict[str, object] = {
        "organizations": frozenset({"Acme Corp"}),
        "domains": frozenset({"acme.com"}),
        "people": frozenset({"jdoe"}),
        "github_orgs": frozenset({"acme"}),
        "enabled_sources": frozenset({"crtsh", "github"}),
    }
    base.update(kw)
    return OsintScope(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("subject", "expected"),
    [
        ("acme.com", True),  # apex exact
        ("mail.acme.com", True),  # subdomain
        ("ACME.COM", True),  # case-insensitive
        ("notacme.com", False),  # not a subdomain (no dot boundary)
        ("evil-acme.com", False),
        ("Acme Corp", True),  # org member, case-insensitive
        ("jdoe", True),  # person member
        ("acme", True),  # github org member
        ("other", False),  # not a member
        ("", False),  # empty
        ("   ", False),  # whitespace only
    ],
)
def test_subject_in_scope(subject: str, expected: bool) -> None:
    assert _osint().subject_in_scope(subject) is expected


def test_defaults_are_conservative() -> None:
    empty = OsintScope()
    assert empty.passive_only is True
    assert empty.autonomous_ceiling is RiskTier.recon
    assert empty.enabled_sources == frozenset()
    assert empty.subject_in_scope("anything.com") is False


def test_engagement_without_osint_disables_it() -> None:
    e = EngagementConfig(name="x", timezone="UTC")
    assert e.osint is None


def test_osint_round_trips_through_scope_json() -> None:
    e = EngagementConfig(
        name="x",
        timezone="UTC",
        osint=_osint(passive_only=False, autonomous_ceiling=RiskTier.active),
    )
    restored = EngagementConfig.model_validate_json(e.model_dump_json())
    assert restored.osint == e.osint
    assert restored.osint is not None
    assert restored.osint.autonomous_ceiling is RiskTier.active
    assert restored.osint.passive_only is False
