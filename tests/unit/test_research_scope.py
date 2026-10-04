"""L1: the research boundary -- public sources only, no offensive path."""

from __future__ import annotations

import pytest

from skuggi.research.schema import RESEARCH_SOURCES
from skuggi.research.scope import RESEARCH_SOURCE_TIER, check_research_source
from skuggi.tooling.registry import RiskTier


@pytest.mark.parametrize("source", RESEARCH_SOURCES)
def test_every_research_source_is_allowed_and_recon_tier(source: str) -> None:
    verdict = check_research_source(source)
    assert verdict.allowed
    assert RESEARCH_SOURCE_TIER[source] is RiskTier.recon  # type: ignore[index]


def test_no_research_source_exceeds_recon() -> None:
    assert all(tier is RiskTier.recon for tier in RESEARCH_SOURCE_TIER.values())


@pytest.mark.parametrize("source", ["nmap", "exploit", "", "shodan-active"])
def test_unknown_source_is_denied(source: str) -> None:
    verdict = check_research_source(source)
    assert not verdict.allowed
    assert "unknown research source" in verdict.reason
