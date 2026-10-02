"""Each compliance golden case: the guard verdict must match its label."""

from __future__ import annotations

import pytest

from skuggi.engagement.engagement import EngagementConfig
from skuggi.eval.goldens import ComplianceCase, load_cases
from skuggi.eval.runner import score_compliance_case
from skuggi.tooling.registry import ToolRegistry
from tests.eval_det.conftest import EVALS_ROOT

_CASES = [
    c for c in load_cases("compliance", EVALS_ROOT) if isinstance(c, ComplianceCase)
]


@pytest.mark.parametrize("case", _CASES, ids=lambda c: c.id)
def test_compliance_case(
    case: ComplianceCase,
    registry: ToolRegistry,
    scopes: dict[str, EngagementConfig],
) -> None:
    score = score_compliance_case(case, registry, scopes)
    assert score.score == 1.0, score.metadata


def test_a_naive_fixture_clock_is_rejected(
    registry: ToolRegistry,
    scopes: dict[str, EngagementConfig],
) -> None:
    # The guard compares against tz-aware bounds; a naive 'now' must fail loudly
    # with a clear message instead of an opaque TypeError inside check_command.
    scope_ref = next(iter(scopes))
    case = ComplianceCase(
        id="naive-clock",
        scope_ref=scope_ref,
        command="nmap scanme.example.com",
        now="2026-06-01T12:00:00",  # no offset
        expect_allowed=True,
    )
    with pytest.raises(ValueError, match="must be timezone-aware"):
        score_compliance_case(case, registry, scopes)
