"""Each compliance golden case: the guard verdict must match its label."""

from __future__ import annotations

import pytest

from skuggi.engagement import EngagementConfig
from skuggi.eval.goldens import ComplianceCase, load_cases
from skuggi.eval.runner import score_compliance_case
from skuggi.registry import ToolRegistry
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
