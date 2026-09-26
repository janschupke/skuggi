"""Each methodology golden case: clamp_phase must land on the expected phase."""

from __future__ import annotations

import pytest

from skuggi.eval.goldens import MethodologyCase, load_cases
from skuggi.eval.runner import score_methodology_case
from tests.eval_det.conftest import EVALS_ROOT

_CASES = [
    c for c in load_cases("methodology", EVALS_ROOT) if isinstance(c, MethodologyCase)
]


@pytest.mark.parametrize("case", _CASES, ids=lambda c: c.id)
def test_methodology_case(case: MethodologyCase) -> None:
    score = score_methodology_case(case)
    assert score.score == 1.0, score.metadata
