"""Each schema golden case: validity against the protocol schema must match."""

from __future__ import annotations

import pytest

from skuggi.eval.goldens import SchemaCase, load_cases
from skuggi.eval.runner import score_schema_case
from tests.eval_det.conftest import EVALS_ROOT

_CASES = [c for c in load_cases("schema", EVALS_ROOT) if isinstance(c, SchemaCase)]


@pytest.mark.parametrize("case", _CASES, ids=lambda c: c.id)
def test_schema_case(case: SchemaCase) -> None:
    score = score_schema_case(case)
    assert score.score == 1.0, score.metadata
