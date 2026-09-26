"""L4 quality tier: does one real turn stay within the budget/latency ceilings?

Run with:  make eval  (or: skuggi-eval --tier quality)

Deselected by default. Token cost is captured with LangChain's usage callback and
priced via ``Settings.model_prices``; latency is wall-clock. Asserts the aggregate
clears the committed baseline threshold, never an exact cost/time (both vary).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.eval.baseline import load_baseline
from skuggi.eval.quality import run_quality
from tests.eval.conftest import require

pytestmark = [
    pytest.mark.eval,
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

_EVALS = Path(__file__).resolve().parents[2] / "evals"


@pytest.mark.parametrize("dimension", ["budget", "latency"])
def test_threshold_dimension_meets_baseline(dimension: str) -> None:
    settings = require("openai")
    results = run_quality(settings, _EVALS, dimensions=[dimension])
    result = results[dimension]
    assert 0.0 <= result.score <= 1.0
    threshold = load_baseline(_EVALS / "baseline.json")[dimension]["threshold"]
    assert isinstance(threshold, (int, float))
    assert result.score >= threshold, f"{dimension} {result.score} < {threshold}"
