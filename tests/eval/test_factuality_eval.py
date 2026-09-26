"""L4 quality tier: does the agent answer lab questions factually?

Run with:  make eval  (or: skuggi-eval --tier quality)

Deselected by default and nondeterministic (a real model answers, an LLM judge
scores). Asserts properties -- every factuality case is scored, the aggregate is
a real fraction, and it clears the committed baseline threshold -- never an exact
score. The judge (``autoevals.Factuality``) uses OpenAI, so this requires an
OpenAI key regardless of the agent provider under test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.eval.baseline import load_baseline
from skuggi.eval.goldens import load_cases
from skuggi.eval.quality import run_quality
from tests.eval.conftest import require

pytestmark = [
    pytest.mark.eval,
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

_EVALS = Path(__file__).resolve().parents[2] / "evals"


def test_factuality_meets_baseline() -> None:
    settings = require("openai")
    results = run_quality(settings, _EVALS, dimensions=["factuality"])
    result = results["factuality"]
    assert result.n_cases == len(load_cases("factuality", _EVALS))
    assert 0.0 <= result.score <= 1.0
    threshold = load_baseline(_EVALS / "baseline.json")["factuality"]["threshold"]
    assert isinstance(threshold, (int, float))
    assert result.score >= threshold, f"factuality {result.score} < {threshold}"
