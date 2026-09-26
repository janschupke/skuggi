"""The hard gate: the deterministic run must not regress below the committed baseline.

Runs every deterministic dimension over the committed corpora and asserts the
baseline gate reports no breach. A guard/phase/schema/ledger regression, or a
lowered committed threshold that the code no longer meets, fails here -- which is
what makes this the CI gate for the eval system.
"""

from __future__ import annotations

from skuggi.eval.baseline import gate, load_baseline
from skuggi.eval.runner import evaluate_deterministic
from tests.eval_det.conftest import EVALS_ROOT, REGISTRY_PATH


def test_deterministic_run_meets_baseline() -> None:
    results = evaluate_deterministic(EVALS_ROOT, registry_path=REGISTRY_PATH)
    baseline = load_baseline(EVALS_ROOT / "baseline.json")
    breaches = gate(results, baseline)
    assert breaches == [], breaches


def test_every_deterministic_dimension_is_scored() -> None:
    results = evaluate_deterministic(EVALS_ROOT, registry_path=REGISTRY_PATH)
    assert set(results) == {"compliance", "methodology", "schema", "result_compat"}
    assert all(r.n_cases > 0 for r in results.values())
