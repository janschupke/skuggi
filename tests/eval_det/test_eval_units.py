"""Unit coverage for the eval building blocks: scorers, cost, baseline, report, cli."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skuggi.config import Settings
from skuggi.eval import cli, quality
from skuggi.eval.baseline import (
    BaselineError,
    DimensionResult,
    gate,
    load_baseline,
    update_baseline,
)
from skuggi.eval.cost import cost_of_usage, price_for
from skuggi.eval.goldens import GoldenError, load_cases, load_scopes
from skuggi.eval.report import render_scorecard
from skuggi.eval.scorers import (
    Score,
    budget_threshold,
    latency_threshold,
    result_compat,
)
from tests.eval_det.conftest import EVALS_ROOT, REGISTRY_PATH

# --- scorers ---------------------------------------------------------------


def test_score_as_braintrust_shape() -> None:
    bt = Score(name="x", score=0.5, metadata={"k": 1}).as_braintrust()
    assert bt == {"name": "x", "score": 0.5, "metadata": {"k": 1}}


def test_budget_threshold_grades() -> None:
    assert budget_threshold(0.01, 0.03).score == 1.0
    assert budget_threshold(0.06, 0.03).score == pytest.approx(0.5)
    assert budget_threshold(0.0, 0.0).score == 1.0
    assert budget_threshold(0.1, 0.0).score == 0.0


def test_latency_threshold_grades() -> None:
    assert latency_threshold(10.0, 45.0).score == 1.0
    assert latency_threshold(90.0, 45.0).score == pytest.approx(0.5)


def test_result_compat_empty_is_zero() -> None:
    assert result_compat(checks={}).score == 0.0
    assert result_compat(checks={"a": True, "b": False}).score == pytest.approx(0.5)


# --- cost ------------------------------------------------------------------


def test_price_for_known_and_unknown() -> None:
    settings = Settings(provider="ollama")
    assert price_for(settings, "qwen3") == (0.0, 0.0)
    assert price_for(settings, "no-such-model") == (0.0, 0.0)


def test_cost_of_usage_prices_and_flags_unknown() -> None:
    settings = Settings(provider="openai")
    usage = {
        "gpt-6-luna": {"input_tokens": 1_000_000, "output_tokens": 1_000_000},
        "mystery": {"input_tokens": 500, "output_tokens": 500},
    }
    breakdown = cost_of_usage(settings, usage)
    assert breakdown.usd == pytest.approx(0.15 + 0.60)
    assert breakdown.input_tokens == 1_000_500
    assert breakdown.unknown_models == ("mystery",)


# --- baseline gate ----------------------------------------------------------


def _res(dim: str, score: float) -> DimensionResult:
    return DimensionResult(dimension=dim, score=score, n_cases=1)


def test_gate_flags_below_threshold_and_regression() -> None:
    baseline: dict[str, dict[str, object]] = {
        "a": {"score": 1.0, "threshold": 1.0},
        "b": {"score": 0.9, "threshold": 0.5},
    }
    results = {"a": _res("a", 0.8), "b": _res("b", 0.85)}
    breaches = gate(results, baseline, tolerance=0.02)
    assert any("a:" in b and "threshold" in b for b in breaches)
    assert any("b:" in b and "regressed" in b for b in breaches)


def test_gate_skips_null_score_and_missing_entry() -> None:
    baseline: dict[str, dict[str, object]] = {"q": {"score": None, "threshold": 0.6}}
    # score above threshold, null baseline score -> no breach; unknown dim -> skipped
    results = {"q": _res("q", 0.7), "unlisted": _res("unlisted", 0.0)}
    assert gate(results, baseline) == []


def test_load_baseline_errors(tmp_path: Path) -> None:
    with pytest.raises(BaselineError):
        load_baseline(tmp_path / "nope.json")
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(bad)


def test_update_baseline_writes_scores(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    baseline: dict[str, dict[str, object]] = {"a": {"threshold": 0.9}}
    merged = update_baseline(path, {"a": _res("a", 0.95)}, baseline, provider="openai")
    assert merged["a"]["score"] == 0.95
    assert merged["a"]["provider"] == "openai"
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["a"]["score"] == 0.95


# --- goldens loader ---------------------------------------------------------


def test_load_cases_unknown_dimension() -> None:
    with pytest.raises(GoldenError):
        load_cases("nonsense", EVALS_ROOT)


def test_load_scopes_has_lab() -> None:
    assert "lab" in load_scopes(EVALS_ROOT)


# --- report -----------------------------------------------------------------


def test_render_scorecard_pass_and_fail() -> None:
    results = {"compliance": _res("compliance", 1.0)}
    baseline: dict[str, dict[str, object]] = {
        "compliance": {"score": 1.0, "threshold": 1.0}
    }
    passing = render_scorecard(results, baseline, breaches=[], provider="deterministic")
    assert "Gate: **PASS**" in passing
    assert "✅ pass" in passing
    failing = render_scorecard(
        results, baseline, breaches=["compliance: 1.000 below threshold 1.000"]
    )
    assert "Gate: **FAIL**" in failing
    assert "❌ fail" in failing


# --- cli --------------------------------------------------------------------


def _args(*extra: str) -> list[str]:
    return [
        "--tier",
        "det",
        "--root",
        str(EVALS_ROOT),
        "--registry",
        str(REGISTRY_PATH),
        "--baseline",
        str(EVALS_ROOT / "baseline.json"),
        *extra,
    ]


def test_cli_det_passes(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(_args("--check")) == 0
    out = capsys.readouterr().out
    assert "skuggi eval scorecard" in out
    assert "Gate: **PASS**" in out


def test_cli_writes_scorecard(tmp_path: Path) -> None:
    card = tmp_path / "scorecard.md"
    assert cli.main(_args("--scorecard", str(card))) == 0
    assert "skuggi eval scorecard" in card.read_text(encoding="utf-8")


def test_cli_check_fails_on_lowered_baseline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A baseline demanding more than a dimension can score must fail --check.
    tampered = tmp_path / "baseline.json"
    tampered.write_text(
        json.dumps({"compliance": {"score": 1.0, "threshold": 1.5}}), encoding="utf-8"
    )
    code = cli.main(
        [
            "--tier",
            "det",
            "--root",
            str(EVALS_ROOT),
            "--registry",
            str(REGISTRY_PATH),
            "--baseline",
            str(tampered),
            "--check",
        ]
    )
    assert code == 1
    assert "BREACH" in capsys.readouterr().err


def test_cli_update_baseline(tmp_path: Path) -> None:
    target = tmp_path / "baseline.json"
    target.write_text("{}", encoding="utf-8")
    assert cli.main(_args("--baseline", str(target), "--update-baseline")) == 0
    written = json.loads(target.read_text(encoding="utf-8"))
    assert written["compliance"]["score"] == 1.0


# --- goldens error paths ----------------------------------------------------


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_load_scopes_rejects_non_object(tmp_path: Path) -> None:
    _write(tmp_path, "scopes.json", "[]")
    with pytest.raises(GoldenError):
        load_scopes(tmp_path)


def test_load_scopes_rejects_invalid_scope(tmp_path: Path) -> None:
    _write(tmp_path, "scopes.json", '{"bad": {"name": "x"}}')
    with pytest.raises(GoldenError):
        load_scopes(tmp_path)


def test_load_cases_missing_file(tmp_path: Path) -> None:
    with pytest.raises(GoldenError):
        load_cases("compliance", tmp_path)


def test_load_cases_malformed_json(tmp_path: Path) -> None:
    _write(tmp_path, "goldens/compliance.json", "{not json")
    with pytest.raises(GoldenError):
        load_cases("compliance", tmp_path)


def test_load_cases_missing_cases_list(tmp_path: Path) -> None:
    _write(tmp_path, "goldens/methodology.json", '{"dimension": "methodology"}')
    with pytest.raises(GoldenError):
        load_cases("methodology", tmp_path)


def test_load_cases_invalid_case(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "goldens/methodology.json",
        '{"cases": [{"id": "x", "current": "recon", "expect": "not-a-phase"}]}',
    )
    with pytest.raises(GoldenError):
        load_cases("methodology", tmp_path)


# --- quality module imports (the runtime tier is provider-gated) ------------


def test_quality_module_is_importable() -> None:
    assert callable(quality.run_quality)
    assert quality._TurnSpec("i", "p", "lab", 1.0).ceiling == 1.0
