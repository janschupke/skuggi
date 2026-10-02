"""Unit coverage for the matrix layer: models config, divergence, judge, scorecard."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skuggi.config.config import Settings
from skuggi.config.configs import ConfigError
from skuggi.eval import cli
from skuggi.eval.baseline import DimensionResult, update_baseline
from skuggi.eval.divergence import (
    DivergenceResult,
    compute_divergence,
    divergence_breaches,
)
from skuggi.eval.judge import LLMJudge
from skuggi.eval.models import (
    ModelsError,
    ModelSpec,
    eval_settings,
    load_matrix,
    load_prices,
)
from skuggi.eval.report import render_scorecard


def _res(dim: str, score: float) -> DimensionResult:
    return DimensionResult(dimension=dim, score=score, n_cases=1)


# --- divergence -------------------------------------------------------------


def test_compute_divergence_spread_and_disagreement() -> None:
    per_model = {
        "a": {"factuality": _res("factuality", 0.9)},
        "b": {"factuality": _res("factuality", 0.5)},
    }
    baseline: dict[str, dict[str, object]] = {"factuality": {"threshold": 0.6}}
    divs = compute_divergence(per_model, baseline)
    assert len(divs) == 1
    assert divs[0].spread == pytest.approx(0.4)
    assert divs[0].disagreement is True  # 0.9 passes, 0.5 fails


def test_compute_divergence_skips_single_model() -> None:
    per_model = {"a": {"budget": _res("budget", 1.0)}}
    assert compute_divergence(per_model, {}) == []


def test_compute_divergence_agrees_without_threshold() -> None:
    per_model = {
        "a": {"latency": _res("latency", 0.9)},
        "b": {"latency": _res("latency", 0.85)},
    }
    divs = compute_divergence(per_model, {})  # no threshold -> no disagreement
    assert divs[0].disagreement is False


def test_divergence_breaches_spread_and_disagreement() -> None:
    divs = [
        DivergenceResult(
            "factuality", spread=0.4, disagreement=True, per_model={"a": 0.9, "b": 0.5}
        ),
        DivergenceResult(
            "budget", spread=0.05, disagreement=False, per_model={"a": 1.0, "b": 0.95}
        ),
    ]
    baseline: dict[str, dict[str, object]] = {
        "factuality": {"divergence_tolerance": 0.25}
    }
    breaches = divergence_breaches(divs, baseline)
    assert any("spread" in b and "factuality" in b for b in breaches)
    assert any("disagree" in b for b in breaches)
    assert not any("budget" in b for b in breaches)  # within default tolerance


def test_divergence_breaches_uses_default_tolerance() -> None:
    divs = [
        DivergenceResult(
            "x", spread=0.2, disagreement=False, per_model={"a": 0.5, "b": 0.7}
        )
    ]
    assert divergence_breaches(divs, {}, default_tolerance=0.1)
    assert not divergence_breaches(divs, {}, default_tolerance=0.3)


# --- models config ----------------------------------------------------------


def _write_models(root: Path, body: dict[str, object]) -> None:
    (root / "models.json").write_text(json.dumps(body), encoding="utf-8")


def test_load_matrix_full_and_fast(tmp_path: Path) -> None:
    _write_models(
        tmp_path,
        {
            "judge": {"provider": "openai", "model": "j"},
            "matrix": [
                {"provider": "anthropic", "model": "a"},
                {"provider": "openai", "model": "o"},
            ],
            "fast": {"matrix": [{"provider": "ollama", "model": "q"}]},
        },
    )
    full, judge = load_matrix(tmp_path, suite="full")
    assert [s.label for s in full] == ["anthropic:a", "openai:o"]
    assert judge.provider == "openai"
    fast, fast_judge = load_matrix(tmp_path, suite="fast")
    assert [s.provider for s in fast] == ["ollama"]
    assert fast_judge.provider == "openai"  # inherited from top level


def test_load_matrix_overrides(tmp_path: Path) -> None:
    _write_models(
        tmp_path,
        {
            "judge": {"provider": "openai", "model": "j"},
            "matrix": [{"provider": "openai", "model": "o"}],
        },
    )
    override = [ModelSpec(provider="ollama", model="q", label="ollama:q")]
    matrix, _ = load_matrix(tmp_path, overrides=override)
    assert matrix == override


def test_load_matrix_errors(tmp_path: Path) -> None:
    _write_models(
        tmp_path, {"judge": {"provider": "openai", "model": "j"}, "matrix": []}
    )
    with pytest.raises(ModelsError):
        load_matrix(tmp_path)
    _write_models(tmp_path, {"matrix": [{"provider": "openai", "model": "o"}]})
    with pytest.raises(ModelsError):
        load_matrix(tmp_path)
    _write_models(
        tmp_path,
        {
            "judge": {"provider": "openai", "model": "j"},
            "matrix": [{"provider": "bogus", "model": "x"}],
        },
    )
    with pytest.raises(ModelsError):
        load_matrix(tmp_path)


def test_load_prices(tmp_path: Path) -> None:
    (tmp_path / "prices.json").write_text(
        json.dumps({"prices": {"m": [1.0, 2.0]}}), encoding="utf-8"
    )
    assert load_prices(tmp_path) == {"m": (1.0, 2.0)}
    (tmp_path / "prices.json").write_text(
        json.dumps({"prices": {"m": [1.0]}}), encoding="utf-8"
    )
    with pytest.raises(ModelsError):
        load_prices(tmp_path)
    (tmp_path / "prices.json").write_text(json.dumps({"nope": {}}), encoding="utf-8")
    with pytest.raises(ModelsError):
        load_prices(tmp_path)


def test_load_prices_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ModelsError):
        load_prices(tmp_path)


def test_eval_settings_pins_model_and_prices() -> None:
    spec = ModelSpec(provider="anthropic", model="pinned-model", label="x")
    prices = {"pinned-model": (3.0, 4.0)}
    settings = eval_settings(spec, prices)
    assert settings.provider == "anthropic"
    assert settings.model_for("anthropic") == "pinned-model"
    assert settings.model_prices == prices


def test_model_spec_default_label(tmp_path: Path) -> None:
    _write_models(
        tmp_path,
        {
            "judge": {"provider": "openai", "model": "j"},
            "matrix": [{"provider": "ollama", "model": "q"}],
        },
    )
    matrix, _ = load_matrix(tmp_path)
    assert matrix[0].label == "ollama:q"


# --- judge guard + empty-answer short circuit (no network) ------------------


def test_llm_judge_rejects_chatgpt() -> None:
    with pytest.raises(ConfigError):
        LLMJudge(Settings(provider="chatgpt"))


def test_llm_judge_empty_answer_is_zero() -> None:
    judge = LLMJudge(Settings(provider="ollama"))  # constructs offline, no network
    score = judge.score(prompt="q", expected="e", actual="   ")
    assert score.score == 0.0
    assert score.metadata["judge_model"] == judge.model_name


# --- update_baseline per-model + scorecard matrix/divergence ----------------


def test_update_baseline_writes_per_model(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    per_model = {
        "a": {"factuality": _res("factuality", 0.9)},
        "b": {"factuality": _res("factuality", 0.6)},
    }
    merged = update_baseline(
        path, {"factuality": _res("factuality", 0.6)}, {}, per_model=per_model
    )
    assert merged["factuality"]["models"] == {"a": 0.9, "b": 0.6}


def test_render_scorecard_shows_matrix_and_divergence() -> None:
    results = {"factuality": _res("factuality", 0.6)}
    baseline: dict[str, dict[str, object]] = {
        "factuality": {"score": None, "threshold": 0.6, "divergence_tolerance": 0.25}
    }
    per_model = {
        "anthropic:haiku": {"factuality": _res("factuality", 0.9)},
        "openai:luna": {"factuality": _res("factuality", 0.6)},
    }
    divs = compute_divergence(per_model, baseline)
    card = render_scorecard(
        results,
        baseline,
        breaches=[],
        provider="x",
        per_model=per_model,
        divergences=divs,
    )
    assert "## Model matrix" in card
    assert "anthropic:haiku" in card
    assert "## Divergence" in card


# --- cli helpers (provider-free) --------------------------------------------


def test_cli_specs_none_when_no_flags() -> None:
    assert cli._cli_specs([], []) is None


def test_cli_specs_pairs_provider_and_model() -> None:
    specs = cli._cli_specs(["anthropic", "openai"], ["m1", "m2"])
    assert specs is not None
    assert [(s.provider, s.model, s.label) for s in specs] == [
        ("anthropic", "m1", "anthropic:m1"),
        ("openai", "m2", "openai:m2"),
    ]


def test_cli_specs_defaults_model_from_settings() -> None:
    specs = cli._cli_specs(["ollama"], [])
    assert specs is not None
    assert specs[0].model == Settings(provider="ollama").model_for("ollama")


def test_cli_specs_rejects_mismatched_counts() -> None:
    with pytest.raises(SystemExit):
        cli._cli_specs(["openai", "anthropic"], ["only-one"])


def test_worst_per_dim_picks_minimum() -> None:
    per_model = {
        "a": {"factuality": _res("factuality", 0.9), "budget": _res("budget", 1.0)},
        "b": {"factuality": _res("factuality", 0.5), "budget": _res("budget", 1.0)},
    }
    worst = cli._worst_per_dim(per_model)
    assert worst["factuality"].score == 0.5
    assert worst["budget"].score == 1.0
