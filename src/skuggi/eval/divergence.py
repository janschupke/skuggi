"""Cross-model divergence: treat models disagreeing as a regression.

The quality tier runs the same cases against a matrix of models. Two models that
each clear their threshold can still disagree -- one scores 0.95, another 0.62 --
which is a quality signal the per-model gate misses. This module turns a
per-model result map into one :class:`DivergenceResult` per dimension and flags a
breach when the spread exceeds a tolerance OR the models disagree on pass/fail.

Pure and provider-free: it takes already-computed scores, so it is unit-tested
offline with fake numbers, no model required.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from skuggi.eval.baseline import DimensionResult

DEFAULT_DIVERGENCE_TOLERANCE = 0.15
_MIN_MODELS = 2  # divergence needs at least two models to compare
_EPS = 1e-9


@dataclass(frozen=True, slots=True)
class DivergenceResult:
    """One dimension's cross-model agreement: the score spread and pass/fail split."""

    dimension: str
    spread: float
    disagreement: bool
    per_model: dict[str, float] = field(default_factory=dict)


def _as_float(value: object) -> float | None:
    return float(value) if isinstance(value, (int, float)) else None


def compute_divergence(
    per_model: Mapping[str, Mapping[str, DimensionResult]],
    baseline: Mapping[str, dict[str, object]],
) -> list[DivergenceResult]:
    """One :class:`DivergenceResult` per dimension scored by at least two models.

    ``disagreement`` is set when the models fall on different sides of the
    dimension's baseline ``threshold`` (some pass, some fail). A dimension scored
    by fewer than two models has nothing to diverge and is skipped.
    """
    dims = sorted({dim for model in per_model.values() for dim in model})
    results: list[DivergenceResult] = []
    for dim in dims:
        scores = {
            label: model[dim].score
            for label, model in per_model.items()
            if dim in model
        }
        if len(scores) < _MIN_MODELS:
            continue
        spread = max(scores.values()) - min(scores.values())
        threshold = _as_float(baseline.get(dim, {}).get("threshold"))
        disagreement = False
        if threshold is not None:
            verdicts = {score >= threshold - _EPS for score in scores.values()}
            disagreement = len(verdicts) > 1
        results.append(
            DivergenceResult(
                dimension=dim,
                spread=spread,
                disagreement=disagreement,
                per_model=scores,
            )
        )
    return results


def divergence_breaches(
    divergences: list[DivergenceResult],
    baseline: Mapping[str, dict[str, object]],
    *,
    default_tolerance: float = DEFAULT_DIVERGENCE_TOLERANCE,
) -> list[str]:
    """One human-readable breach string per dimension whose models diverge too far.

    A dimension breaches when its score spread exceeds its ``divergence_tolerance``
    (per-dimension in the baseline, else ``default_tolerance``) or when the models
    disagree on pass/fail. An empty list means the matrix agrees closely enough.
    """
    breaches: list[str] = []
    for div in divergences:
        tolerance = (
            _as_float(baseline.get(div.dimension, {}).get("divergence_tolerance"))
            or default_tolerance
        )
        if div.spread > tolerance + _EPS:
            breaches.append(
                f"{div.dimension}: model score spread {div.spread:.3f} exceeds "
                f"divergence tolerance {tolerance:.3f} ({_fmt_models(div.per_model)})"
            )
        if div.disagreement:
            breaches.append(
                f"{div.dimension}: models disagree on pass/fail "
                f"({_fmt_models(div.per_model)})"
            )
    return breaches


def _fmt_models(per_model: Mapping[str, float]) -> str:
    return ", ".join(
        f"{label}={score:.3f}" for label, score in sorted(per_model.items())
    )
