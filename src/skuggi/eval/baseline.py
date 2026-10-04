"""The committed baseline and the threshold/regression gate.

``evals/baseline.json`` maps each dimension to ``{"score", "threshold",
"provider"}``. The gate fails a run when a dimension drops below its absolute
``threshold`` (a floor) or regresses more than ``tolerance`` below the committed
``score``. A dimension absent from the baseline, or whose entry has a null score,
is gated on its threshold alone -- which is how a not-yet-measured quality
dimension participates before its first real run. Only ``skuggi-eval
--update-baseline`` writes this file, so a baseline change is always an explicit,
reviewed commit rather than a side effect of a run.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_BASELINE = Path("evals/baseline.json")
DEFAULT_TOLERANCE = 0.02
_EPS = 1e-9


@dataclass(frozen=True, slots=True)
class DimensionResult:
    """One dimension's aggregate for a run: its mean case score over ``n_cases``.

    ``metadata`` is optional per-dimension diagnostics that survive aggregation --
    for the latency dimension it carries the summed per-node time split, call and
    repair counts, so the scorecard can report where the time went. Empty for
    dimensions that attach none.
    """

    dimension: str
    score: float
    n_cases: int
    metadata: dict[str, object] = field(default_factory=dict)


class BaselineError(RuntimeError):
    """The baseline file is missing or malformed."""


def load_baseline(path: Path = DEFAULT_BASELINE) -> dict[str, dict[str, object]]:
    """Load ``baseline.json`` as a dimension -> entry mapping."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        msg = f"cannot read baseline at {path}: {exc}"
        raise BaselineError(msg) from exc
    except json.JSONDecodeError as exc:
        msg = f"malformed baseline JSON at {path}: {exc}"
        raise BaselineError(msg) from exc
    if not isinstance(data, dict):
        msg = "baseline.json must be an object of dimension -> entry"
        raise BaselineError(msg)
    return data


def _as_float(value: object) -> float | None:
    return float(value) if isinstance(value, (int, float)) else None


def gate(
    results: Mapping[str, DimensionResult],
    baseline: Mapping[str, dict[str, object]],
    *,
    tolerance: float = DEFAULT_TOLERANCE,
) -> list[str]:
    """Return one human-readable breach string per dimension that failed the gate.

    An empty list means the run passes. A dimension with no baseline entry is not
    gated (there is nothing to compare against yet).
    """
    breaches: list[str] = []
    for dim, res in results.items():
        entry = baseline.get(dim)
        if entry is None:
            continue
        threshold = _as_float(entry.get("threshold"))
        if threshold is not None and res.score < threshold - _EPS:
            breaches.append(f"{dim}: {res.score:.3f} below threshold {threshold:.3f}")
            continue
        base = _as_float(entry.get("score"))
        if base is not None and res.score < base - tolerance - _EPS:
            breaches.append(
                f"{dim}: regressed {base:.3f} -> {res.score:.3f} "
                f"(tolerance {tolerance:.3f})"
            )
    return breaches


def update_baseline(
    path: Path,
    results: Mapping[str, DimensionResult],
    baseline: Mapping[str, dict[str, object]],
    *,
    provider: str = "",
    per_model: Mapping[str, Mapping[str, DimensionResult]] | None = None,
) -> dict[str, dict[str, object]]:
    """Return a new baseline mapping with each result's score written in.

    Thresholds and any ``divergence_tolerance`` are preserved from the existing
    entry (threshold defaults to the measured score, rounded down a little, for a
    first-time dimension). When ``per_model`` is given, each dimension records the
    per-model scores that produced the matrix run. Never called implicitly -- only
    ``skuggi-eval --update-baseline`` writes the file.
    """
    merged: dict[str, dict[str, object]] = {k: dict(v) for k, v in baseline.items()}
    for dim, res in results.items():
        entry = merged.setdefault(dim, {})
        entry["score"] = round(res.score, 4)
        entry.setdefault("threshold", round(max(0.0, res.score - 0.05), 4))
        if provider:
            entry["provider"] = provider
    if per_model:
        by_dim: dict[str, dict[str, float]] = {}
        for label, model_results in per_model.items():
            for dim, res in model_results.items():
                by_dim.setdefault(dim, {})[label] = round(res.score, 4)
        for dim, scores in by_dim.items():
            merged.setdefault(dim, {})["models"] = dict(sorted(scores.items()))
    path.write_text(
        json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return merged
