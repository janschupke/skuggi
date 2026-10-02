"""``skuggi-eval`` -- the local eval runner, gate and scorecard writer.

Runs the deterministic tier (offline, framework-free) and/or the quality tier (a
real provider, graded in-house across a configurable model matrix), compares each
dimension to ``evals/baseline.json``, treats cross-model divergence as a
regression, prints a scorecard, and -- with ``--check`` -- exits non-zero on any
breach. ``--update-baseline`` is the only way the baseline file is rewritten, so a
baseline change is always an explicit, reviewed commit.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from skuggi.common.logs import get_logger, setup_logging
from skuggi.config.config import Provider, Settings
from skuggi.eval import DETERMINISTIC, QUALITY
from skuggi.eval.baseline import (
    DEFAULT_BASELINE,
    DimensionResult,
    gate,
    load_baseline,
    update_baseline,
)
from skuggi.eval.divergence import (
    DivergenceResult,
    compute_divergence,
    divergence_breaches,
)
from skuggi.eval.models import ModelSpec
from skuggi.eval.report import render_scorecard
from skuggi.eval.runner import DEFAULT_REGISTRY, evaluate_deterministic

_TIERS: dict[str, tuple[str, ...]] = {
    "det": DETERMINISTIC,
    "quality": QUALITY,
    "all": DETERMINISTIC + QUALITY,
}
_PROVIDERS: tuple[Provider, ...] = ("openai", "chatgpt", "anthropic", "ollama")


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="skuggi-eval", description=__doc__)
    parser.add_argument("--tier", choices=sorted(_TIERS), default="det")
    parser.add_argument("--suite", choices=("fast", "full"), default="full")
    parser.add_argument(
        "--provider", action="append", choices=list(_PROVIDERS), default=[]
    )
    parser.add_argument("--model", action="append", default=[])
    parser.add_argument("--root", type=Path, default=Path("evals"))
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--scorecard", type=Path, default=None)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--update-baseline", action="store_true")
    return parser.parse_args(argv)


def _cli_specs(providers: list[Provider], models: list[str]) -> list[ModelSpec] | None:
    """Turn paired ``--provider``/``--model`` flags into a matrix override, or None."""
    if not providers and not models:
        return None
    if models and len(models) != len(providers):
        msg = "--model must be given once per --provider (1:1), or not at all"
        raise SystemExit(msg)
    specs: list[ModelSpec] = []
    for i, provider in enumerate(providers):
        model = models[i] if models else Settings(provider=provider).model_for(provider)
        specs.append(
            ModelSpec(provider=provider, model=model, label=f"{provider}:{model}")
        )
    return specs


def _worst_per_dim(
    per_model: Mapping[str, Mapping[str, DimensionResult]],
) -> dict[str, DimensionResult]:
    """Collapse the matrix to the worst score per dimension (conservative gate)."""
    worst: dict[str, DimensionResult] = {}
    for model_results in per_model.values():
        for dim, res in model_results.items():
            current = worst.get(dim)
            if current is None or res.score < current.score:
                worst[dim] = res
    return worst


def _run_quality(  # pragma: no cover -- needs a real provider; opt-in only
    args: argparse.Namespace, dims: list[str]
) -> tuple[dict[str, dict[str, DimensionResult]], list[ModelSpec], ModelSpec]:
    from skuggi.eval.models import load_matrix  # noqa: PLC0415
    from skuggi.eval.quality import run_matrix  # noqa: PLC0415

    matrix, judge = load_matrix(
        args.root, suite=args.suite, overrides=_cli_specs(args.provider, args.model)
    )
    per_model = run_matrix(matrix, judge, args.root, dimensions=dims, suite=args.suite)
    return per_model, matrix, judge


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested tier, gate against the baseline, write the scorecard."""
    setup_logging()
    get_logger(__name__).info("skuggi-eval starting")
    args = _parse_args(argv)
    dims = _TIERS[args.tier]
    det_dims = [d for d in dims if d in DETERMINISTIC]
    quality_dims = [d for d in dims if d in QUALITY]

    baseline = load_baseline(args.baseline) if args.baseline.is_file() else {}
    results: dict[str, DimensionResult] = {}
    per_model: dict[str, dict[str, DimensionResult]] | None = None
    divergences: list[DivergenceResult] | None = None
    labels: list[str] = []

    if det_dims:
        results.update(
            evaluate_deterministic(
                args.root, registry_path=args.registry, dimensions=det_dims
            )
        )
        labels.append("deterministic")
    if quality_dims:  # pragma: no cover -- needs a real provider
        per_model, matrix, _judge = _run_quality(args, quality_dims)
        results.update(_worst_per_dim(per_model))
        divergences = compute_divergence(per_model, baseline)
        labels.append(",".join(spec.label for spec in matrix))

    breaches = gate(results, baseline)
    if divergences:  # pragma: no cover -- needs a real provider
        breaches += divergence_breaches(divergences, baseline)
    scorecard = render_scorecard(
        results,
        baseline,
        breaches=breaches,
        provider=" + ".join(labels),
        per_model=per_model,
        divergences=divergences,
    )
    print(scorecard)

    if args.scorecard is not None:
        args.scorecard.write_text(scorecard, encoding="utf-8")
        print(f"scorecard written: {args.scorecard}")
    if args.update_baseline:
        update_baseline(
            args.baseline,
            results,
            baseline,
            provider=" + ".join(labels),
            per_model=per_model,
        )
        print(f"baseline updated: {args.baseline}")

    if args.check and breaches:
        for breach in breaches:
            print(f"BREACH {breach}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
