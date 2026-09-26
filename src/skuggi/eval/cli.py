"""``skuggi-eval`` -- the local eval runner, gate and scorecard writer.

Runs the deterministic tier (offline, no Braintrust) and/or the quality tier (a
real provider through a local Braintrust ``Eval``), compares each dimension to
``evals/baseline.json``, prints a scorecard, and -- with ``--check`` -- exits
non-zero on any regression. ``--update-baseline`` is the only way the baseline
file is rewritten, so a baseline change is always an explicit, reviewed commit.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from skuggi.config import Provider, Settings
from skuggi.eval import DETERMINISTIC, QUALITY
from skuggi.eval.baseline import (
    DEFAULT_BASELINE,
    DimensionResult,
    gate,
    load_baseline,
    update_baseline,
)
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
    parser.add_argument(
        "--provider", action="append", choices=list(_PROVIDERS), default=[]
    )
    parser.add_argument("--root", type=Path, default=Path("evals"))
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--scorecard", type=Path, default=None)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--update-baseline", action="store_true")
    return parser.parse_args(argv)


def _run_quality_dims(  # pragma: no cover -- needs a real provider; opt-in only
    providers: list[str], root: Path, dims: list[str]
) -> tuple[dict[str, DimensionResult], str]:
    from skuggi.eval.quality import run_quality  # noqa: PLC0415

    chosen = providers or ["openai"]
    merged: dict[str, DimensionResult] = {}
    for name in chosen:
        settings = Settings(provider=name)  # type: ignore[arg-type]
        for dim, res in run_quality(settings, root, dimensions=dims).items():
            prior = merged.get(dim)
            if prior is None or res.score < prior.score:
                merged[dim] = res  # conservative: keep the worst provider's score
    return merged, ",".join(chosen)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested tier, gate against the baseline, write the scorecard."""
    args = _parse_args(argv)
    dims = _TIERS[args.tier]
    det_dims = [d for d in dims if d in DETERMINISTIC]
    quality_dims = [d for d in dims if d in QUALITY]

    baseline = load_baseline(args.baseline) if args.baseline.is_file() else {}
    results: dict[str, DimensionResult] = {}
    labels: list[str] = []

    if det_dims:
        results.update(
            evaluate_deterministic(
                args.root, registry_path=args.registry, dimensions=det_dims
            )
        )
        labels.append("deterministic")
    if quality_dims:  # pragma: no cover -- needs a real provider
        quality_results, provider_label = _run_quality_dims(
            args.provider, args.root, quality_dims
        )
        results.update(quality_results)
        labels.append(provider_label)

    breaches = gate(results, baseline)
    scorecard = render_scorecard(
        results, baseline, breaches=breaches, provider=" + ".join(labels)
    )
    print(scorecard)

    if args.scorecard is not None:
        args.scorecard.write_text(scorecard, encoding="utf-8")
        print(f"scorecard written: {args.scorecard}")
    if args.update_baseline:
        update_baseline(args.baseline, results, baseline, provider=" + ".join(labels))
        print(f"baseline updated: {args.baseline}")

    if args.check and breaches:
        for breach in breaches:
            print(f"BREACH {breach}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
