"""Renders the committed eval scorecard (``evals/scorecard.md``).

Pure Markdown assembly from a run's per-dimension results and the committed
baseline, so it is fully testable offline and never imports Braintrust.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

from skuggi.eval.baseline import DimensionResult


def _fmt(value: object) -> str:
    return f"{value:.3f}" if isinstance(value, (int, float)) else "-"


def render_scorecard(
    results: Mapping[str, DimensionResult],
    baseline: Mapping[str, dict[str, object]],
    *,
    breaches: list[str] | None = None,
    provider: str = "",
) -> str:
    """Compose the scorecard: a per-dimension table plus the gate verdict."""
    breaches = breaches or []
    failed = {b.split(":", 1)[0] for b in breaches}
    generated = datetime.now(UTC).isoformat(timespec="seconds")
    meta = f"_Generated {generated}"
    if provider:
        meta += f" · provider: {provider}"
    meta += "._"

    rows = [
        "| Dimension | Score | Cases | Baseline | Threshold | Status |",
        "|---|---|---|---|---|---|",
    ]
    for dim in sorted(results):
        res = results[dim]
        entry = baseline.get(dim, {})
        status = "❌ fail" if dim in failed else "✅ pass"
        rows.append(
            f"| {dim} | {res.score:.3f} | {res.n_cases} | "
            f"{_fmt(entry.get('score'))} | {_fmt(entry.get('threshold'))} | {status} |"
        )

    verdict = "**FAIL**" if breaches else "**PASS**"
    tail = [f"\n## Gate: {verdict}"]
    if breaches:
        tail += [""] + [f"- {b}" for b in breaches]
    return "\n".join(["# skuggi eval scorecard", "", meta, "", *rows, *tail]) + "\n"
