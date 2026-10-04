"""Renders the committed eval scorecard (``evals/scorecard.md``).

Pure Markdown assembly from a run's per-dimension results, the committed baseline,
the per-model matrix and the cross-model divergence verdict. Fully testable
offline and depends on no eval framework.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

from skuggi.eval.baseline import DimensionResult
from skuggi.eval.divergence import DivergenceResult


def _fmt(value: object) -> str:
    return f"{value:.3f}" if isinstance(value, (int, float)) else "-"


def render_scorecard(  # noqa: PLR0913 -- a scorecard composes several optional sections
    results: Mapping[str, DimensionResult],
    baseline: Mapping[str, dict[str, object]],
    *,
    breaches: list[str] | None = None,
    provider: str = "",
    per_model: Mapping[str, Mapping[str, DimensionResult]] | None = None,
    divergences: list[DivergenceResult] | None = None,
) -> str:
    """Compose the scorecard: per-dimension table, model matrix, divergence, verdict."""
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

    body = ["# skuggi eval scorecard", "", meta, "", *rows]
    latency = results.get("latency")
    if latency is not None and latency.metadata.get("by_node"):
        body += ["", *_latency_breakdown(latency)]
    if per_model:
        body += ["", *_matrix_table(per_model)]
    if divergences:
        body += ["", *_divergence_section(divergences, baseline, failed)]

    verdict = "**FAIL**" if breaches else "**PASS**"
    tail = [f"\n## Gate: {verdict}"]
    if breaches:
        tail += [""] + [f"- {b}" for b in breaches]
    return "\n".join([*body, *tail]) + "\n"


def _latency_breakdown(latency: DimensionResult) -> list[str]:
    """Where the latency tier's time went: per-node seconds, slowest first.

    The whole reason to run the latency dimension is to attribute a slow turn, so
    the scorecard spells out the split (summed over the tier's cases) rather than
    leaving only an aggregate pass/fail. ``calls``/``repairs`` expose the sequential
    round-trip count -- and the repair retries that silently double it.
    """
    by_node = latency.metadata.get("by_node")
    if not isinstance(by_node, dict):
        return []
    calls = latency.metadata.get("calls", 0)
    repairs = latency.metadata.get("repairs", 0)
    seconds = latency.metadata.get("seconds", 0.0)
    rows = [
        "## Latency breakdown",
        "",
        (
            f"_{_fmt(seconds)}s across the tier's cases · {calls} model call(s)"
            f" · {repairs} repair retry(ies)._"
        ),
        "",
        "| Node | Seconds |",
        "|---|---|",
    ]
    for node, secs in sorted(
        by_node.items(), key=lambda kv: float(kv[1]), reverse=True
    ):
        rows.append(f"| {node} | {float(secs):.3f} |")
    return rows


def _matrix_table(per_model: Mapping[str, Mapping[str, DimensionResult]]) -> list[str]:
    labels = sorted(per_model)
    dims = sorted({dim for model in per_model.values() for dim in model})
    header = "| Dimension | " + " | ".join(labels) + " |"
    sep = "|---|" + "---|" * len(labels)
    rows = ["## Model matrix", "", header, sep]
    for dim in dims:
        cells = [
            f"{per_model[label][dim].score:.3f}" if dim in per_model[label] else "-"
            for label in labels
        ]
        rows.append(f"| {dim} | " + " | ".join(cells) + " |")
    return rows


def _divergence_section(
    divergences: list[DivergenceResult],
    baseline: Mapping[str, dict[str, object]],
    failed: set[str],
) -> list[str]:
    rows = [
        "## Divergence",
        "",
        "| Dimension | Spread | Tolerance | Pass/fail agree | Status |",
        "|---|---|---|---|---|",
    ]
    for div in sorted(divergences, key=lambda d: d.dimension):
        tol = baseline.get(div.dimension, {}).get("divergence_tolerance", "-")
        agree = "no" if div.disagreement else "yes"
        status = "❌ fail" if div.dimension in failed else "✅ pass"
        rows.append(
            f"| {div.dimension} | {div.spread:.3f} | {_fmt(tol)} | {agree} | {status} |"
        )
    return rows
