"""The quality tier: live agent turns scored in-house across a model matrix.

Everything here needs a live model (and, for factuality, an :class:`LLMJudge`),
so it is opt-in (``skuggi-eval`` / ``make bench``) and excluded from coverage --
it cannot run on a credential-free CI machine. It is still linted and type-checked.

There is no eval framework: each dimension is a plain loop that produces the same
pure :class:`~skuggi.eval.scorers.Score` the deterministic tier uses, aggregated
with :func:`~skuggi.eval.runner.aggregate`. ``run_quality`` grades one model;
``run_matrix`` runs the whole configured matrix so :mod:`skuggi.eval.divergence`
can compare them. Nothing is uploaded and no third-party judge service is called.
"""

from __future__ import annotations

import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from skuggi.agent.core import AgentCore
from skuggi.agent.turn_runner import TurnLatency
from skuggi.common.paths import ensure_dir
from skuggi.config.config import Settings
from skuggi.engagement.engagement import EngagementConfig
from skuggi.eval.baseline import DimensionResult
from skuggi.eval.cost import cost_of_usage
from skuggi.eval.goldens import (
    BudgetCase,
    FactualityCase,
    LatencyCase,
    load_cases,
    load_scopes,
)
from skuggi.eval.judge import Judge, LLMJudge
from skuggi.eval.models import ModelSpec, eval_settings, load_prices
from skuggi.eval.runner import aggregate
from skuggi.eval.scorers import Score, budget_threshold, latency_threshold


def build_live_core(  # pragma: no cover
    settings: Settings, scope: EngagementConfig, tmp: Path
) -> AgentCore:
    """An ``AgentCore`` on the real provider for ``scope``, state under ``tmp``."""
    workspace = tmp / "engagement"
    ensure_dir(workspace)
    (workspace / "scope.json").write_text(scope.model_dump_json(), encoding="utf-8")
    live = settings.model_copy(
        update={
            "engagement_root": workspace,
            "sqlite_path": tmp / "sessions.db",
            "faiss_path": tmp / "faiss",
            "preferences_path": tmp / "preferences.db",
        }
    )
    return AgentCore(live)


def _answer(  # pragma: no cover
    settings: Settings, scope: EngagementConfig, prompt: str
) -> str:
    core = build_live_core(settings, scope, Path(tempfile.mkdtemp()))
    try:
        finals = [e.text for e in core.turn(prompt) if e.kind == "final"]
        return finals[-1] if finals else ""
    finally:
        core.close()


def _cost_latency(  # pragma: no cover
    settings: Settings, scope: EngagementConfig, prompt: str
) -> tuple[float, TurnLatency | None]:
    # Imported lazily: langchain_core.callbacks pulls the tracer context (and
    # langsmith), which warns under Python 3.14 -- keep the module top clean so
    # the default suite can import this file at collection without erroring.
    from langchain_core.callbacks import get_usage_metadata_callback  # noqa: PLC0415

    core = build_live_core(settings, scope, Path(tempfile.mkdtemp()))
    try:
        with get_usage_metadata_callback() as cb:
            list(core.turn(prompt))
        usage = cast("Mapping[str, Mapping[str, int]]", cb.usage_metadata)
        # The turn runner already timed every model call and summarised the turn
        # (total wall-clock + per-node split + call/repair counts); reuse that one
        # measurement rather than wrapping a second, coarser stopwatch out here.
        return cost_of_usage(settings, usage).usd, core.turn_runner.last_latency
    finally:
        core.close()


def _run_factuality(  # pragma: no cover
    settings: Settings,
    scopes: dict[str, EngagementConfig],
    root: Path,
    judge: Judge,
    *,
    suite: str,
) -> DimensionResult:
    cases = [
        c
        for c in load_cases("factuality", root)
        if isinstance(c, FactualityCase) and suite in c.suites
    ]
    scores: list[Score] = []
    for case in cases:
        actual = _answer(settings, scopes[case.scope_ref], case.prompt)
        scores.append(
            judge.score(prompt=case.prompt, expected=case.expected, actual=actual)
        )
    return aggregate("factuality", scores)


def _run_budget(  # pragma: no cover
    settings: Settings, scopes: dict[str, EngagementConfig], root: Path, *, suite: str
) -> DimensionResult:
    cases = [
        c
        for c in load_cases("budget", root)
        if isinstance(c, BudgetCase) and suite in c.suites
    ]
    scores = [
        budget_threshold(
            _cost_latency(settings, scopes[c.scope_ref], c.prompt)[0], c.max_cost_usd
        )
        for c in cases
    ]
    return aggregate("budget", scores)


def _score_latency(  # pragma: no cover
    latency: TurnLatency | None, ceiling_s: float
) -> Score:
    """Score one latency case, carrying the per-node attribution into metadata.

    The score is the turn's total wall-clock against the ceiling; the ``by_node``
    split, call count and repair count ride alongside so the scorecard can report
    *which* model call dominated -- the diagnosis the latency tier exists for.
    """
    if latency is None:  # a turn that errored before timing closed (defensive)
        return latency_threshold(0.0, ceiling_s)
    return latency_threshold(
        latency.total_s,
        ceiling_s,
        by_node=latency.by_node,
        calls=latency.calls,
        repairs=latency.repairs,
    )


def _run_latency(  # pragma: no cover
    settings: Settings, scopes: dict[str, EngagementConfig], root: Path, *, suite: str
) -> DimensionResult:
    cases = [
        c
        for c in load_cases("latency", root)
        if isinstance(c, LatencyCase) and suite in c.suites
    ]
    scores = [
        _score_latency(
            _cost_latency(settings, scopes[c.scope_ref], c.prompt)[1], c.max_latency_s
        )
        for c in cases
    ]
    return aggregate("latency", scores)


def run_quality(  # pragma: no cover
    settings: Settings,
    root: Path,
    *,
    dimensions: Sequence[str],
    suite: str = "full",
    judge: Judge | None = None,
) -> dict[str, DimensionResult]:
    """Grade the requested quality dimensions for one model (``settings``).

    ``judge`` grades factuality; when omitted a :class:`LLMJudge` on the same
    provider is built (only if factuality is requested, so budget/latency-only
    runs need no judge-capable provider). ``suite`` filters cases by membership.
    """
    scopes = load_scopes(root)
    results: dict[str, DimensionResult] = {}
    if "factuality" in dimensions:
        active_judge = judge or LLMJudge(settings)
        results["factuality"] = _run_factuality(
            settings, scopes, root, active_judge, suite=suite
        )
    if "budget" in dimensions:
        results["budget"] = _run_budget(settings, scopes, root, suite=suite)
    if "latency" in dimensions:
        results["latency"] = _run_latency(settings, scopes, root, suite=suite)
    return results


def run_matrix(  # pragma: no cover
    matrix: Sequence[ModelSpec],
    judge_spec: ModelSpec,
    root: Path,
    *,
    dimensions: Sequence[str],
    suite: str = "full",
) -> dict[str, dict[str, DimensionResult]]:
    """Grade ``dimensions`` for every model in ``matrix``; return per-model results.

    One shared :class:`LLMJudge` (built from ``judge_spec``) grades factuality for
    every model, so the comparison is fair. Prices come from ``evals/prices.json``
    so the budget dimension is correct for whatever models the matrix pins.
    """
    prices = load_prices(root)
    judge = LLMJudge(eval_settings(judge_spec, prices))
    per_model: dict[str, dict[str, DimensionResult]] = {}
    for spec in matrix:
        settings = eval_settings(spec, prices)
        per_model[spec.label] = run_quality(
            settings, root, dimensions=dimensions, suite=suite, judge=judge
        )
    return per_model
