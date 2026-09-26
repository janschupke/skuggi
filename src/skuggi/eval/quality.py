"""The quality tier: the Braintrust benchmark over a real provider.

Everything here needs a live model (and, for factuality, an ``autoevals`` judge),
so it is opt-in (``skuggi-eval`` / ``make bench``) and excluded from coverage --
it cannot run on a credential-free CI machine. It is still linted and type-checked.

Every ``Eval`` is local: ``no_send_logs=True`` on every call, no experiment is
uploaded, and no ``BRAINTRUST_API_KEY`` is read. ``braintrust`` is imported here
(not in :mod:`skuggi.eval.runner`) so the deterministic path never imports it.
"""

from __future__ import annotations

import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from skuggi.config import Settings
from skuggi.core import AgentCore
from skuggi.engagement import EngagementConfig
from skuggi.eval.baseline import DimensionResult
from skuggi.eval.cost import cost_of_usage
from skuggi.eval.goldens import (
    BudgetCase,
    FactualityCase,
    LatencyCase,
    load_cases,
    load_scopes,
)
from skuggi.eval.scorers import budget_threshold, latency_threshold


@dataclass(frozen=True, slots=True)
class _TurnSpec:  # pragma: no cover
    """One quality-tier turn: its id, prompt, scope and threshold ceiling."""

    id: str
    prompt: str
    scope_ref: str
    ceiling: float


def _local_eval(  # pragma: no cover
    name: str, *, data: Any, task: Any, scores: list[Any]
) -> Any:
    """Run one local Braintrust eval (never uploads); return its result object.

    The one place ``braintrust`` is imported and the one place its strict eval
    generics are absorbed -- our plain dict data and scorer callables are valid
    at runtime but do not satisfy the published overloads.
    """
    from braintrust import Eval  # noqa: PLC0415

    return Eval(name, data=data, task=task, scores=scores, no_send_logs=True)


def build_live_core(  # pragma: no cover
    settings: Settings, scope: EngagementConfig, tmp: Path
) -> AgentCore:
    """An ``AgentCore`` on the real provider for ``scope``, state under ``tmp``."""
    workspace = tmp / "engagements" / scope.name
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "scope.json").write_text(scope.model_dump_json(), encoding="utf-8")
    live = settings.model_copy(
        update={
            "engagements_dir": tmp / "engagements",
            "engagement": scope.name,
            "sqlite_path": tmp / "sessions.db",
            "faiss_path": tmp / "faiss",
            "history_path": tmp / ".repl_history",
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
) -> tuple[float, float]:
    # Imported lazily: langchain_core.callbacks pulls the tracer context (and
    # langsmith), which warns under Python 3.14 -- keep the module top clean so
    # the default suite can import this file at collection without erroring.
    from langchain_core.callbacks import get_usage_metadata_callback  # noqa: PLC0415

    core = build_live_core(settings, scope, Path(tempfile.mkdtemp()))
    try:
        with get_usage_metadata_callback() as cb:
            start = time.perf_counter()
            list(core.turn(prompt))
            elapsed = time.perf_counter() - start
        usage = cast("Mapping[str, Mapping[str, int]]", cb.usage_metadata)
        return cost_of_usage(settings, usage).usd, elapsed
    finally:
        core.close()


def _summary_result(  # pragma: no cover
    dim: str, res: Any, n_cases: int
) -> DimensionResult:
    """Pull the single mean score out of a Braintrust eval summary."""
    scores = getattr(getattr(res, "summary", None), "scores", {}) or {}
    mean = next((s.score for s in scores.values()), 0.0)
    return DimensionResult(dimension=dim, score=float(mean or 0.0), n_cases=n_cases)


def _run_factuality(  # pragma: no cover
    settings: Settings, scopes: dict[str, EngagementConfig], root: Path
) -> DimensionResult:
    from autoevals import Factuality  # noqa: PLC0415

    cases = [cast("FactualityCase", c) for c in load_cases("factuality", root)]
    by_prompt = {c.prompt: c for c in cases}

    def task(prompt: str) -> str:
        return _answer(settings, scopes[by_prompt[prompt].scope_ref], prompt)

    res = _local_eval(
        "skuggi-factuality",
        data=[
            {"input": c.prompt, "expected": c.expected, "metadata": {"id": c.id}}
            for c in cases
        ],
        task=task,
        scores=[Factuality()],
    )
    return _summary_result("factuality", res, len(cases))


def _run_threshold(  # noqa: PLR0913 -- one threshold runner, parameterised per dimension  # pragma: no cover
    settings: Settings,
    scopes: dict[str, EngagementConfig],
    *,
    dim: str,
    specs: list[_TurnSpec],
    measure: Callable[[Settings, EngagementConfig, str], float],
    score_of: Callable[[float, float], dict[str, object]],
) -> DimensionResult:
    by_prompt = {spec.prompt: spec for spec in specs}

    def task(prompt: str) -> float:
        return measure(settings, scopes[by_prompt[prompt].scope_ref], prompt)

    def score(
        output: float, metadata: dict[str, object], **_: object
    ) -> dict[str, object]:
        return score_of(output, float(cast("float", metadata["ceiling"])))

    res = _local_eval(
        f"skuggi-{dim}",
        data=[
            {
                "input": spec.prompt,
                "expected": None,
                "metadata": {"id": spec.id, "ceiling": spec.ceiling},
            }
            for spec in specs
        ],
        task=task,
        scores=[score],
    )
    return _summary_result(dim, res, len(specs))


def run_quality(  # pragma: no cover
    settings: Settings,
    root: Path,
    *,
    dimensions: Sequence[str],
) -> dict[str, DimensionResult]:
    """Run the requested quality dimensions through a local Braintrust ``Eval``."""
    scopes = load_scopes(root)
    results: dict[str, DimensionResult] = {}
    for dim in dimensions:
        if dim == "factuality":
            results[dim] = _run_factuality(settings, scopes, root)
        elif dim == "budget":
            budget_cases = [cast("BudgetCase", c) for c in load_cases("budget", root)]
            results[dim] = _run_threshold(
                settings,
                scopes,
                dim="budget",
                specs=[
                    _TurnSpec(c.id, c.prompt, c.scope_ref, c.max_cost_usd)
                    for c in budget_cases
                ],
                measure=lambda s, sc, p: _cost_latency(s, sc, p)[0],
                score_of=lambda out, ceil: budget_threshold(out, ceil).as_braintrust(),
            )
        elif dim == "latency":
            latency_cases = [
                cast("LatencyCase", c) for c in load_cases("latency", root)
            ]
            results[dim] = _run_threshold(
                settings,
                scopes,
                dim="latency",
                specs=[
                    _TurnSpec(c.id, c.prompt, c.scope_ref, c.max_latency_s)
                    for c in latency_cases
                ],
                measure=lambda s, sc, p: _cost_latency(s, sc, p)[1],
                score_of=lambda out, ceil: latency_threshold(out, ceil).as_braintrust(),
            )
    return results
