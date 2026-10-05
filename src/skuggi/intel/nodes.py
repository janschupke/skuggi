"""Shared node machinery for the DAG intelligence loops (OSINT and research).

The two loops' planner and collector nodes were near-identical: the planner asks
for a todo DAG and extends the plan (deduped, capped, counting a re-plan), and the
collector runs one ready task per superstep and appends its result. Those two
bodies live here once, parameterized by the loop's schema/prompt/guard/sink; the
per-loop nodes shrink to that binding plus the genuinely loop-specific verifier
(OSINT promotes findings; research assembles a profile). The shared ``ask`` seam
(``agent.requests.ask``) and the structured-output discipline are unchanged.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Protocol

from langchain_core.language_models import BaseChatModel
from pydantic import BaseModel

from skuggi.agent.requests import ask
from skuggi.common.logs import get_logger
from skuggi.intel.scheduler import Task, select_ready
from skuggi.intel.schema import IntelResult
from skuggi.security.policy import RedactionPolicy

log = get_logger(__name__)


class ModelPlane(Protocol):
    """The model-plane fields every loop's deps share (read by ``ask_schema``)."""

    @property
    def llm(self) -> BaseChatModel | None:
        """The chat model (built before streaming; ``ask`` guards a ``None``)."""

    @property
    def native_structured(self) -> bool:
        """Whether the provider supports native structured output."""

    @property
    def redaction_policy(self) -> RedactionPolicy | None:
        """The session redaction policy (a default masks when ``None``)."""


def policy_of(deps: ModelPlane) -> RedactionPolicy:
    """The deps' redaction policy, or a one-way-masking default when unset."""
    return deps.redaction_policy or RedactionPolicy()


def ask_schema[T: BaseModel](
    deps: ModelPlane, system: str, request: str, schema: type[T], *, label: str
) -> T:
    """Obtain a validated ``schema`` for a loop node, binding the deps' model plane.

    Collapses the ``policy=_policy(deps), native=deps.native_structured`` plumbing
    that every loop node repeated by hand, and makes the ``label`` (for the per-run
    latency attribution) a required argument so a node can never forget it.
    """
    return ask(
        deps.llm,
        system,
        request,
        schema,
        policy=policy_of(deps),
        native=deps.native_structured,
        label=label,
    )


def results_block(results: Sequence[IntelResult]) -> str:
    """A one-line-per-result digest for a verifier/planner request block."""
    return "\n".join(
        f"[{r.source}] {r.subject}: {len(r.items)} items -- {r.note}" for r in results
    )


def extend_plan[T: Task](
    tasks: Sequence[T], existing: Sequence[T], *, max_tasks: int, replan_count: int
) -> dict[str, object]:
    """Merge newly-planned tasks into the plan: dedup by id, cap, count a re-plan.

    The shared planner-node body: a first pass seeds the plan; a re-plan appends
    only unseen task ids (so a re-plan narrows gaps rather than restarting) and
    increments the replan counter that bounds the loop.
    """
    seen = {t.id for t in existing}
    additions = [t for t in tasks if t.id not in seen]
    plan = (list(existing) + additions)[:max_tasks]
    return {"plan": plan, "replan_count": replan_count + (1 if existing else 0)}


def _persist_result(
    result: IntelResult, persist: Callable[[IntelResult], None]
) -> None:
    """Persist one artifact, swallowing a bad write so it cannot abort the run (B3)."""
    try:
        persist(result)
    except (OSError, ValueError) as exc:  # a bad artifact write must not abort the run
        log.warning(
            "intel artifact write failed for %s/%s: %s",
            result.source,
            result.subject,
            exc,
        )


def collect_ready[T: Task](  # noqa: PLR0913 -- keyword-only collect-step seams
    plan: Sequence[T],
    completed: Sequence[str],
    results: Sequence[IntelResult],
    *,
    collect_one: Callable[[T], IntelResult],
    persist: Callable[[IntelResult], None],
    uses_driver: Callable[[T], bool] = lambda _t: False,
    max_workers: int = 1,
) -> dict[str, object]:
    """Run every currently-ready task, persist its artifact, mark it completed.

    The shared collector-node body. All ready tasks run in one superstep (the DAG
    is re-evaluated next step for any that this unblocks), so an independent set is
    not serialized a step apart (audit D1). Pure-I/O collectors run in a bounded
    thread pool; a driver-capable collector (``uses_driver``) runs serially, so a
    parallel superstep never spawns a browser pool -- the one hard constraint on
    this parallelism. Results are appended in ready (plan) order regardless of
    completion order, so a run stays deterministic and the goldens hold. ``persist``
    is the loop's confined writer; a bad write is logged and swallowed (audit B3).
    An empty ready set is a no-op update.
    """
    ready = select_ready(list(plan), list(completed))
    if not ready:
        return {}
    serial = [t for t in ready if uses_driver(t)]
    parallel = [t for t in ready if not uses_driver(t)]
    collected: dict[str, IntelResult] = {}
    for task in serial:  # driver-backed: one browser at a time, never pooled
        collected[task.id] = collect_one(task)
    workers = max(1, min(max_workers, len(parallel)))
    if workers == 1 or len(parallel) <= 1:
        for task in parallel:
            collected[task.id] = collect_one(task)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(collect_one, task): task for task in parallel}
            for future in as_completed(futures):
                collected[futures[future].id] = future.result()
    ordered = [collected[task.id] for task in ready]  # deterministic plan order
    for result in ordered:
        _persist_result(result, persist)
    return {
        "completed": [*completed, *[task.id for task in ready]],
        "results": [*results, *ordered],
    }
