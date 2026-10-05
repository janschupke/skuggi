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


def collect_one_ready[T: Task](
    plan: Sequence[T],
    completed: Sequence[str],
    results: Sequence[IntelResult],
    *,
    collect_one: Callable[[T], IntelResult],
    persist: Callable[[IntelResult], None],
) -> dict[str, object]:
    """Run one ready task, persist its artifact, and record it as completed.

    The shared collector-node body. ``persist`` is the loop's confined artifact
    writer; a bad write (a subject that will not slug, a confinement escape) is
    logged and swallowed so one odd task cannot abort a whole run and discard every
    result collected so far (audit B3). An empty ready set is a no-op update.
    """
    ready = select_ready(list(plan), list(completed))
    if not ready:
        return {}
    task = ready[0]
    result = collect_one(task)
    try:
        persist(result)
    except (OSError, ValueError) as exc:  # a bad artifact write must not abort the run
        log.warning(
            "intel artifact write failed for %s/%s: %s",
            result.source,
            result.subject,
            exc,
        )
    return {"completed": [*completed, task.id], "results": [*results, result]}
