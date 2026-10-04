"""The research loop's graph nodes (thin; DAG logic lives in intel.scheduler).

planner -> (collector loop) -> verifier -> re-plan or respond. The planner emits a
todo DAG; the collector runs one ready task per superstep (source-checked, then
dispatched to a public-source handler, the result written as a confined artifact);
the verifier assembles the structured profile and either re-plans the gaps or ends;
the responder writes the Markdown report. Every model call goes through the shared
``requests.ask`` seam. No findings are promoted -- research is report-only.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage

from skuggi.agent.requests import ask
from skuggi.common.logs import get_logger
from skuggi.common.text import join_blocks, labeled
from skuggi.intel import store
from skuggi.intel.scheduler import coverage_gaps, select_ready
from skuggi.intel.schema import IntelResult
from skuggi.research import report
from skuggi.research.collectors import collector_for
from skuggi.research.deps import ResearchDeps
from skuggi.research.schema import ResearchPlan, ResearchTask, ResearchVerdict
from skuggi.research.scope import check_research_source
from skuggi.research.state import ResearchState
from skuggi.security.policy import RedactionPolicy

log = get_logger(__name__)

_SOURCE_HELP = (
    "versions, github, websearch, cve, exploitdb, searchsploit, metasploit "
    "(all public, passive sources)"
)


def _policy(deps: ResearchDeps) -> RedactionPolicy:
    return deps.redaction_policy or RedactionPolicy()


def _plan_request(state: ResearchState, deps: ResearchDeps) -> str:  # noqa: ARG001
    planned = "\n".join(
        f"- {t.id} [{t.source}] {t.subject}: {t.objective}"
        for t in state.get("plan", [])
    )
    return join_blocks(
        labeled("Request", state.get("request", "")),
        labeled("Available sources", _SOURCE_HELP),
        labeled("Gaps to close", "\n".join(state.get("gaps", []))),
        labeled("Already planned", planned),
    )


def _results_block(results: list[IntelResult]) -> str:
    return "\n".join(
        f"[{r.source}] {r.subject}: {len(r.items)} items -- {r.note}" for r in results
    )


def _verify_request(state: ResearchState, deps: ResearchDeps, floor: list[str]) -> str:
    results = state.get("results", [])
    budget = deps.max_replans - state.get("replan_count", 0)
    return join_blocks(
        labeled("Request", state.get("request", "")),
        labeled("Collected results", _results_block(results)),
        labeled("Sources with no data yet", ", ".join(floor)),
        labeled("Re-plan budget remaining", str(max(budget, 0))),
    )


def plan_node(state: ResearchState, deps: ResearchDeps) -> dict[str, object]:
    """Ask the planner for a todo DAG; extend the plan, capped and deduped."""
    resp = ask(
        deps.llm,
        deps.prompts.planner,
        _plan_request(state, deps),
        ResearchPlan,
        policy=_policy(deps),
        native=deps.native_structured,
    )
    existing = list(state.get("plan", []))
    seen = {t.id for t in existing}
    additions = [t for t in resp.tasks if t.id not in seen]
    plan = (existing + additions)[: deps.max_tasks]
    replan = state.get("replan_count", 0) + (1 if existing else 0)
    return {"plan": plan, "replan_count": replan}


def _collect_one(task: ResearchTask, deps: ResearchDeps) -> IntelResult:
    """Source-check the task, dispatch to its collector, return a result (no raise)."""
    from skuggi.intel.collectors.base import empty_result  # noqa: PLC0415

    verdict = check_research_source(task.source)
    if not verdict.allowed:
        return empty_result(task, f"denied: {verdict.reason}")
    collector = collector_for(task.source, deps.collectors)
    ctx = deps.collect_context
    if collector is None or ctx is None:
        return empty_result(task, f"no collector configured for {task.source}")
    if not collector.available(ctx):
        return empty_result(task, f"{task.source} collector is unavailable")
    return collector.collect(task, ctx)


def collect_node(state: ResearchState, deps: ResearchDeps) -> dict[str, object]:
    """Run one ready task, persist its artifact, and record it as completed."""
    plan = list(state.get("plan", []))
    completed = list(state.get("completed", []))
    results = list(state.get("results", []))
    ready = select_ready(plan, completed)
    if not ready:
        return {}
    task = ready[0]
    result = _collect_one(task, deps)
    ctx = deps.collect_context
    if deps.output_root is not None and ctx is not None:
        store.write_result(deps.output_root, result, clean=ctx.clean)
    return {"completed": [*completed, task.id], "results": [*results, result]}


def _available_sources(deps: ResearchDeps) -> list[str]:
    """The sources whose collector can actually run now (the coverage floor base)."""
    ctx = deps.collect_context
    if ctx is None:
        return []
    return [c.source for c in deps.collectors if c.available(ctx)]


def verify_node(state: ResearchState, deps: ResearchDeps) -> dict[str, object]:
    """Judge coverage, assemble the profile, and set the draft + any gaps to re-plan."""
    results = list(state.get("results", []))
    floor = coverage_gaps(results, _available_sources(deps))
    resp = ask(
        deps.llm,
        deps.prompts.verifier,
        _verify_request(state, deps, floor),
        ResearchVerdict,
        policy=_policy(deps),
        native=deps.native_structured,
    )
    return {
        "draft": resp.summary,
        "gaps": list(resp.gaps),
        "done": resp.done,
        "profile": resp.profile,
    }


def respond_node(state: ResearchState, deps: ResearchDeps) -> dict[str, object]:
    """Write the Markdown report and emit the summary as the loop's answer."""
    summary = state.get("draft") or ""
    ctx = deps.collect_context
    if deps.output_root is not None and ctx is not None:
        try:
            path = report.write_research_report(
                deps.output_root,
                state.get("request", ""),
                state.get("profile"),
                list(state.get("results", [])),
                clean=ctx.clean,
            )
            summary = f"{summary}\n\nReport written to {path}".strip()
        except (OSError, ValueError) as e:  # a bad write must not kill the loop
            log.warning("research report write failed: %s", e)
    return {"messages": [AIMessage(content=summary)]}
