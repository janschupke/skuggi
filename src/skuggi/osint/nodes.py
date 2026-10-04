"""The OSINT loop's graph nodes (thin; the branchy logic lives in scheduler.py).

planner -> (collector loop) -> verifier -> re-plan or respond. The planner emits a
todo DAG; the collector runs one ready task per superstep (scope-checked, then
dispatched to a source handler, the result written as a confined artifact); the
verifier judges coverage, promotes findings, and either re-plans the gaps or ends.
Every model call goes through the shared ``requests.ask`` seam; findings reuse the
executor's ``record_finding_drafts``.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage

from skuggi.agent.executor import record_finding_drafts
from skuggi.agent.requests import ask
from skuggi.common.text import join_blocks, labeled
from skuggi.engagement.osint_guard import check_osint_task
from skuggi.engagement.scope import OsintScope
from skuggi.osint import store
from skuggi.osint.collectors import collector_for
from skuggi.osint.collectors.base import empty_result
from skuggi.osint.deps import OsintDeps
from skuggi.osint.scheduler import coverage_gaps, select_ready
from skuggi.osint.schema import OsintPlan, OsintResult, OsintTask, OsintVerdict
from skuggi.osint.state import OsintState
from skuggi.security.policy import RedactionPolicy


def _scope_block(osint: OsintScope) -> str:
    """A labelled summary of the OSINT boundary for a request."""
    return (
        f"organizations: {', '.join(sorted(osint.organizations)) or '(none)'}\n"
        f"domains: {', '.join(sorted(osint.domains)) or '(none)'}\n"
        f"people: {', '.join(sorted(osint.people)) or '(none)'}\n"
        f"github orgs: {', '.join(sorted(osint.github_orgs)) or '(none)'}\n"
        f"enabled sources: {', '.join(sorted(osint.enabled_sources)) or '(none)'}\n"
        f"passive only: {osint.passive_only}"
    )


def _plan_request(state: OsintState, deps: OsintDeps) -> str:
    osint = deps.osint
    planned = "\n".join(
        f"- {t.id} [{t.source}] {t.subject}: {t.objective}"
        for t in state.get("plan", [])
    )
    return join_blocks(
        labeled("Request", state.get("request", "")),
        labeled("OSINT scope", _scope_block(osint) if osint else ""),
        labeled("Gaps to close", "\n".join(state.get("gaps", []))),
        labeled("Already planned", planned),
    )


def _results_block(results: list[OsintResult]) -> str:
    return "\n".join(
        f"[{r.source}] {r.subject}: {len(r.items)} items -- {r.note}" for r in results
    )


def _verify_request(state: OsintState, deps: OsintDeps, floor: list[str]) -> str:
    results = state.get("results", [])
    budget = deps.max_replans - state.get("replan_count", 0)
    return join_blocks(
        labeled("Request", state.get("request", "")),
        labeled("OSINT scope", _scope_block(deps.osint) if deps.osint else ""),
        labeled("Collected results", _results_block(results)),
        labeled("Sources with no data yet", ", ".join(floor)),
        labeled("Re-plan budget remaining", str(max(budget, 0))),
    )


def _policy(deps: OsintDeps) -> RedactionPolicy:
    return deps.redaction_policy or RedactionPolicy()


def plan_node(state: OsintState, deps: OsintDeps) -> dict[str, object]:
    """Ask the planner for a todo DAG; extend the plan, capped and deduped."""
    resp = ask(
        deps.llm,
        deps.prompts.planner,
        _plan_request(state, deps),
        OsintPlan,
        policy=_policy(deps),
        native=deps.native_structured,
    )
    existing = list(state.get("plan", []))
    seen = {t.id for t in existing}
    additions = [t for t in resp.tasks if t.id not in seen]
    plan = (existing + additions)[: deps.max_tasks]
    replan = state.get("replan_count", 0) + (1 if existing else 0)
    return {"plan": plan, "replan_count": replan}


def _collect_one(task: OsintTask, deps: OsintDeps) -> OsintResult:
    """Scope-check the task, dispatch to its collector, return a result (no raise)."""
    if deps.osint is None:
        return empty_result(task, "no OSINT scope loaded")
    verdict = check_osint_task(task.source, task.subject, deps.osint)
    if not verdict.allowed:
        return empty_result(task, f"denied: {verdict.reason}")
    collector = collector_for(task.source, deps.collectors)
    ctx = deps.collect_context
    if collector is None or ctx is None:
        return empty_result(task, f"no collector configured for {task.source}")
    if not collector.available(ctx):
        return empty_result(task, f"{task.source} collector is unavailable")
    return collector.collect(task, ctx)


def collect_node(state: OsintState, deps: OsintDeps) -> dict[str, object]:
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
    if deps.workspace is not None and ctx is not None:
        store.write_result(deps.workspace, result, clean=ctx.clean)
    return {"completed": [*completed, task.id], "results": [*results, result]}


def verify_node(state: OsintState, deps: OsintDeps) -> dict[str, object]:
    """Judge coverage, record findings, and set the draft + any gaps to re-plan."""
    results = list(state.get("results", []))
    floor = [str(s) for s in coverage_gaps(results, deps.osint)] if deps.osint else []
    resp = ask(
        deps.llm,
        deps.prompts.verifier,
        _verify_request(state, deps, floor),
        OsintVerdict,
        policy=_policy(deps),
        native=deps.native_structured,
    )
    if deps.ledger is not None and deps.session_id and resp.findings:
        record_finding_drafts(
            deps.ledger,
            resp.findings,
            session_id=deps.session_id,
            engagement=deps.engagement,
            command_id=None,
        )
    return {
        "draft": resp.summary,
        "gaps": list(resp.gaps),
        "done": resp.done,
    }


def respond_node(state: OsintState) -> dict[str, object]:
    """Emit the accumulated summary as the loop's answer."""
    return {"messages": [AIMessage(content=state.get("draft") or "")]}
