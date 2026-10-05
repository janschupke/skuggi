"""The OSINT loop's graph nodes (thin bindings over the shared intel machinery).

planner -> (collector loop) -> verifier -> re-plan or respond. The planner and
collector bodies are the shared ``intel.nodes`` steps bound to OSINT's schema,
guard and artifact sink; only the verifier is OSINT-specific -- it judges coverage
against the enabled sources, promotes ``FindingDraft``s to the engagement ledger,
and sets the re-plan gaps. Every model call goes through the shared ``ask`` seam.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from langchain_core.messages import AIMessage

from skuggi.agent.executor import record_finding_drafts
from skuggi.common.text import join_blocks, labeled
from skuggi.engagement.osint_guard import check_osint_task
from skuggi.engagement.scope import OsintScope
from skuggi.intel.collectors.base import collector_uses_driver, empty_result
from skuggi.intel.nodes import ask_schema, collect_ready, extend_plan, results_block
from skuggi.intel.schema import IntelResult
from skuggi.osint import store
from skuggi.osint.collectors import collector_for
from skuggi.osint.deps import OsintDeps
from skuggi.osint.promote import promotable_hosts
from skuggi.osint.scheduler import coverage_gaps
from skuggi.osint.schema import OsintPlan, OsintTask, OsintVerdict
from skuggi.osint.state import OsintState


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


def _verify_request(state: OsintState, deps: OsintDeps, floor: list[str]) -> str:
    results = state.get("results", [])
    budget = deps.max_replans - state.get("replan_count", 0)
    return join_blocks(
        labeled("Request", state.get("request", "")),
        labeled("OSINT scope", _scope_block(deps.osint) if deps.osint else ""),
        labeled("Collected results", results_block(results)),
        labeled("Sources with no data yet", ", ".join(floor)),
        labeled("Re-plan budget remaining", str(max(budget, 0))),
    )


def plan_node(state: OsintState, deps: OsintDeps) -> dict[str, object]:
    """Ask the planner for a todo DAG; extend the plan, capped and deduped."""
    resp = ask_schema(
        deps,
        deps.prompts.planner,
        _plan_request(state, deps),
        OsintPlan,
        label="planner",
    )
    return extend_plan(
        resp.tasks,
        list(state.get("plan", [])),
        max_tasks=deps.max_tasks,
        replan_count=state.get("replan_count", 0),
    )


def _collect_one(
    task: OsintTask, deps: OsintDeps, upstream: Sequence[IntelResult] = ()
) -> IntelResult:
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
    ctx = replace(ctx, upstream=tuple(upstream))  # thread upstream results (E15)
    if not collector.available(ctx):
        return empty_result(task, f"{task.source} collector is unavailable")
    return collector.collect(task, ctx)


def collect_node(state: OsintState, deps: OsintDeps) -> dict[str, object]:
    """Run every ready task (bounded parallel), persist artifacts, mark completed."""

    def persist(result: IntelResult) -> None:
        ws, ctx = deps.workspace, deps.collect_context
        if ws is not None and ctx is not None:
            store.write_result(ws, result, clean=ctx.clean)

    def uses_driver(task: OsintTask) -> bool:
        collector = collector_for(task.source, deps.collectors)
        return collector is not None and collector_uses_driver(collector)

    return collect_ready(
        list(state.get("plan", [])),
        list(state.get("completed", [])),
        list(state.get("results", [])),
        collect_one=lambda task, upstream: _collect_one(task, deps, upstream),
        persist=persist,
        uses_driver=uses_driver,
        max_workers=deps.concurrency,
    )


def verify_node(state: OsintState, deps: OsintDeps) -> dict[str, object]:
    """Judge coverage, record findings, and set the draft + any gaps to re-plan."""
    results = list(state.get("results", []))
    floor = [str(s) for s in coverage_gaps(results, deps.osint)] if deps.osint else []
    resp = ask_schema(
        deps,
        deps.prompts.verifier,
        _verify_request(state, deps, floor),
        OsintVerdict,
        label="verifier",
    )
    if deps.ledger is not None and deps.session_id and resp.findings:
        record_finding_drafts(
            deps.ledger,
            resp.findings,
            session_id=deps.session_id,
            engagement=deps.engagement,
            command_id=None,
        )
    summary = _with_scope_proposal(resp.summary, results, deps)
    return {"draft": summary, "gaps": list(resp.gaps), "done": resp.done}


def _with_scope_proposal(
    summary: str, results: list[IntelResult], deps: OsintDeps
) -> str:
    """Append a gated scope-promotion proposal for any discovered in-scope hosts.

    OSINT-discovered hosts inside an authorized network but not yet in
    ``allowed_hosts`` are surfaced here as a proposal, never auto-applied: the
    operator authorizes them through the gated, non-grantable ``set scope`` flow,
    closing the recon -> scan loop deliberately (audit E17/C4).
    """
    hosts = promotable_hosts(results, deps.engagement)
    if not hosts:
        return summary
    proposal = (
        "Discovered in-scope hosts not yet authorized for scanning: "
        f"{', '.join(hosts)}. Run `set scope` to add them to allowed_hosts "
        "(each change is confirmed)."
    )
    return f"{summary}\n\n{proposal}" if summary else proposal


def respond_node(state: OsintState) -> dict[str, object]:
    """Emit the accumulated summary as the loop's answer."""
    return {"messages": [AIMessage(content=state.get("draft") or "")]}
