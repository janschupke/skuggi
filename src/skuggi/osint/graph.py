"""Compile the OSINT reconnaissance graph.

planner -> (collector loop) -> verifier -> re-plan | respond. The collector loops
by routing back through the same selection predicate each superstep, so one ready
task runs per step until none remain (or the plan is blocked), exactly the
executor's bounded worker<->executor shape. A sibling of ``agent.graph.build_graph``
that shares the request seam but nothing of the turn graph's wiring.
"""

from __future__ import annotations

from typing import Literal

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from skuggi.osint.deps import OsintDeps
from skuggi.osint.nodes import collect_node, plan_node, respond_node, verify_node
from skuggi.osint.scheduler import select_ready
from skuggi.osint.state import OsintState


def build_osint_graph(
    deps: OsintDeps, checkpointer: BaseCheckpointSaver[str]
) -> CompiledStateGraph[OsintState]:
    """Compile the OSINT loop graph for one session."""

    def planner(state: OsintState) -> dict[str, object]:
        return plan_node(state, deps)

    def collector(state: OsintState) -> dict[str, object]:
        return collect_node(state, deps)

    def verifier(state: OsintState) -> dict[str, object]:
        return verify_node(state, deps)

    def route_next(state: OsintState) -> Literal["collector", "verifier"]:
        ready = select_ready(
            list(state.get("plan", [])), list(state.get("completed", []))
        )
        return "collector" if ready else "verifier"

    def route_after_verify(state: OsintState) -> Literal["planner", "respond"]:
        incomplete = not state.get("done")
        under_cap = state.get("replan_count", 0) < deps.max_replans
        if incomplete and under_cap and state.get("gaps"):
            return "planner"
        return "respond"

    graph: StateGraph[OsintState, None, OsintState, OsintState] = StateGraph(OsintState)
    graph.add_node("planner", planner)
    graph.add_node("collector", collector)
    graph.add_node("verifier", verifier)
    graph.add_node("respond", respond_node)

    graph.add_edge(START, "planner")
    graph.add_conditional_edges("planner", route_next)
    graph.add_conditional_edges("collector", route_next)
    graph.add_conditional_edges("verifier", route_after_verify)
    graph.add_edge("respond", END)
    return graph.compile(checkpointer=checkpointer)


def osint_recursion_limit(*, max_tasks: int, max_replans: int) -> int:
    """Supersteps for the worst-case OSINT run, plus headroom.

    One plan cycle is the planner, up to ``max_tasks`` collector steps (one ready
    task per superstep), and the verifier; a run may re-plan ``max_replans`` times.
    A DAG loop needs more than langgraph's default of 25, so size it explicitly.
    """
    per_cycle = max_tasks + 2  # planner + collectors + verifier
    return (max_replans + 1) * per_cycle + 6
