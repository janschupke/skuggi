"""Compile a generic planner -> collect-loop -> verify -> respond DAG graph.

The OSINT and research loops are the same shape: a planner emits a dependency
DAG, a scheduler walks it one ready task per superstep, a verifier judges coverage
and either re-plans the gaps or ends, and a responder emits the answer. Only the
node bodies, the state channel schema and the loop bounds differ -- those are
injected via :class:`DagNodes` and ``state_type``/``max_replans``. The turn graph
and the linear forensics graph are NOT this shape and keep their own builders.

This is the graph-wiring half of the shared intel core (the scheduler/store/schema
were already shared); lifting it here is what lets ``osint`` and ``research`` stop
duplicating the identical builder and recursion-limit arithmetic.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from skuggi.intel.scheduler import select_ready

# A node is a function from the loop's state to a partial state update. The state
# is a loop-specific TypedDict; the builder is agnostic to which, so the callables
# are typed over ``Any`` here and pinned by each loop's own builder signature.
DagNode = Callable[[Any], dict[str, object]]


@dataclass(frozen=True, slots=True)
class DagNodes:
    """The four node callables a DAG loop wires, already bound to their deps."""

    plan: DagNode
    collect: DagNode
    verify: DagNode
    respond: DagNode


def build_dag_loop(
    nodes: DagNodes,
    checkpointer: BaseCheckpointSaver[str],
    *,
    state_type: type[Any],
    max_replans: int,
) -> CompiledStateGraph[Any]:
    """Compile the shared planner/collector/verifier/respond DAG loop.

    ``route_next`` loops the collector while a ready task remains, else advances to
    the verifier; ``route_after_verify`` re-plans while work remains, gaps are
    named and the replan budget holds, else responds. Both read only generic state
    keys, so every loop that supplies ``DagNodes`` + a matching state schema reuses
    this wiring unchanged.
    """

    def route_next(state: Any) -> Literal["collector", "verifier"]:  # noqa: ANN401
        ready = select_ready(
            list(state.get("plan", [])), list(state.get("completed", []))
        )
        return "collector" if ready else "verifier"

    def route_after_verify(state: Any) -> Literal["planner", "respond"]:  # noqa: ANN401
        incomplete = not state.get("done")
        under_cap = state.get("replan_count", 0) < max_replans
        if incomplete and under_cap and state.get("gaps"):
            return "planner"
        return "respond"

    graph: StateGraph[Any, None, Any, Any] = StateGraph(state_type)
    # The nodes are typed over ``Any`` (the builder is state-agnostic), so mypy
    # cannot infer langgraph's TypedDict-bound node-input type; each loop's own
    # builder signature pins the real state type.
    for name, node in (
        ("planner", nodes.plan),
        ("collector", nodes.collect),
        ("verifier", nodes.verify),
        ("respond", nodes.respond),
    ):
        graph.add_node(name, node)  # type: ignore[call-overload]
    graph.add_edge(START, "planner")
    graph.add_conditional_edges("planner", route_next)
    graph.add_conditional_edges("collector", route_next)
    graph.add_conditional_edges("verifier", route_after_verify)
    graph.add_edge("respond", END)
    return graph.compile(checkpointer=checkpointer)


def dag_recursion_limit(*, max_tasks: int, max_replans: int) -> int:
    """Supersteps for the worst-case DAG run, plus headroom.

    One plan cycle is the planner, up to ``max_tasks`` collector steps (one ready
    task per superstep), and the verifier; a run may re-plan ``max_replans`` times.
    A DAG loop needs more than langgraph's default of 25, so size it explicitly.
    """
    per_cycle = max_tasks + 2  # planner + collectors + verifier
    return (max_replans + 1) * per_cycle + 6
