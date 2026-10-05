"""Compile the OSINT reconnaissance graph on the shared DAG loop.

planner -> (collector loop) -> verifier -> re-plan | respond. The shape, routing
and recursion-limit arithmetic live in :mod:`skuggi.intel.graph`; this module only
binds the OSINT nodes (and state schema) into it. A sibling of the research graph
built on the same core -- it shares the wiring but keeps its own nodes, scope and
finding promotion.
"""

from __future__ import annotations

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph.state import CompiledStateGraph

from skuggi.intel.graph import DagNodes, build_dag_loop, dag_recursion_limit
from skuggi.osint.deps import OsintDeps
from skuggi.osint.nodes import collect_node, plan_node, respond_node, verify_node
from skuggi.osint.state import OsintState


def build_osint_graph(
    deps: OsintDeps, checkpointer: BaseCheckpointSaver[str]
) -> CompiledStateGraph[OsintState]:
    """Compile the OSINT loop graph for one session (shared DAG wiring)."""
    nodes = DagNodes(
        plan=lambda state: plan_node(state, deps),
        collect=lambda state: collect_node(state, deps),
        verify=lambda state: verify_node(state, deps),
        respond=respond_node,
    )
    return build_dag_loop(
        nodes, checkpointer, state_type=OsintState, max_replans=deps.max_replans
    )


def osint_recursion_limit(*, max_tasks: int, max_replans: int) -> int:
    """Supersteps for the worst-case OSINT run (the shared DAG bound)."""
    return dag_recursion_limit(max_tasks=max_tasks, max_replans=max_replans)
