"""Compile the public-source research graph on the shared DAG loop.

planner -> (collector loop) -> verifier -> re-plan | respond. The shape, routing
and recursion-limit arithmetic live in :mod:`skuggi.intel.graph`; this module only
binds the research nodes (and state schema) into it. A sibling of the OSINT graph
on the same core -- it shares the wiring but has its own nodes, source check and
report-only output.
"""

from __future__ import annotations

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph.state import CompiledStateGraph

from skuggi.intel.graph import DagNodes, build_dag_loop, dag_recursion_limit
from skuggi.research.deps import ResearchDeps
from skuggi.research.nodes import collect_node, plan_node, respond_node, verify_node
from skuggi.research.state import ResearchState


def build_research_graph(
    deps: ResearchDeps, checkpointer: BaseCheckpointSaver[str]
) -> CompiledStateGraph[ResearchState]:
    """Compile the research loop graph for one session (shared DAG wiring)."""
    nodes = DagNodes(
        plan=lambda state: plan_node(state, deps),
        collect=lambda state: collect_node(state, deps),
        verify=lambda state: verify_node(state, deps),
        respond=lambda state: respond_node(state, deps),
    )
    return build_dag_loop(
        nodes, checkpointer, state_type=ResearchState, max_replans=deps.max_replans
    )


def research_recursion_limit(*, max_tasks: int, max_replans: int) -> int:
    """Supersteps for the worst-case research run (the shared DAG bound)."""
    return dag_recursion_limit(max_tasks=max_tasks, max_replans=max_replans)
