"""Compile the forensics loop graph.

collect -> examine -> respond, linear. Unlike the OSINT/research loops there is no
planner or DAG scheduler: forensic collection is deterministic and exhaustive (the
analyzer battery over every evidence file), so there is nothing to plan or re-plan.
The examiner synthesises grounded findings from the collected observations and the
responder writes the cited report.
"""

from __future__ import annotations

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from skuggi.forensics.deps import ForensicsDeps
from skuggi.forensics.nodes import collect_node, examine_node, respond_node
from skuggi.forensics.state import ForensicsState


def build_forensics_graph(
    deps: ForensicsDeps, checkpointer: BaseCheckpointSaver[str]
) -> CompiledStateGraph[ForensicsState]:
    """Compile the forensics loop graph for one session."""

    def collect(state: ForensicsState) -> dict[str, object]:
        return collect_node(dict(state), deps)

    def examine(state: ForensicsState) -> dict[str, object]:
        return examine_node(dict(state), deps)

    def respond(state: ForensicsState) -> dict[str, object]:
        return respond_node(dict(state), deps)

    graph: StateGraph[ForensicsState, None, ForensicsState, ForensicsState] = (
        StateGraph(ForensicsState)
    )
    graph.add_node("collect", collect)
    graph.add_node("examine", examine)
    graph.add_node("respond", respond)
    graph.add_edge(START, "collect")
    graph.add_edge("collect", "examine")
    graph.add_edge("examine", "respond")
    graph.add_edge("respond", END)
    return graph.compile(checkpointer=checkpointer)


def forensics_recursion_limit() -> int:
    """Supersteps for a forensics run: three linear nodes plus headroom."""
    return 8
