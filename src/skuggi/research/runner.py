"""Drive one research run, translating supersteps into ``TurnEvent``s.

The streaming body is the shared :func:`skuggi.agent.loop_runner.stream_loop`; this
runner keeps only research's pre-flight (a usage hint on an empty request, and a
"writing to ./research" note when no engagement is loaded, since research is
engagement-independent) and the node-status labels.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

from langchain_core.messages import HumanMessage

from skuggi.agent.loop_runner import stream_loop
from skuggi.agent.turn_runner import TurnEvent
from skuggi.common.logs import get_logger
from skuggi.research.graph import research_recursion_limit
from skuggi.research.state import ResearchState

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore

log = get_logger(__name__)

_NODE_STATUS = {
    "planner": "planning research tasks",
    "collector": "collecting",
    "verifier": "assembling profile",
}


class ResearchRunner:
    """Runs the research graph for one session, yielding operator-facing events."""

    def __init__(self, core: AgentCore) -> None:
        """Hold a back-ref to the core; it owns the compiled research graph + saver."""
        self._core = core

    def research_turn(self, request: str) -> Iterator[TurnEvent]:
        """Run one research loop, yielding a status per node and a final summary."""
        request = request.strip()
        if not request:
            yield TurnEvent("status", "usage: research <subject>", node="error")
            return
        if self._core.engagement is None:
            yield TurnEvent(
                "status",
                "no engagement set; writing research to ./research",
                node="planner",
            )
        settings = self._core.settings
        initial: ResearchState = {
            "messages": [HumanMessage(content=request)],
            "request": request,
            "replan_count": 0,
            "max_replans": settings.research_max_replans,
        }
        yield from stream_loop(
            self._core,
            self._core.research_graph,
            initial,
            thread_prefix="research",
            recursion_limit=research_recursion_limit(
                max_tasks=settings.research_max_tasks,
                max_replans=settings.research_max_replans,
            ),
            node_status=_NODE_STATUS,
            log=log,
        )
