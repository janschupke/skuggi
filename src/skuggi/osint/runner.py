"""Drive one OSINT run, translating supersteps into ``TurnEvent``s.

The streaming body (checkpoint namespace, stream, error handling, latency) is the
shared :func:`skuggi.agent.loop_runner.stream_loop`; this runner keeps only the
OSINT-specific pre-flight check (refuse without an OSINT scope) and the node-status
labels, then hands the compiled graph to the shared driver.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

from langchain_core.messages import HumanMessage

from skuggi.agent.loop_runner import stream_loop
from skuggi.agent.turn_runner import TurnEvent
from skuggi.common.logs import get_logger
from skuggi.osint.graph import osint_recursion_limit
from skuggi.osint.state import OsintState

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore

log = get_logger(__name__)

_NODE_STATUS = {
    "planner": "planning OSINT tasks",
    "collector": "collecting",
    "verifier": "verifying coverage",
}


class OsintRunner:
    """Runs the OSINT graph for one engagement, yielding operator-facing events."""

    def __init__(self, core: AgentCore) -> None:
        """Hold a back-ref to the core; it owns the compiled osint graph + saver."""
        self._core = core

    def osint_turn(self, request: str) -> Iterator[TurnEvent]:
        """Run one OSINT loop, yielding a status per node and a final summary."""
        if self._core.engagement is None or self._core.engagement.osint is None:
            yield TurnEvent(
                "status", "no OSINT scope loaded; set one via the wizard", node="error"
            )
            return
        settings = self._core.settings
        initial: OsintState = {
            "messages": [HumanMessage(content=request)],
            "request": request,
            "replan_count": 0,
            "max_replans": settings.osint_max_replans,
        }
        yield from stream_loop(
            self._core,
            self._core.osint_graph,
            initial,
            thread_prefix="osint",
            recursion_limit=osint_recursion_limit(
                max_tasks=settings.osint_max_tasks,
                max_replans=settings.osint_max_replans,
            ),
            node_status=_NODE_STATUS,
            log=log,
        )
