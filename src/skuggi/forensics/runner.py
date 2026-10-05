"""Drive one forensics run, translating supersteps into ``TurnEvent``s.

The streaming body is the shared :func:`skuggi.agent.loop_runner.stream_loop`; this
runner keeps only forensics' pre-flight (refuse without a case -- the chain-of-
custody ledger lives in the case) and builds the graph per turn so it always
reflects the active case. The forensics graph is linear (collect -> examine ->
respond), but the stream translation is the same shape the DAG loops use.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

from langchain_core.messages import HumanMessage

from skuggi.agent.loop_runner import stream_loop
from skuggi.agent.turn_runner import TurnEvent
from skuggi.common.logs import get_logger
from skuggi.forensics.graph import build_forensics_graph, forensics_recursion_limit
from skuggi.forensics.state import ForensicsState

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore

log = get_logger(__name__)

_NODE_STATUS = {
    "collect": "acquiring + examining evidence",
    "examine": "assembling findings",
}


class ForensicsRunner:
    """Runs the forensics graph for one session, yielding operator-facing events."""

    def __init__(self, core: AgentCore) -> None:
        """Hold a back-ref to the core; it owns the case plane + the saver."""
        self._core = core

    def forensics_turn(self, request: str) -> Iterator[TurnEvent]:
        """Run one forensics loop, yielding a status per node and a final summary."""
        request = request.strip() or "examine the evidence"
        if self._core.case_mgr is None:
            yield TurnEvent(
                "status",
                "no forensics case loaded; run `set case <dir>` first",
                node="error",
            )
            return
        graph = build_forensics_graph(self._core.forensics_deps(), self._core.saver)
        initial: ForensicsState = {
            "messages": [HumanMessage(content=request)],
            "request": request,
        }
        yield from stream_loop(
            self._core,
            graph,
            initial,
            thread_prefix="forensics",
            recursion_limit=forensics_recursion_limit(),
            node_status=_NODE_STATUS,
            log=log,
        )
