"""Drive one forensics run, translating supersteps into ``TurnEvent``s.

A sibling of ``ResearchRunner`` for the forensics graph, under a dedicated
``forensics:<thread>`` checkpoint namespace. Unlike research it REQUIRES a case
(the chain-of-custody ledger lives in the case): with no case loaded it yields a
guidance event rather than running, mirroring how OSINT refuses without an
engagement. The graph is built per turn so it always reflects the active case. A
bad run yields an error event rather than raising, so a front-end loop survives.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, cast

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.runnables import RunnableConfig

from skuggi.agent.turn_runner import TurnEvent
from skuggi.common.logs import get_logger
from skuggi.config.configs import ConfigError
from skuggi.forensics.graph import build_forensics_graph, forensics_recursion_limit
from skuggi.forensics.state import ForensicsState

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore

log = get_logger(__name__)

_NODE_STATUS = {
    "collect": "acquiring + examining evidence",
    "examine": "assembling findings",
    "respond": "writing report",
}


class ForensicsRunner:
    """Runs the forensics graph for one session, yielding operator-facing events."""

    def __init__(self, core: AgentCore) -> None:
        """Hold a back-ref to the core; it owns the case plane + the saver."""
        self._core = core

    def _config(self) -> RunnableConfig:
        return {
            "configurable": {"thread_id": f"forensics:{self._core.thread_id}"},
            "recursion_limit": forensics_recursion_limit(),
        }

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
        initial: ForensicsState = {
            "messages": [HumanMessage(content=request)],
            "request": request,
        }
        log.info(
            "forensics run start thread=%s request=%r", self._core.thread_id, request
        )
        try:
            self._core.ensure_llm()
            graph = build_forensics_graph(self._core.forensics_deps(), self._core.saver)
            stream: Iterator[Any] = graph.stream(
                initial, self._config(), stream_mode="updates"
            )
            for payload in stream:
                yield from self._updates(cast("dict[str, object]", payload))
        except ConfigError as e:
            log.warning("forensics run aborted on config error: %s", e)
            yield TurnEvent("status", str(e), node="error")
        except Exception as e:  # a bad run must not kill the loop
            log.exception("forensics run failed")
            yield TurnEvent("status", f"{type(e).__name__}: {e}", node="error")
        finally:
            log.info("forensics run done thread=%s", self._core.thread_id)

    def _updates(self, payload: dict[str, object]) -> Iterator[TurnEvent]:
        """Turn one superstep's ``{node: update}`` into events."""
        for node, value in payload.items():
            if node == "respond":
                yield TurnEvent("final", _draft_of(value), node="respond")
                continue
            yield TurnEvent("status", _NODE_STATUS.get(node, node), node=node)


def _draft_of(value: object) -> str:
    """The respond node's emitted answer text."""
    if isinstance(value, dict):
        messages = value.get("messages")
        if isinstance(messages, list) and messages:
            last = messages[-1]
            if isinstance(last, AIMessage):
                return str(last.text)
    return ""
