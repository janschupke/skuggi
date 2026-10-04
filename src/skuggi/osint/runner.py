"""Drive one OSINT run, translating supersteps into ``TurnEvent``s.

The sibling of ``TurnRunner`` for the OSINT graph: it owns a dedicated
``osint:<thread>`` checkpoint namespace (so the two graphs never share a channel
schema on one checkpoint), records the run on the ledger timeline, and yields the
same ``TurnEvent`` stream the front-ends already render -- a ``status`` per node and
a ``final`` summary. A bad run yields an error event rather than raising, so a
front-end loop is never killed.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, cast

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.runnables import RunnableConfig

from skuggi.agent.turn_runner import TurnEvent
from skuggi.common.logs import get_logger
from skuggi.config.configs import ConfigError
from skuggi.osint.graph import osint_recursion_limit
from skuggi.osint.state import OsintState

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore

log = get_logger(__name__)

_NODE_STATUS = {
    "planner": "planning OSINT tasks",
    "collector": "collecting",
    "verifier": "verifying coverage",
    "respond": "done",
}


class OsintRunner:
    """Runs the OSINT graph for one engagement, yielding operator-facing events."""

    def __init__(self, core: AgentCore) -> None:
        """Hold a back-ref to the core; it owns the compiled osint graph + saver."""
        self._core = core

    def _config(self) -> RunnableConfig:
        settings = self._core.settings
        return {
            "configurable": {"thread_id": f"osint:{self._core.thread_id}"},
            "recursion_limit": osint_recursion_limit(
                max_tasks=settings.osint_max_tasks,
                max_replans=settings.osint_max_replans,
            ),
        }

    def osint_turn(self, request: str) -> Iterator[TurnEvent]:
        """Run one OSINT loop, yielding a status per node and a final summary."""
        if self._core.engagement is None or self._core.engagement.osint is None:
            yield TurnEvent(
                "status", "no OSINT scope loaded; set one via the wizard", node="error"
            )
            return
        initial: OsintState = {
            "messages": [HumanMessage(content=request)],
            "request": request,
            "replan_count": 0,
            "max_replans": self._core.settings.osint_max_replans,
        }
        log.info("osint run start thread=%s request=%r", self._core.thread_id, request)
        try:
            self._core.ensure_llm()
            stream: Iterator[Any] = self._core.osint_graph.stream(
                initial, self._config(), stream_mode="updates"
            )
            for payload in stream:
                yield from self._updates(cast("dict[str, object]", payload))
        except ConfigError as e:
            log.warning("osint run aborted on config error: %s", e)
            yield TurnEvent("status", str(e), node="error")
        except Exception as e:  # a bad run must not kill the loop
            log.exception("osint run failed")
            yield TurnEvent("status", f"{type(e).__name__}: {e}", node="error")
        finally:
            log.info("osint run done thread=%s", self._core.thread_id)

    def _updates(self, payload: dict[str, object]) -> Iterator[TurnEvent]:
        """Turn one superstep's ``{node: update}`` into events."""
        for node, value in payload.items():
            if node == "respond":
                draft = _draft_of(value)
                yield TurnEvent("final", draft, node="respond")
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
