"""Drive one research run, translating supersteps into ``TurnEvent``s.

A sibling of ``OsintRunner`` for the research graph: it owns a dedicated
``research:<thread>`` checkpoint namespace (so the graphs never share a channel
schema on one checkpoint) and yields the same ``TurnEvent`` stream the front-ends
already render -- a ``status`` per node and a ``final`` summary. Unlike OSINT it
does NOT refuse without an engagement: research is engagement-independent, so when
none is loaded it yields a warning that artifacts go to ``./research`` and runs.
A bad run yields an error event rather than raising, so a front-end loop is never
killed.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, cast

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.runnables import RunnableConfig

from skuggi.agent.turn_runner import TurnEvent
from skuggi.common.logs import get_logger
from skuggi.config.configs import ConfigError
from skuggi.research.graph import research_recursion_limit
from skuggi.research.state import ResearchState

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore

log = get_logger(__name__)

_NODE_STATUS = {
    "planner": "planning research tasks",
    "collector": "collecting",
    "verifier": "assembling profile",
    "respond": "done",
}


class ResearchRunner:
    """Runs the research graph for one session, yielding operator-facing events."""

    def __init__(self, core: AgentCore) -> None:
        """Hold a back-ref to the core; it owns the compiled research graph + saver."""
        self._core = core

    def _config(self) -> RunnableConfig:
        settings = self._core.settings
        return {
            "configurable": {"thread_id": f"research:{self._core.thread_id}"},
            "recursion_limit": research_recursion_limit(
                max_tasks=settings.research_max_tasks,
                max_replans=settings.research_max_replans,
            ),
        }

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
        initial: ResearchState = {
            "messages": [HumanMessage(content=request)],
            "request": request,
            "replan_count": 0,
            "max_replans": self._core.settings.research_max_replans,
        }
        log.info(
            "research run start thread=%s request=%r", self._core.thread_id, request
        )
        try:
            self._core.ensure_llm()
            stream: Iterator[Any] = self._core.research_graph.stream(
                initial, self._config(), stream_mode="updates"
            )
            for payload in stream:
                yield from self._updates(cast("dict[str, object]", payload))
        except ConfigError as e:
            log.warning("research run aborted on config error: %s", e)
            yield TurnEvent("status", str(e), node="error")
        except Exception as e:  # a bad run must not kill the loop
            log.exception("research run failed")
            yield TurnEvent("status", f"{type(e).__name__}: {e}", node="error")
        finally:
            log.info("research run done thread=%s", self._core.thread_id)

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
