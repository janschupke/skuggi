"""Drive one agentic sub-loop (OSINT / research / forensics) as ``TurnEvent``s.

The three non-turn loops share a streaming shape: open a per-loop checkpoint
namespace, stream the compiled graph, translate each superstep's ``{node: update}``
into a ``status`` event (or the ``respond`` node's answer into a ``final``), and
guarantee a bad run yields an error event rather than killing the front-end loop.
That body lived copied -- byte-identical ``_draft_of`` and ``_updates`` plus the
same error triad -- in three runners; it lives here once. Each runner keeps only
its own pre-flight checks (OSINT refuses without a scope, forensics without a case,
research warns without an engagement) and hands the stream to :func:`stream_loop`.

Timing is collected around the stream (audit A4): each ``ask`` in these loops now
records against the active collector, so a run's per-node LLM time is logged like a
chat turn's -- the loops were previously untimed and unlabeled.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableConfig

from skuggi.agent.turn_runner import TurnEvent
from skuggi.common.timing import collect_turn_timing
from skuggi.config.configs import ConfigError

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from logging import Logger

    from langgraph.graph.state import CompiledStateGraph

    from skuggi.agent.core import AgentCore


def stream_loop(  # noqa: PLR0913 -- the shared driver binds core+graph+namespace+limit+labels
    core: AgentCore,
    graph: CompiledStateGraph[Any],
    initial: Mapping[str, Any],
    *,
    thread_prefix: str,
    recursion_limit: int,
    node_status: Mapping[str, str],
    log: Logger,
) -> Iterator[TurnEvent]:
    """Stream a compiled loop graph, yielding operator-facing ``TurnEvent``s.

    ``thread_prefix`` namespaces the checkpoint (``osint:``/``research:``/
    ``forensics:``) so the loops never share a channel schema on one checkpoint.
    ``node_status`` maps each node to its one-line spinner label; ``respond`` is
    special-cased to the turn's ``final`` answer. A ``ConfigError`` (missing
    credential) and any other exception both degrade to a single error event.
    """
    config: RunnableConfig = {
        "configurable": {"thread_id": f"{thread_prefix}:{core.thread_id}"},
        "recursion_limit": recursion_limit,
    }
    log.info("%s run start thread=%s", thread_prefix, core.thread_id)
    try:
        core.ensure_llm()
        with collect_turn_timing() as timing:
            stream: Iterator[Any] = graph.stream(
                dict(initial), config, stream_mode="updates"
            )
            for payload in stream:
                for node, value in cast("dict[str, object]", payload).items():
                    if node == "respond":
                        yield TurnEvent("final", _draft_of(value), node="respond")
                    else:
                        yield TurnEvent(
                            "status", node_status.get(node, node), node=node
                        )
        _log_latency(log, thread_prefix, core.thread_id, timing)
    except ConfigError as e:
        log.warning("%s run aborted on config error: %s", thread_prefix, e)
        yield TurnEvent("status", str(e), node="error")
    except Exception as e:  # a bad run must not kill the front-end loop
        log.exception("%s run failed", thread_prefix)
        yield TurnEvent("status", f"{type(e).__name__}: {e}", node="error")
    finally:
        log.info("%s run done thread=%s", thread_prefix, core.thread_id)


def _log_latency(log: Logger, prefix: str, thread_id: str, timing: object) -> None:
    """Log a per-node latency line for a completed run (diagnostics only)."""
    calls = getattr(timing, "call_count", 0)
    if not calls:
        return
    by_node = ", ".join(
        f"{node} {secs:.1f}s"
        for node, secs in sorted(
            timing.by_node().items(),  # type: ignore[attr-defined]
            key=lambda kv: kv[1],
            reverse=True,
        )
    )
    log.info(
        "%s run latency thread=%s %.1fs llm, %d call(s) -- %s",
        prefix,
        thread_id,
        timing.llm_s,  # type: ignore[attr-defined]
        calls,
        by_node,
    )


def _draft_of(value: object) -> str:
    """The respond node's emitted answer text."""
    if isinstance(value, dict):
        messages = value.get("messages")
        if isinstance(messages, list) and messages:
            last = messages[-1]
            if isinstance(last, AIMessage):
                return str(last.text)
    return ""
