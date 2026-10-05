"""The history compactor folds scrolled-out turns into a running summary (G3)."""

from __future__ import annotations

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage

from skuggi.agent.graph import GraphDeps, _compact_node
from skuggi.agent.protocol import SummaryResponse
from skuggi.agent.state import AgentState
from skuggi.security.policy import RedactionPolicy
from tests.fakes import StructuredChatModel


def _clean(text: str) -> str:
    return text


def _msgs(n: int) -> list[BaseMessage]:
    """``n`` completed turns followed by the new (unanswered) human turn."""
    out: list[BaseMessage] = []
    for i in range(n):
        out.append(HumanMessage(content=f"user {i}"))
        out.append(AIMessage(content=f"assistant {i}"))
    out.append(HumanMessage(content="newest question"))
    return out


def _deps(**kw: object) -> GraphDeps:
    kw.setdefault("history_messages", 2)
    return GraphDeps(
        llm=StructuredChatModel(obj=SummaryResponse(summary="rolled-up summary")),
        redaction_policy=RedactionPolicy(),
        native_structured=True,
        **kw,  # type: ignore[arg-type]
    )


def test_no_compaction_when_history_fits_the_window() -> None:
    # 1 completed turn = 2 prior messages, window of 2 -> nothing scrolled out.
    assert _compact_node({"messages": _msgs(1)}, _deps(), _clean) == {}


def test_compaction_folds_overflow_and_advances_the_marker() -> None:
    # 5 completed turns (10 messages), window 2 -> 8 messages overflow.
    update = _compact_node({"messages": _msgs(5)}, _deps(), _clean)
    assert update == {"summary": "rolled-up summary", "summary_len": 8}


def test_compaction_is_incremental() -> None:
    # Already folded through 8; the same history has no *new* overflow.
    state: AgentState = {"messages": _msgs(5), "summary": "old", "summary_len": 8}
    assert _compact_node(state, _deps(), _clean) == {}


def test_compaction_disabled_is_a_noop() -> None:
    assert (
        _compact_node({"messages": _msgs(5)}, _deps(compact_history=False), _clean)
        == {}
    )
