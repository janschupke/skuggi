"""L3: the streaming pane, fed the event shapes the graph really emits.

`stream_mode="messages"` emits every BaseMessage a node writes to state, not just
tokens, and each tool round is a separate LLM run. Both facts were observed on
the real graph; this pins the rendering consequences.
"""

from __future__ import annotations

import io

import pytest
from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    HumanMessage,
    SystemMessage,
)
from rich.console import Console
from rich.live import Live

from skuggi.tui import DraftView


@pytest.fixture
def view() -> DraftView:
    console = Console(file=io.StringIO(), width=80)
    with Live("", console=console) as live:
        yield DraftView(live)


def _chunks(run_id: str, *pieces: str) -> list[AIMessageChunk]:
    return [AIMessageChunk(content=piece, id=run_id) for piece in pieces]


def test_tokens_accumulate(view: DraftView) -> None:
    for chunk in _chunks("run-1", "Hel", "lo"):
        view.push(chunk, "worker")
    assert view.buffer == "Hello"


def test_state_writes_are_not_rendered(view: DraftView) -> None:
    """The worker writes its own system prompt and seed into state.

    Those arrive on the messages stream as concrete messages, so without the
    AIMessageChunk guard they would be spliced into the visible answer.
    """
    view.push(SystemMessage(content="You are the worker."), "worker")
    view.push(HumanMessage(content="Request:\nsecret plan"), "worker")
    view.push(AIMessage(content="a full state write"), "worker")

    assert view.buffer == ""


def test_other_nodes_are_ignored(view: DraftView) -> None:
    for chunk in _chunks("run-p", "planning..."):
        view.push(chunk, "planner")
    assert view.buffer == ""


def test_preamble_before_a_tool_call_is_dropped(view: DraftView) -> None:
    """Round 1's narration must not be concatenated with round 2's answer.

    A model that says "Let me compute that." before calling a tool would
    otherwise leave that text glued to the front of the real reply.
    """
    for chunk in _chunks("run-1", "Let me ", "compute that."):
        view.push(chunk, "worker")
    for chunk in _chunks("run-2", "The answer ", "is 391."):
        view.push(chunk, "worker")

    assert view.buffer == "The answer is 391."


def test_explicit_reset_clears_the_buffer(view: DraftView) -> None:
    for chunk in _chunks("run-1", "partial"):
        view.push(chunk, "worker")
    view.reset()
    assert view.buffer == ""


def test_show_makes_the_finalized_draft_authoritative(view: DraftView) -> None:
    for chunk in _chunks("run-1", "streamed guess"):
        view.push(chunk, "worker")
    view.show("the draft the critic judged")
    assert view.buffer == "the draft the critic judged"


def test_block_content_is_flattened(view: DraftView) -> None:
    """Responses-API and Anthropic chunks carry content blocks, not strings."""
    view.push(
        AIMessageChunk(content=[{"type": "text", "text": "blocky", "index": 0}], id="r"),
        "worker",
    )
    assert view.buffer == "blocky"
