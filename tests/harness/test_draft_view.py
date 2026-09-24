"""L3: the turn event stream (core) and the Live pane (DraftView).

`stream_mode="messages"` emits every BaseMessage a node writes to state, not
just tokens, and each tool round is a separate LLM run. `AgentCore.turn` filters
that into reset/status/token/final events; `DraftView` renders them. Both facts
were observed on the real graph; this pins the consequences without a provider.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessageChunk, SystemMessage
from rich.console import Console
from rich.live import Live

from skuggi.core import AgentCore, TurnEvent
from skuggi.tui import DraftView
from tests.conftest import offline_settings, wire_offline_core


class _FakeGraph:
    """Replays a fixed (event, payload) stream, as langgraph would emit it."""

    def __init__(self, items: list[tuple[str, Any]]) -> None:
        self._items = items

    def stream(self, *_a: object, **_k: object) -> Iterator[tuple[str, Any]]:
        return iter(self._items)


def _core(tmp_path: Path) -> AgentCore:
    core = AgentCore(offline_settings(tmp_path))
    wire_offline_core(core)
    return core


def _worker(text: str, run_id: str) -> tuple[str, Any]:
    chunk = AIMessageChunk(content=text, id=run_id)
    return ("messages", (chunk, {"langgraph_node": "worker"}))


def test_turn_filters_the_stream_into_events(tmp_path: Path) -> None:
    core = _core(tmp_path)
    try:
        core.graph = _FakeGraph(  # type: ignore[assignment]
            [
                ("updates", {"planner": {"plan": "1. do"}}),
                _worker("Hel", "r1"),
                _worker("lo", "r1"),
                # A non-worker chunk and a non-chunk message are both ignored.
                (
                    "messages",
                    (
                        AIMessageChunk(content="x", id="rp"),
                        {"langgraph_node": "planner"},
                    ),
                ),
                (
                    "messages",
                    (
                        SystemMessage(content="You are the worker."),
                        {"langgraph_node": "worker"},
                    ),
                ),
                ("updates", {"retriever": {"context": "ctx"}}),
                ("updates", {"tools": {}}),
                _worker("answer", "r2"),
                ("updates", {"critic": {"critique": "APPROVED: ok"}}),
                ("updates", {"finalize": {"draft": "the final answer"}}),
            ]
        )
        events = list(core.turn("q"))
    finally:
        core.close()

    tokens = [e.text for e in events if e.kind == "token"]
    assert tokens == ["Hel", "lo", "answer"]
    finals = [e.text for e in events if e.kind == "final"]
    assert finals == ["the final answer"]
    statuses = {e.node for e in events if e.kind == "status"}
    assert {"planner", "retriever", "critic"} <= statuses
    # A reset precedes the first token of each run (id change) plus planner/tools.
    assert sum(1 for e in events if e.kind == "reset") >= 3


def test_turn_flattens_block_content(tmp_path: Path) -> None:
    core = _core(tmp_path)
    try:
        core.graph = _FakeGraph(  # type: ignore[assignment]
            [
                (
                    "messages",
                    (
                        AIMessageChunk(
                            content=[{"type": "text", "text": "blocky", "index": 0}],
                            id="r",
                        ),
                        {"langgraph_node": "worker"},
                    ),
                ),
            ]
        )
        tokens = [e.text for e in core.turn("q") if e.kind == "token"]
    finally:
        core.close()
    assert tokens == ["blocky"]


@pytest.fixture
def view() -> Iterator[DraftView]:
    console = Console(file=io.StringIO(), width=80)
    with Live("", console=console) as live:
        yield DraftView(live)


def test_draft_view_accumulates_and_resets(view: DraftView) -> None:
    view.push_text("Hel")
    view.push_text("lo")
    assert view.buffer == "Hello"
    view.reset()
    assert view.buffer == ""


def test_draft_view_show_is_authoritative(view: DraftView) -> None:
    view.push_text("streamed guess")
    view.show("the draft the critic judged")
    assert view.buffer == "the draft the critic judged"


def test_turn_event_defaults() -> None:
    assert TurnEvent("reset").text == ""
    assert TurnEvent("token", "x").node == ""
