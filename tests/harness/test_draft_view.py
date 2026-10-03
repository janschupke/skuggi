"""L3: the turn event stream (core) and the Live pane (DraftView).

Structured output is not token-streamed: ``AgentCore.turn`` streams langgraph in
``updates`` mode and maps each node's state update to events. Only the worker's
answer is operator-facing (a ``final`` event, bracketed by ``reset``); the
planner/retriever/executor/critic scaffolding is logged, not shown. ``DraftView``
renders those. Both facts were observed on the real graph; this pins the
consequences without a provider.
"""

from __future__ import annotations

import io
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console
from rich.live import Live

from skuggi.agent.core import AgentCore
from skuggi.agent.protocol import CommandBrief, WorkerResponse, render_response
from skuggi.agent.turn_runner import TurnEvent
from skuggi.frontend.tui import DraftView
from tests.conftest import offline_settings, wire_offline_core


class _FakeGraph:
    """Replays a fixed list of update payloads, as langgraph's updates stream does."""

    def __init__(self, items: list[dict[str, Any]]) -> None:
        self._items = items

    def stream(self, *_a: object, **_k: object) -> Iterator[dict[str, Any]]:
        return iter(self._items)


def _core(tmp_path: Path) -> AgentCore:
    core = AgentCore(offline_settings(tmp_path))
    wire_offline_core(core)
    return core


def test_turn_maps_node_updates_to_events(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    core = _core(tmp_path)
    worker = WorkerResponse(advice="the final answer")
    try:
        core.graph = _FakeGraph(  # type: ignore[assignment]
            [
                {"planner": {"plan": ["recon", "enumerate"]}},
                {"retriever": {"context": "ctx"}},
                {"worker": {"worker": worker, "draft": render_response(worker)}},
                {
                    "executor": {
                        "commands": [
                            CommandBrief(id=1, status="proposed", command="nmap x")
                        ]
                    }
                },
                {"critic": {"approved": True, "critique": "ok"}},
            ]
        )
        with caplog.at_level(logging.DEBUG, logger="skuggi.agent.turn_runner"):
            events = list(core.turn("q"))
    finally:
        core.close()

    # Only the worker's clean answer is operator-facing; a reset brackets the passes.
    assert [e.text for e in events if e.kind == "final"] == ["the final answer"]
    assert [e.kind for e in events][:3] == ["reset", "reset", "final"]
    scaffolding = {"planner", "retriever", "executor", "critic"}
    assert not [e for e in events if e.kind == "status" and e.node in scaffolding]
    # The scaffolding is logged instead of shown.
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "recon" in logged  # plan steps
    assert "nmap x" in logged  # executor command brief
    assert "approved=True" in logged  # critic verdict


def test_turn_reports_an_error_as_a_status_event(tmp_path: Path) -> None:
    core = _core(tmp_path)

    class _Boom:
        def stream(self, *_a: object, **_k: object) -> Iterator[dict[str, Any]]:
            msg = "kaboom"
            raise RuntimeError(msg)

    try:
        core.graph = _Boom()  # type: ignore[assignment]
        events = list(core.turn("q"))
    finally:
        core.close()

    errors = [e for e in events if e.node == "error"]
    assert errors
    assert "kaboom" in errors[0].text


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
