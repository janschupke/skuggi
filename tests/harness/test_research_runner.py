"""L3: the research runner wired through a real AgentCore (no network).

Covers the core seams -- research_turn's usage guard, the agent-only warning (it
must NOT refuse), the node->event translation, the exception path, and the output-
root resolution -- by swapping a fake compiled graph in, so nothing reaches the LLM
or the network. The full collector/scheduler path is covered at L2
(test_research_graph).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from langchain_core.messages import AIMessage

from skuggi.agent.core import AgentCore
from skuggi.config.config import Settings
from skuggi.frontend.daemon import Daemon
from tests.support import engaged_core

_SCOPE: dict[str, object] = {
    "name": "research-eng",
    "timezone": "UTC",
    "allowed_tools": ["nmap"],
    "allowed_methods": ["recon"],
}


class _FakeGraph:
    """A compiled-graph stand-in whose stream yields canned superstep payloads."""

    def __init__(
        self, payloads: list[dict[str, object]] | None = None, *, boom: bool = False
    ) -> None:
        self._payloads = payloads or []
        self._boom = boom

    def stream(
        self, _initial: Any, _config: Any, *, stream_mode: str
    ) -> Iterator[dict[str, object]]:
        if self._boom:
            msg = "stream exploded"
            raise RuntimeError(msg)
        yield from self._payloads


class _DummyLLM:
    """A placeholder the core returns from ensure_llm; never invoked here."""


def _engaged(tmp_path: Path) -> AgentCore:
    core = engaged_core(tmp_path, dict(_SCOPE))
    core.llm = _DummyLLM()  # type: ignore[assignment]
    return core


def _agent_only(tmp_path: Path) -> AgentCore:
    empty = tmp_path / "nowhere"  # no scope.json -> agent-only
    empty.mkdir()
    settings = Settings(
        provider="ollama",
        engagement_root=empty,
        sqlite_path=tmp_path / "sessions.db",
        faiss_path=tmp_path / "faiss",
        preferences_path=tmp_path / "preferences.db",
        layout_path=tmp_path / "layout.json",
        commands_path=tmp_path / "commands.json",
        managed_tools_dir=tmp_path / "toolbox",
    )
    core = AgentCore(settings)
    core.llm = _DummyLLM()  # type: ignore[assignment]
    return core


def test_research_turn_usage_without_a_request(tmp_path: Path) -> None:
    core = _engaged(tmp_path)
    events = list(core.research_turn("   "))
    assert len(events) == 1
    assert events[0].node == "error"
    assert "usage" in events[0].text


def test_research_turn_warns_but_runs_without_an_engagement(tmp_path: Path) -> None:
    core = _agent_only(tmp_path)
    assert core.engagement is None
    core.research_graph = _FakeGraph(  # type: ignore[assignment]
        [{"respond": {"messages": [AIMessage(content="the profile")]}}]
    )
    events = list(core.research_turn("wordpress"))
    # it does NOT refuse: a warning, then the real run
    assert any("./research" in e.text for e in events)
    final = next(e for e in events if e.kind == "final")
    assert final.text == "the profile"


def test_research_turn_no_warning_with_an_engagement(tmp_path: Path) -> None:
    core = _engaged(tmp_path)
    core.research_graph = _FakeGraph(  # type: ignore[assignment]
        [
            {"planner": {"plan": []}},
            {"collector": {"completed": ["t1"]}},
            {"respond": {"messages": [AIMessage(content="done")]}},
        ]
    )
    events = list(core.research_turn("jenkins"))
    assert not any("./research" in e.text for e in events)
    kinds = [(e.kind, e.node) for e in events]
    assert ("status", "planner") in kinds
    assert ("status", "collector") in kinds
    assert next(e for e in events if e.kind == "final").text == "done"


def test_research_turn_surfaces_an_error_instead_of_raising(tmp_path: Path) -> None:
    core = _engaged(tmp_path)
    core.research_graph = _FakeGraph(boom=True)  # type: ignore[assignment]
    events = list(core.research_turn("wordpress"))
    assert events[-1].node == "error"
    assert "RuntimeError" in events[-1].text


def test_output_root_is_workspace_research_dir_when_engaged(tmp_path: Path) -> None:
    core = _engaged(tmp_path)
    assert core._research_output_root() == core.workspace.research_dir  # type: ignore[union-attr]


def test_output_root_falls_back_to_cwd_research_agent_only(tmp_path: Path) -> None:
    core = _agent_only(tmp_path)
    assert core._research_output_root() == Path.cwd() / "research"


def test_core_rebuilds_the_research_graph(tmp_path: Path) -> None:
    core = _engaged(tmp_path)
    first = core.research_graph
    core.rebuild_graph()
    assert core.research_graph is not first


def test_daemon_research_streams_status_and_summary(tmp_path: Path) -> None:
    core = _engaged(tmp_path)
    core.research_graph = _FakeGraph(  # type: ignore[assignment]
        [
            {"planner": {"plan": []}},
            {"respond": {"messages": [AIMessage(content="the profile")]}},
        ]
    )
    out = "".join(Daemon(core)._research("wordpress"))
    assert "(planner)" in out
    assert "the profile" in out


def test_daemon_research_usage_without_a_request(tmp_path: Path) -> None:
    core = _engaged(tmp_path)
    assert "usage" in "".join(Daemon(core)._research(""))
