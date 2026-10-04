"""L3: the OSINT runner wired through a real AgentCore (no network).

Covers the core seams -- osint_turn's no-scope guard, the node->event translation,
and the exception path -- by swapping a fake compiled graph in, so nothing reaches
the LLM or the network. The full collector/scheduler path is covered at L2
(test_osint_graph).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage

from skuggi.agent.core import AgentCore
from skuggi.frontend.daemon import Daemon
from tests.support import engaged_core

_SCOPE_BASE: dict[str, object] = {
    "name": "osint-eng",
    "timezone": "UTC",
    "allowed_tools": ["nmap"],
    "allowed_methods": ["recon"],
}
_OSINT = {
    "domains": ["acme.com"],
    "enabled_sources": ["crtsh"],
    "passive_only": True,
    "autonomous_ceiling": "recon",
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


def _core(tmp_path: Path, *, with_osint: bool) -> AgentCore:
    scope = dict(_SCOPE_BASE)
    if with_osint:
        scope["osint"] = _OSINT
    core = engaged_core(tmp_path, scope)
    core.llm = _DummyLLM()  # type: ignore[assignment]  # ensure_llm returns it
    return core


class _DummyLLM:
    """A placeholder the core returns from ensure_llm; never invoked here."""


def test_osint_turn_refuses_without_a_scope(tmp_path: Path) -> None:
    core = _core(tmp_path, with_osint=False)
    events = list(core.osint_turn("map acme.com"))
    assert len(events) == 1
    assert events[0].node == "error"
    assert "no OSINT scope" in events[0].text


def test_osint_turn_translates_nodes_to_events(tmp_path: Path) -> None:
    core = _core(tmp_path, with_osint=True)
    core.osint_graph = _FakeGraph(  # type: ignore[assignment]
        [
            {"planner": {"plan": []}},
            {"collector": {"completed": ["t1"]}},
            {"respond": {"messages": [AIMessage(content="the footprint")]}},
        ]
    )
    events = list(core.osint_turn("map acme.com"))
    kinds = [(e.kind, e.node) for e in events]
    assert ("status", "planner") in kinds
    assert ("status", "collector") in kinds
    final = next(e for e in events if e.kind == "final")
    assert final.text == "the footprint"


def test_osint_turn_surfaces_an_error_instead_of_raising(tmp_path: Path) -> None:
    core = _core(tmp_path, with_osint=True)
    core.osint_graph = _FakeGraph(boom=True)  # type: ignore[assignment]
    events = list(core.osint_turn("map acme.com"))
    assert events[-1].node == "error"
    assert "RuntimeError" in events[-1].text


@pytest.mark.usefixtures("tmp_path")
def test_core_rebuilds_both_graphs(tmp_path: Path) -> None:
    core = _core(tmp_path, with_osint=True)
    first = core.osint_graph
    core.rebuild_graph()
    assert core.osint_graph is not first  # a fresh compile


def test_daemon_osint_streams_status_and_summary(tmp_path: Path) -> None:
    core = _core(tmp_path, with_osint=True)
    core.osint_graph = _FakeGraph(  # type: ignore[assignment]
        [
            {"planner": {"plan": []}},
            {"respond": {"messages": [AIMessage(content="the footprint")]}},
        ]
    )
    out = "".join(Daemon(core)._osint("map acme.com"))
    assert "(planner)" in out
    assert "the footprint" in out


def test_daemon_osint_usage_without_a_request(tmp_path: Path) -> None:
    core = _core(tmp_path, with_osint=True)
    assert "usage" in "".join(Daemon(core)._osint(""))


def test_daemon_osint_surfaces_the_no_scope_error(tmp_path: Path) -> None:
    core = _core(tmp_path, with_osint=False)
    out = "".join(Daemon(core)._osint("map acme.com"))
    assert "error" in out
    assert "no OSINT scope" in out
