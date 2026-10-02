"""L3: harness memory through AgentCore -- manual edits, injection, auto-capture.

The store itself is exercised in tests/integration/test_preferences.py; here the
concern is the core's behavior: preferences reaching the prompt, the manual
edit API rebuilding the graph, and the post-turn automatic capture (gate + LLM
extraction), all offline.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from skuggi.core import AgentCore
from skuggi.preferences import PreferenceRow
from skuggi.protocol import MemoryExtraction
from tests.conftest import offline_settings, wire_offline_core
from tests.fakes import StructuredChatModel


@pytest.fixture
def core(tmp_path: Path, pentest_configs: Callable[..., Path]) -> Iterator[AgentCore]:
    pentest_configs()
    built = AgentCore(offline_settings(tmp_path, engagement="test-eng"))
    wire_offline_core(built)
    yield built
    built.close()


# --- manual edits -----------------------------------------------------------


def test_add_list_forget_clear_rebuild_the_graph(core: AgentCore) -> None:
    before = core.graph
    row = core.add_preference("Prefer ffuf over gobuster")
    assert row is not None
    assert row.source == "manual"
    assert core.graph is not before, "adding a preference must rebuild the graph"
    assert [r.text for r in core.list_preferences()] == ["Prefer ffuf over gobuster"]

    assert core.add_preference("prefer FFUF over gobuster") is None  # duplicate
    assert len(core.list_preferences()) == 1

    assert core.forget_preference(row.id) is True
    assert core.list_preferences() == []
    assert core.forget_preference(row.id) is False  # already gone

    core.add_preference("keep answers terse")
    assert core.clear_preferences() == 1
    assert core.list_preferences() == []


def test_a_remembered_preference_reaches_the_worker_prompt(core: AgentCore) -> None:
    core.add_preference("Prefer ffuf over gobuster")
    list(core.turn("what is exposed?"))  # not a directive -> no auto-capture noise
    # core.llm is wired to the offline role-scripted fake; read it through a cast
    worker_prompt = cast("Any", core.llm).prompts_for("worker")[-1]
    assert "Operator preferences" in worker_prompt
    assert "Prefer ffuf over gobuster" in worker_prompt


# --- automatic capture ------------------------------------------------------


def test_capture_extracts_and_persists_a_directive(core: AgentCore) -> None:
    core.llm = cast(
        Any,
        StructuredChatModel(
            obj=MemoryExtraction(directives=("Prefer ffuf over gobuster",))
        ),
    )
    before = core.graph

    rows = core.maybe_capture_preferences("always prefer ffuf over gobuster")

    assert [r.text for r in rows] == ["Prefer ffuf over gobuster"]
    assert rows[0].source == "auto"
    assert [r.text for r in core.list_preferences()] == ["Prefer ffuf over gobuster"]
    assert core.graph is not before, "a capture must rebuild the graph"


def test_capture_gate_skips_ordinary_requests(core: AgentCore) -> None:
    class _NoLLM:
        def invoke(self, _prompt: object) -> object:
            msg = "the extractor must not run on a non-directive"
            raise AssertionError(msg)

    core.llm = cast(Any, _NoLLM())
    assert core.maybe_capture_preferences("what is exposed on the host?") == []
    assert core.list_preferences() == []


def test_capture_respects_the_memory_auto_switch(core: AgentCore) -> None:
    core.settings = core.settings.model_copy(update={"memory_auto": False})

    class _NoLLM:
        def invoke(self, _prompt: object) -> object:
            msg = "capture is off; the extractor must not run"
            raise AssertionError(msg)

    core.llm = cast(Any, _NoLLM())
    assert core.maybe_capture_preferences("always prefer ffuf") == []


def test_capture_empty_extraction_stores_nothing(core: AgentCore) -> None:
    core.llm = cast(Any, StructuredChatModel(obj=MemoryExtraction(directives=())))
    assert core.maybe_capture_preferences("from now on, hmm, never mind") == []
    assert core.list_preferences() == []


def test_turn_announces_a_captured_preference(
    core: AgentCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = PreferenceRow(3, "general", "Keep answers terse", "auto", "2026-01-01")
    monkeypatch.setattr(core, "maybe_capture_preferences", lambda _text: [row])
    events = list(core.turn("from now on keep answers terse"))
    memory = [e for e in events if e.node == "memory"]
    assert memory
    assert "remembered: Keep answers terse" in memory[0].text
    assert "forget 3" in memory[0].text
