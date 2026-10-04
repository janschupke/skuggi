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

from skuggi.agent.core import AgentCore
from skuggi.agent.protocol import MemoryExtraction
from tests.conftest import offline_settings, wire_offline_core
from tests.fakes import StructuredChatModel


@pytest.fixture
def core(tmp_path: Path, pentest_configs: Callable[..., Path]) -> Iterator[AgentCore]:
    pentest_configs()
    built = AgentCore(offline_settings(tmp_path))
    wire_offline_core(built)
    yield built
    built.close()


# --- manual edits -----------------------------------------------------------


def test_add_list_forget_clear_rebuild_the_graph(core: AgentCore) -> None:
    before = core.graph
    row = core.memory.add("Prefer ffuf over gobuster")
    assert row is not None
    assert row.source == "manual"
    assert core.graph is not before, "adding a preference must rebuild the graph"
    assert [r.text for r in core.memory.entries()] == ["Prefer ffuf over gobuster"]

    assert core.memory.add("prefer FFUF over gobuster") is None  # duplicate
    assert len(core.memory.entries()) == 1

    assert core.memory.forget(row.id) is True
    assert core.memory.entries() == []
    assert core.memory.forget(row.id) is False  # already gone

    core.memory.add("keep answers terse")
    assert core.memory.clear() == 1
    assert core.memory.entries() == []


def test_a_remembered_preference_reaches_the_worker_prompt(core: AgentCore) -> None:
    core.memory.add("Prefer ffuf over gobuster")
    list(core.turn("what is exposed?"))  # not a directive -> no auto-capture noise
    # core.llm is wired to the offline role-scripted fake; read it through a cast
    worker_prompt = cast("Any", core.llm).prompts_for("worker")[-1]
    assert "Operator preferences" in worker_prompt
    assert "Prefer ffuf over gobuster" in worker_prompt


# --- automatic capture: the evaluator proposes, the gate writes --------------


def test_propose_capture_extracts_without_persisting(core: AgentCore) -> None:
    core.llm = cast(
        Any,
        StructuredChatModel(
            obj=MemoryExtraction(directives=("Prefer ffuf over gobuster",))
        ),
    )
    before = core.graph

    candidates = core.memory.propose_capture("always prefer ffuf over gobuster")

    assert candidates == ["Prefer ffuf over gobuster"]
    # Proposing never writes or rebuilds -- that is the gated apply's job.
    assert core.memory.entries() == []
    assert core.graph is before


def test_apply_capture_persists_and_rebuilds(core: AgentCore) -> None:
    before = core.graph
    summary = core.memory.apply_capture(["Prefer ffuf over gobuster"])

    assert "remembered" in summary
    rows = core.memory.entries()
    assert [r.text for r in rows] == ["Prefer ffuf over gobuster"]
    assert rows[0].source == "auto"
    assert core.graph is not before, "an applied capture must rebuild the graph"


def test_propose_capture_dedups_restated_candidates(core: AgentCore) -> None:
    core.llm = cast(
        Any,
        StructuredChatModel(
            obj=MemoryExtraction(directives=("Prefer ffuf", "prefer FFUF", ""))
        ),
    )
    assert core.memory.propose_capture("always prefer ffuf") == ["Prefer ffuf"]


def test_capture_gate_skips_ordinary_requests(core: AgentCore) -> None:
    class _NoLLM:
        def invoke(self, _prompt: object) -> object:
            msg = "the extractor must not run on a non-directive"
            raise AssertionError(msg)

    core.llm = cast(Any, _NoLLM())
    assert core.memory.propose_capture("what is exposed on the host?") == []
    assert core.memory.entries() == []


def test_capture_respects_the_memory_auto_switch(core: AgentCore) -> None:
    core.settings = core.settings.model_copy(update={"memory_auto": False})

    class _NoLLM:
        def invoke(self, _prompt: object) -> object:
            msg = "capture is off; the extractor must not run"
            raise AssertionError(msg)

    core.llm = cast(Any, _NoLLM())
    assert core.memory.propose_capture("always prefer ffuf") == []


def test_propose_capture_empty_extraction_yields_nothing(core: AgentCore) -> None:
    core.llm = cast(Any, StructuredChatModel(obj=MemoryExtraction(directives=())))
    assert core.memory.propose_capture("from now on, hmm, never mind") == []
    assert core.memory.entries() == []


def test_propose_capture_without_a_model_yields_nothing(core: AgentCore) -> None:
    core.llm = None
    assert core.memory.propose_capture("always prefer ffuf") == []


def test_propose_capture_swallows_extraction_errors(
    core: AgentCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> object:
        msg = "provider blew up"
        raise RuntimeError(msg)

    core.llm = cast(Any, StructuredChatModel(obj=MemoryExtraction(directives=())))
    monkeypatch.setattr("skuggi.agent.preferencebook.structured_invoke", boom)
    # A failed extraction must not break the turn -- it captures nothing.
    assert core.memory.propose_capture("always prefer ffuf") == []


def test_apply_capture_reports_nothing_new_for_blank_candidates(
    core: AgentCore,
) -> None:
    assert core.memory.apply_capture(["", "   "]) == "nothing new to remember"
    assert core.memory.entries() == []


def test_apply_capture_refuses_at_capacity_without_evicting(core: AgentCore) -> None:
    core.settings = core.settings.model_copy(update={"memory_max": 2})
    core.memory.add("Prefer ffuf over gobuster")  # one manual preference -> count 1

    summary = core.memory.apply_capture(["Keep answers terse", "Write scripts in Go"])

    # The cap is 2: the first fits (count 1 -> 2), the second is refused, not evicted.
    texts = [r.text for r in core.memory.entries()]
    assert "Keep answers terse" in texts
    assert "Write scripts in Go" not in texts
    assert "Prefer ffuf over gobuster" in texts, "nothing is evicted to make room"
    assert "remembered" in summary
    assert "capacity" in summary
    assert "Write scripts in Go" in summary


def test_turn_does_not_auto_write_memory(core: AgentCore) -> None:
    """The turn loop never writes memory; the front-end gates the capture post-turn."""
    core.llm = cast(
        Any,
        StructuredChatModel(
            obj=MemoryExtraction(directives=("Prefer ffuf over gobuster",))
        ),
    )
    events = list(core.turn("from now on prefer ffuf over gobuster"))

    assert [e for e in events if e.node == "memory"] == []
    assert core.memory.entries() == [], "a turn alone must not persist a preference"
