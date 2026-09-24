"""L4: does the agent loop actually work against a real model?

Run with:  make eval      (or: uv run pytest -m eval)

These cost money and are nondeterministic, so they assert properties and are
never part of `make check`.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from tests.eval.conftest import answer, require, tool_names

from skuggi.state import AgentState

pytestmark = [
    pytest.mark.eval,
    # Real provider SDKs keep pooled TLS connections alive past the test, which
    # the suite-wide -W error turns into a failure. Scoped to this layer only:
    # every offline layer keeps the strict setting.
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]

Runner = Callable[..., AgentState]


@pytest.mark.parametrize("provider", ["openai", "anthropic", "ollama", "chatgpt"])
def test_each_provider_completes_a_turn(run_turn: Runner, provider: str) -> None:
    settings = require(provider)  # type: ignore[arg-type]
    state = run_turn(settings, "Reply with a single word: ready")

    assert answer(state), f"{provider} produced no reply"
    assert state.get("critique"), "the critic should have judged the draft"


def test_worker_reaches_for_the_calculator(run_turn: Runner) -> None:
    """Arithmetic should go through the tool, not the model's own guess."""
    state = run_turn(require("openai"), "What is 17 * 23? Use the calculator tool.")

    assert "391" in answer(state)
    assert "calculator" in tool_names(state)


def test_retrieval_answers_from_an_ingested_document(run_turn: Runner) -> None:
    """The fact is not in any training set, so only retrieval can supply it."""
    state = run_turn(
        require("openai"),
        "According to the knowledge base, what is the skuggi mascot?",
        ingest="The skuggi mascot is a shadow badger named Kvistur.",
    )

    reply = answer(state)
    assert "badger" in reply or "kvistur" in reply
    assert "retrieve" in tool_names(state)


def test_conversation_memory_survives_a_follow_up(run_turn: Runner) -> None:
    """The fix for history: turn 2 has to resolve a reference from turn 1."""
    state = run_turn(
        require("openai"),
        "My favourite animal is the badger. Just acknowledge.",
        "What is my favourite animal?",
    )

    assert "badger" in answer(state)


def test_the_critic_loop_terminates_with_an_answer(run_turn: Runner) -> None:
    """The loop must always settle, whatever the critic says.

    Deliberately not asserting the critique matches APPROVED:/REVISE:. A real
    model drifts from an instructed output format often enough to make that
    flaky, and the graph already treats anything non-APPROVED as a revision
    request -- so the property worth pinning is that a turn ends with an answer
    and a spent-or-unspent budget, not the wording.
    """
    state = run_turn(
        require("openai"),
        "Answer in exactly three words, no more: what colour is the sky?",
        max_revisions=2,
    )

    assert answer(state), "every turn must produce a reply"
    assert state.get("critique"), "the critic must have run"
    assert 0 <= (state.get("revision_count") or 0) <= 2


@pytest.mark.parametrize("provider", ["openai", "chatgpt"])
def test_retrieval_reaches_providers_without_tool_support(
    run_turn: Runner, provider: str
) -> None:
    """Covers the inlined-context path, which chatgpt depends on entirely."""
    settings = require(provider)  # type: ignore[arg-type]
    state = run_turn(
        settings,
        "According to the knowledge base, who is the mascot?",
        ingest="The skuggi mascot is a shadow badger named Kvistur.",
    )

    reply = answer(state)
    assert "badger" in reply or "kvistur" in reply
    if not settings.supports_tools():
        assert state.get("context"), "context should be inlined for this provider"
