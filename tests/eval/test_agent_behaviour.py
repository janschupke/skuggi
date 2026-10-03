"""L4: does the agent loop actually work against a real model?

Run with:  make eval      (or: uv run pytest -m eval)

These cost money and are nondeterministic, so they assert properties and are
never part of `make check`. Every node now returns a validated structured
response (skuggi.protocol), so the properties checked are that a turn produces an
answer, that the critic ran, that conversation memory survives, and that the
inlined-retrieval path reaches the answer on every provider.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from skuggi.agent.state import AgentState
from tests.eval.conftest import answer, require

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
    # Name a target so the deterministic backstop forces the full pipeline on every
    # provider, however the planner triages -- which is what makes the critic run.
    state = run_turn(settings, "What is a sensible first recon step for 10.0.0.5?")

    assert answer(state), f"{provider} produced no reply"
    # The critic's structured verdict must have run.
    assert state.get("approved") is not None, "the critic should have judged the draft"


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_a_conversational_turn_is_answered_directly(
    run_turn: Runner, provider: str
) -> None:
    """The latency fix: an identity question is answered in one call, no pipeline."""
    settings = require(provider)  # type: ignore[arg-type]
    state = run_turn(settings, "Who are you?")

    assert answer(state), f"{provider} produced no reply"
    # A direct answer never reaches the critic, so there is no verdict.
    assert state.get("approved") is None, "a direct answer must skip the critic"


def test_conversation_memory_survives_a_follow_up(run_turn: Runner) -> None:
    """The fix for history: turn 2 has to resolve a reference from turn 1."""
    state = run_turn(
        require("openai"),
        "My favourite animal is the badger. Just acknowledge.",
        "What is my favourite animal?",
    )

    assert "badger" in answer(state)


def test_the_critic_loop_terminates_with_an_answer(run_turn: Runner) -> None:
    """The loop must always settle, whatever the critic says."""
    state = run_turn(
        require("openai"),
        "In exactly three words, give a first recon step for 10.0.0.5.",
        max_revisions=2,
    )

    assert answer(state), "every turn must produce a reply"
    assert state.get("approved") is not None, "the critic must have run"
    assert 0 <= (state.get("revision_count") or 0) <= 2


@pytest.mark.parametrize("provider", ["openai", "chatgpt"])
def test_retrieval_reaches_every_provider(run_turn: Runner, provider: str) -> None:
    """Retrieval is inlined ahead of the worker on every provider now."""
    settings = require(provider)  # type: ignore[arg-type]
    state = run_turn(
        settings,
        "According to the knowledge base, who is the mascot?",
        ingest="The skuggi mascot is a shadow badger named Kvistur.",
    )

    reply = answer(state)
    assert "badger" in reply or "kvistur" in reply
    assert state.get("context"), "context should be inlined for this provider"
