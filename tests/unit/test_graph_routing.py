"""L1: the critic's routing decision, as a pure function."""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from skuggi.graph import last_user_text, prior_turns, render_history, route_after_critic
from skuggi.state import AgentState


def _state(**kwargs: object) -> AgentState:
    base: AgentState = {"messages": []}
    base.update(kwargs)  # type: ignore[typeddict-item]
    return base


@pytest.mark.parametrize(
    ("approved", "revisions", "budget", "expected"),
    [
        (True, 0, 2, "respond"),
        (False, 0, 2, "bump"),
        (False, 1, 2, "bump"),
        (False, 2, 2, "respond"),
        (False, 0, 0, "respond"),
        (None, 0, 2, "bump"),  # unset verdict is treated as "not approved"
    ],
)
def test_route_after_critic(
    approved: bool | None, revisions: int, budget: int, expected: str
) -> None:
    kwargs: dict[str, object] = {"revision_count": revisions, "max_revisions": budget}
    if approved is not None:
        kwargs["approved"] = approved
    state = _state(**kwargs)
    assert route_after_critic(state) == expected


def test_last_user_text_takes_the_most_recent() -> None:
    messages = [
        HumanMessage(content="first"),
        AIMessage(content="a"),
        HumanMessage(content="second"),
    ]
    assert last_user_text(messages) == "second"


def test_last_user_text_handles_block_content() -> None:
    """Anthropic and the Responses API return content as blocks, not a string."""
    messages = [HumanMessage(content=[{"type": "text", "text": "blocky"}])]
    assert last_user_text(messages) == "blocky"


def test_prior_turns_drops_the_current_request() -> None:
    messages = [
        HumanMessage(content="q1"),
        AIMessage(content="a1"),
        HumanMessage(content="q2 being answered now"),
    ]
    assert [m.text for m in prior_turns(messages)] == ["q1", "a1"]


def test_prior_turns_excludes_scaffolding() -> None:
    """System and tool messages must never reach a history block."""
    messages = [
        SystemMessage(content="worker system prompt"),
        HumanMessage(content="q"),
        ToolMessage(content="391", tool_call_id="c1"),
        AIMessage(content="a"),
    ]
    assert [m.type for m in prior_turns(messages)] == ["human", "ai"]


def test_render_history_respects_the_message_cap() -> None:
    messages = [HumanMessage(content=f"m{i}") for i in range(10)]
    rendered = render_history(messages, max_messages=3, max_chars=10_000)
    assert rendered.count("\n") == 2
    assert "m9" in rendered
    assert "m0" not in rendered


def test_render_history_drops_oldest_to_fit_the_char_budget() -> None:
    messages = [HumanMessage(content="x" * 100) for _ in range(5)]
    rendered = render_history(messages, max_messages=5, max_chars=250)
    assert len(rendered) <= 250
    assert rendered.count("user:") < 5


def test_render_history_keeps_one_message_even_if_oversized() -> None:
    rendered = render_history(
        [HumanMessage(content="y" * 500)], max_messages=5, max_chars=10
    )
    assert "y" in rendered


def test_render_history_empty() -> None:
    assert render_history([], max_messages=5, max_chars=100) == ""
