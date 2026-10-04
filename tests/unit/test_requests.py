"""L1: the shared request seam -- history helpers + the structured-ask egress.

These pin the two properties the OSINT loop and the turn graph both rely on:
``ask`` scrubs the rendered request before the model ever sees it (the one egress
point), and it refuses to run without a configured model. The history helpers are
pure string work hoisted out of ``graph.py``; a couple of cases keep them covered
in their new home.
"""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from skuggi.agent.protocol import PlannerResponse
from skuggi.agent.requests import ask, last_user_text, prior_turns, render_history
from skuggi.security.policy import RedactionPolicy
from tests.fakes import RoleScriptedChatModel

# A well-formed AWS access key id the deterministic detector masks regardless of
# the (empty) default allow-list -- so a leak into the prompt is unmistakable.
_SECRET = "AKIAIOSFODNN7EXAMPLE"


def test_ask_scrubs_the_request_before_the_model_sees_it() -> None:
    model = RoleScriptedChatModel(planner_replies=[PlannerResponse(steps=("go",))])
    out = ask(
        model,
        "You are the planner.",
        f"operator pasted a secret: {_SECRET} -- find it",
        PlannerResponse,
        policy=RedactionPolicy(),
        native=True,
    )
    assert isinstance(out, PlannerResponse)
    received = model.prompts_for("planner")[-1]
    assert _SECRET not in received  # scrubbed at the egress


def test_ask_without_a_model_raises() -> None:
    with pytest.raises(RuntimeError, match="no model provider configured"):
        ask(None, "sys", "hi", PlannerResponse, policy=RedactionPolicy(), native=True)


def test_last_user_text_takes_the_most_recent_human_message() -> None:
    msgs = [
        HumanMessage(content="first"),
        AIMessage(content="reply"),
        HumanMessage(content="second"),
    ]
    assert last_user_text(msgs) == "second"
    assert last_user_text([AIMessage(content="only assistant")]) == ""


def test_prior_turns_drops_the_trailing_human_request() -> None:
    msgs = [
        HumanMessage(content="q1"),
        AIMessage(content="a1"),
        HumanMessage(content="q2"),
    ]
    kept = prior_turns(msgs)
    assert [m.text for m in kept] == ["q1", "a1"]


def test_render_history_is_bounded_and_degenerate_budgets_are_empty() -> None:
    msgs = [HumanMessage(content="hello"), AIMessage(content="world")]
    assert render_history(msgs, max_messages=8, max_chars=4000) == (
        "user: hello\nassistant: world"
    )
    assert render_history(msgs, max_messages=0, max_chars=4000) == ""
    assert render_history(msgs, max_messages=8, max_chars=0) == ""
