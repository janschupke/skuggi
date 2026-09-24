"""L2: the compiled graph, driven by a scripted model over a real checkpointer.

Real ToolNode, real reducers, real SqliteSaver/InMemorySaver -- only the LLM is
fake. These are the tests that prove conversation history reaches the prompts,
that retrieval works on a provider that cannot call tools, and that the tool
loop is a genuine graph cycle.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph.state import CompiledStateGraph

from skuggi.graph import GraphDeps, build_graph, recursion_limit
from skuggi.state import AgentState
from skuggi.tools import build_tools
from skuggi.vectorstore import Store
from tests.fakes import RoleScriptedChatModel

CompiledGraph = CompiledStateGraph[AgentState]

TOOL_CALL = AIMessage(
    content="",
    id="w-tool",
    tool_calls=[
        {"name": "calculator", "args": {"expression": "17*23"}, "id": "call-1"}
    ],
)


def _turn(
    app: CompiledGraph, text: str, thread: str = "t1", **overrides: object
) -> AgentState:
    initial: AgentState = {
        "messages": [HumanMessage(content=text)],
        "scratch": [],
        "revision_count": 0,
        "max_revisions": 2,
        "tool_rounds": 0,
    }
    initial.update(overrides)  # type: ignore[typeddict-item]
    config: RunnableConfig = {
        "configurable": {"thread_id": thread},
        "recursion_limit": recursion_limit(max_revisions=4, max_tool_rounds=4),
    }
    return cast("AgentState", app.invoke(initial, config))


def _app(model: RoleScriptedChatModel, **deps: Any) -> CompiledGraph:
    return build_graph(GraphDeps(llm=model, **deps), InMemorySaver())


# --- the revision loop ------------------------------------------------------


def test_approved_turn_records_exactly_one_answer() -> None:
    model = RoleScriptedChatModel(
        worker_replies=["The answer is 391."], critic_replies=["APPROVED: correct"]
    )

    state = _turn(_app(model), "17*23?")

    assert state["draft"] == "The answer is 391."
    assert [(m.type, m.text) for m in state["messages"]] == [
        ("human", "17*23?"),
        ("ai", "The answer is 391."),
    ]


def test_revision_replans_and_feeds_the_critique_back() -> None:
    """The point of the loop: the critic's complaint must reach the next planner."""
    model = RoleScriptedChatModel(
        worker_replies=["too terse", "a fuller answer"],
        critic_replies=["REVISE: add detail", "APPROVED: better"],
    )

    state = _turn(_app(model), "explain")

    assert state["revision_count"] == 1
    planner_prompts = model.prompts_for("planner")
    assert len(planner_prompts) == 2
    assert "add detail" in planner_prompts[1]


def test_a_revised_turn_still_persists_only_one_draft() -> None:
    """The rejected draft must not linger in the visible conversation."""
    model = RoleScriptedChatModel(
        worker_replies=["bad", "good"],
        critic_replies=["REVISE: no", "APPROVED: yes"],
    )

    state = _turn(_app(model), "q")

    assert [m.text for m in state["messages"]] == ["q", "good"]


def test_max_revisions_cuts_the_loop_off() -> None:
    model = RoleScriptedChatModel(
        worker_replies=["draft"], critic_replies=["REVISE: never happy"]
    )

    state = _turn(_app(model), "q", max_revisions=2)

    assert state["revision_count"] == 2
    assert len(model.prompts_for("planner")) == 3
    assert state["messages"][-1].type == "ai"


# --- the tool cycle ---------------------------------------------------------


def test_tool_call_is_a_real_graph_cycle(store: Store, tmp_path: Path) -> None:
    """The intermediate messages must be checkpointed, not held in a local list."""
    model = RoleScriptedChatModel(
        worker_replies=[TOOL_CALL, "The answer is 391."],
        critic_replies=["APPROVED: ok"],
    )
    app = _app(model, tools=build_tools(store, root=tmp_path), store=store)

    state = _turn(app, "17*23?")

    assert state["draft"] == "The answer is 391."
    assert state["tool_rounds"] == 1
    kinds = [m.type for m in state["scratch"]]
    assert kinds == ["system", "human", "ai", "tool", "ai"]
    assert any(m.type == "tool" and m.text == "391" for m in state["scratch"])
    assert [m.text for m in state["messages"]] == ["17*23?", "The answer is 391."]


@pytest.mark.timeout(30)
def test_tool_loop_is_bounded(store: Store, tmp_path: Path) -> None:
    """A model that always calls a tool must still terminate."""
    model = RoleScriptedChatModel(
        worker_replies=[TOOL_CALL], critic_replies=["APPROVED: ok"]
    )
    app = _app(
        model, tools=build_tools(store, root=tmp_path), store=store, max_tool_rounds=3
    )

    state = _turn(app, "loop forever")

    assert state["tool_rounds"] == 3
    assert state["draft"], "a draft is still produced when the budget runs out"


def test_scratch_is_reset_between_turns(store: Store, tmp_path: Path) -> None:
    """Passing an empty list cannot clear a reducer channel; the sentinel does.

    add_messages(old, []) returns old, so without the explicit reset a stale
    working set survives into the next turn.
    """
    model = RoleScriptedChatModel(
        worker_replies=["first answer", "second answer"],
        critic_replies=["APPROVED: ok"],
    )
    app = _app(model, tools=build_tools(store, root=tmp_path), store=store)

    _turn(app, "first question", thread="shared")
    state = _turn(app, "second question", thread="shared")

    seeded = [m for m in state["scratch"] if m.type == "human"]
    assert len(seeded) == 1, "scratch should hold only this pass's seed"
    assert "second question" in seeded[0].text
    # Exactly one assistant reply for this pass: turn 1's scratch entries are gone.
    # (The seed legitimately quotes turn 1 inside its history block -- that is the
    # conversation-memory feature, not leftover scratch.)
    assert [m.type for m in state["scratch"]] == ["system", "human", "ai"]
    assert state["scratch"][-1].text == "second answer"


# --- conversation history (the fix) ----------------------------------------


def test_history_reaches_the_next_turn(store: Store, tmp_path: Path) -> None:
    """Multi-turn memory was display-only: persisted, restored, then ignored."""
    model = RoleScriptedChatModel(
        worker_replies=["Noted, Jan.", "Your name is Jan."],
        critic_replies=["APPROVED: ok"],
    )
    app = _app(model, tools=build_tools(store, root=tmp_path), store=store)

    _turn(app, "my name is Jan", thread="mem")
    _turn(app, "what is my name?", thread="mem")

    second_worker_prompt = model.prompts_for("worker")[-1]
    assert "Jan" in second_worker_prompt
    assert "my name is Jan" in second_worker_prompt
    assert "Jan" in model.prompts_for("planner")[-1]


def test_history_excludes_worker_scaffolding(store: Store, tmp_path: Path) -> None:
    model = RoleScriptedChatModel(
        worker_replies=[TOOL_CALL, "391", "second"], critic_replies=["APPROVED: ok"]
    )
    app = _app(model, tools=build_tools(store, root=tmp_path), store=store)

    _turn(app, "first", thread="clean")
    _turn(app, "second question", thread="clean")

    prompt = model.prompts_for("planner")[-1]
    assert "You are the worker" not in prompt
    assert "Retrieved context" not in prompt


def test_history_is_bounded(store: Store, tmp_path: Path) -> None:
    model = RoleScriptedChatModel(
        worker_replies=["a" * 200], critic_replies=["APPROVED: ok"]
    )
    app = _app(
        model,
        tools=build_tools(store, root=tmp_path),
        store=store,
        history_messages=2,
        history_chars=120,
    )

    for i in range(4):
        _turn(app, f"question {i} " + "z" * 100, thread="long")

    prompt = model.prompts_for("planner")[-1]
    assert "question 0" not in prompt


# --- retrieval on a provider that cannot bind tools ------------------------


def _ingest(store: Store, tmp_path: Path) -> None:
    doc = tmp_path / "kb.md"
    doc.write_text("The skuggi mascot is a shadow badger.", encoding="utf-8")
    store.ingest([doc])


def test_context_is_inlined_when_tools_are_unavailable(
    store: Store, tmp_path: Path
) -> None:
    """The chatgpt path: /ingest was silently inert because this did not exist."""
    _ingest(store, tmp_path)
    model = RoleScriptedChatModel(
        worker_replies=["A shadow badger."], critic_replies=["APPROVED: ok"]
    )
    app = _app(model, store=store, bind_tools=False)

    state = _turn(app, "who is the mascot?")

    assert "shadow badger" in (state.get("context") or "")
    assert "shadow badger" in model.prompts_for("worker")[0]


def test_no_context_when_tools_are_bound(store: Store, tmp_path: Path) -> None:
    """Tool-capable providers use the retrieve tool; inlining would duplicate it."""
    _ingest(store, tmp_path)
    model = RoleScriptedChatModel(
        worker_replies=["answer"], critic_replies=["APPROVED: ok"]
    )
    app = _app(model, tools=build_tools(store, root=tmp_path), store=store)

    state = _turn(app, "who is the mascot?")

    assert state.get("context") is None


def test_no_context_when_the_index_is_empty(store: Store) -> None:
    model = RoleScriptedChatModel(
        worker_replies=["answer"], critic_replies=["APPROVED: ok"]
    )
    app = _app(model, store=store, bind_tools=False)

    assert _turn(app, "anything").get("context") is None


def test_no_store_is_not_an_error() -> None:
    model = RoleScriptedChatModel(
        worker_replies=["answer"], critic_replies=["APPROVED: ok"]
    )
    assert _turn(_app(model, bind_tools=False), "q")["draft"] == "answer"


# --- topology ---------------------------------------------------------------


def test_declared_routes_match_the_real_edges(store: Store, tmp_path: Path) -> None:
    """The old router declared Literal["planner", "__end__"] and returned neither.

    Drawing the graph uses the annotation, so an honest router and the drawn
    edges must agree.
    """
    model = RoleScriptedChatModel()
    app = _app(model, tools=build_tools(store, root=tmp_path), store=store)

    drawn = app.get_graph().draw_mermaid()

    for edge in ("critic", "bump", "respond", "tools", "worker", "retriever"):
        assert edge in drawn
    assert "planner" in drawn


def test_no_tools_node_without_tool_support(store: Store) -> None:
    model = RoleScriptedChatModel()
    app = _app(model, store=store, bind_tools=False)
    assert "tools" not in app.get_graph().nodes
