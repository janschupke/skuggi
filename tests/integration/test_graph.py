"""L2: the compiled graph, driven by a scripted model over a real checkpointer.

Real reducers, real SqliteSaver/InMemorySaver, real engagement guard + ledger --
only the LLM is fake, and it returns validated protocol objects per role. These
prove that the structured contract threads through: history and scope reach the
prompts, retrieval is inlined ahead of the worker, the worker <-> executor loop is
a genuine graph cycle, and the executor guards/records/runs the worker's command.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph.state import CompiledStateGraph

from skuggi.agent.graph import GraphDeps, build_graph, recursion_limit
from skuggi.agent.protocol import (
    CriticResponse,
    FindingDraft,
    PlannerResponse,
    WorkerResponse,
)
from skuggi.agent.state import AgentState
from skuggi.common.execution import CommandResult
from skuggi.engagement.engagement import EngagementConfig
from skuggi.persistence.ledger import Ledger, open_ledger
from skuggi.persistence.vectorstore import Store
from skuggi.tooling.registry import ToolRegistry, ToolSpec
from tests.fakes import RoleScriptedChatModel

CompiledGraph = CompiledStateGraph[AgentState]

_REGISTRY = ToolRegistry(
    tools=(
        ToolSpec(name="nmap", binary="nmap", method="scan"),
        ToolSpec(name="echo", binary="echo", method="recon", requires_target=False),
    )
)
_CLOCK = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def _engagement(*, autonomous: bool = False) -> EngagementConfig:
    return EngagementConfig.model_validate(
        {
            "name": "e",
            "timezone": "UTC",
            "authorized_start": datetime(2000, 1, 1, tzinfo=UTC),
            "authorized_end": datetime(2999, 1, 1, tzinfo=UTC),
            "target_networks": ("10.0.0.0/8",),
            "allowed_tools": frozenset({"nmap", "echo"}),
            "allowed_methods": frozenset({"scan", "recon"}),
            "autonomous": autonomous,
        }
    )


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with open_ledger(tmp_path / "ledger.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        yield led


def _turn(
    app: CompiledGraph, text: str, thread: str = "t1", **overrides: object
) -> AgentState:
    initial: AgentState = {
        "messages": [HumanMessage(content=text)],
        "revision_count": 0,
        "max_revisions": 2,
    }
    initial.update(overrides)  # type: ignore[typeddict-item]
    config: RunnableConfig = {
        "configurable": {"thread_id": thread},
        "recursion_limit": recursion_limit(max_revisions=4, max_command_rounds=4),
    }
    return cast("AgentState", app.invoke(initial, config))


def _app(model: RoleScriptedChatModel, **deps: object) -> CompiledGraph:
    return build_graph(GraphDeps(llm=model, **deps), InMemorySaver())  # type: ignore[arg-type]


def _pentest_app(
    model: RoleScriptedChatModel, ledger: Ledger, *, autonomous: bool = False
) -> CompiledGraph:
    return _app(
        model,
        engagement=_engagement(autonomous=autonomous),
        ledger=ledger,
        registry=_REGISTRY,
        session_id="s1",
        thread_id=lambda: "t1",
        clock=lambda: _CLOCK,
    )


# --- the revision loop ------------------------------------------------------


def test_approved_turn_records_exactly_one_answer() -> None:
    model = RoleScriptedChatModel(
        worker_replies=[WorkerResponse(summary="The answer is 391.")],
        critic_replies=[CriticResponse(approved=True, reason="correct")],
    )

    state = _turn(_app(model), "17*23?")

    assert "The answer is 391." in state["draft"]
    worker = state.get("worker")
    assert worker is not None
    assert worker.summary == "The answer is 391."
    assert [m.type for m in state["messages"]] == ["human", "ai"]
    assert "The answer is 391." in state["messages"][-1].text


def test_revision_replans_and_feeds_the_critique_back() -> None:
    """The point of the loop: the critic's complaint must reach the next planner."""
    model = RoleScriptedChatModel(
        worker_replies=[
            WorkerResponse(summary="too terse"),
            WorkerResponse(summary="a fuller answer"),
        ],
        critic_replies=[
            CriticResponse(approved=False, reason="add detail"),
            CriticResponse(approved=True, reason="better"),
        ],
    )

    state = _turn(_app(model), "explain")

    assert state["revision_count"] == 1
    planner_prompts = model.prompts_for("planner")
    assert len(planner_prompts) == 2
    assert "add detail" in planner_prompts[1]


def test_a_revised_turn_still_persists_only_one_answer() -> None:
    model = RoleScriptedChatModel(
        worker_replies=[WorkerResponse(summary="bad"), WorkerResponse(summary="good")],
        critic_replies=[
            CriticResponse(approved=False, reason="no"),
            CriticResponse(approved=True, reason="yes"),
        ],
    )

    state = _turn(_app(model), "q")

    assert [m.type for m in state["messages"]] == ["human", "ai"]
    assert "good" in state["messages"][-1].text


def test_max_revisions_cuts_the_loop_off() -> None:
    model = RoleScriptedChatModel(
        worker_replies=[WorkerResponse(summary="draft")],
        critic_replies=[CriticResponse(approved=False, reason="never happy")],
    )

    state = _turn(_app(model), "q", max_revisions=2)

    assert state["revision_count"] == 2
    assert len(model.prompts_for("planner")) == 3
    assert state["messages"][-1].type == "ai"


# --- phase advancement ------------------------------------------------------


def test_planner_advances_the_phase_forward_only() -> None:
    model = RoleScriptedChatModel(
        planner_replies=[PlannerResponse(advance_to="exploitation")],
        worker_replies=[WorkerResponse(summary="ok")],
        critic_replies=[CriticResponse(approved=True)],
    )

    state = _turn(_app(model), "go")

    # A jump from recon to exploitation is clamped to a single step.
    assert state["phase"] == "enumeration"


# --- the executor (command + findings) --------------------------------------


def test_command_is_recorded_proposed_without_executing(ledger: Ledger) -> None:
    model = RoleScriptedChatModel(
        worker_replies=[WorkerResponse(command="nmap 10.0.0.5", summary="scan")],
        critic_replies=[CriticResponse(approved=True)],
    )

    state = _turn(_pentest_app(model, ledger), "scan the host")

    assert [r.status for r in ledger.commands_for("s1")] == ["proposed"]
    assert state["commands"][-1].status == "proposed"
    assert "nmap 10.0.0.5" in state["draft"]


def test_out_of_scope_command_is_blocked_and_recorded(ledger: Ledger) -> None:
    model = RoleScriptedChatModel(
        worker_replies=[WorkerResponse(command="nmap 8.8.8.8", summary="scan")],
        critic_replies=[CriticResponse(approved=True)],
    )

    state = _turn(_pentest_app(model, ledger), "scan out of scope")

    assert [r.status for r in ledger.commands_for("s1")] == ["blocked"]
    assert state["commands"][-1].status == "blocked"


def test_autonomous_executes_and_loops_the_result_back(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(argv: Sequence[str], **_kwargs: object) -> CommandResult:
        now = datetime.now(UTC)
        return CommandResult(
            command=" ".join(argv),
            exit_code=0,
            stdout="22/tcp open",
            stderr="",
            started_at=now,
            finished_at=now,
        )

    monkeypatch.setattr("skuggi.common.execution.run", fake_run)
    model = RoleScriptedChatModel(
        worker_replies=[
            WorkerResponse(command="echo scan", summary="probe"),
            WorkerResponse(summary="done", done=True),
        ],
        critic_replies=[CriticResponse(approved=True)],
    )

    state = _turn(_pentest_app(model, ledger, autonomous=True), "probe it")

    assert state["command_rounds"] == 1
    assert state["commands"][-1].status == "executed"
    assert ledger.commands_for("s1")[-1].exit_code == 0
    # The executed command's output was fed back to the worker's second pass.
    assert "22/tcp open" in model.prompts_for("worker")[-1]


@pytest.mark.timeout(30)
def test_autonomous_loop_is_bounded(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A worker that always proposes a command must still terminate at the bound."""

    def fake_run(argv: Sequence[str], **_kwargs: object) -> CommandResult:
        now = datetime.now(UTC)
        return CommandResult(
            command=" ".join(argv),
            exit_code=0,
            stdout="ok",
            stderr="",
            started_at=now,
            finished_at=now,
        )

    monkeypatch.setattr("skuggi.common.execution.run", fake_run)
    model = RoleScriptedChatModel(
        worker_replies=[WorkerResponse(command="echo loop", summary="again")],
        critic_replies=[CriticResponse(approved=True)],
    )
    app = build_graph(
        GraphDeps(
            llm=model,
            engagement=_engagement(autonomous=True),
            ledger=ledger,
            registry=_REGISTRY,
            session_id="s1",
            thread_id=lambda: "t1",
            clock=lambda: _CLOCK,
            max_command_rounds=3,
        ),
        InMemorySaver(),
    )

    state = _turn(app, "loop forever")

    assert state["command_rounds"] == 3


def test_autonomous_holds_a_command_above_the_risk_ceiling(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An in-scope but destructive command is NOT auto-run under the default ceiling."""

    def must_not_run(*_a: object, **_k: object) -> CommandResult:
        pytest.fail("a command above the ceiling must not execute")

    monkeypatch.setattr("skuggi.common.execution.run", must_not_run)
    registry = ToolRegistry(
        tools=(
            ToolSpec(name="msf", binary="msf", method="exploit", requires_target=False),
        )
    )
    engagement = EngagementConfig.model_validate(
        {
            "name": "e",
            "timezone": "UTC",
            "authorized_start": datetime(2000, 1, 1, tzinfo=UTC),
            "authorized_end": datetime(2999, 1, 1, tzinfo=UTC),
            "target_networks": ("10.0.0.0/8",),
            "allowed_tools": frozenset({"msf"}),
            "allowed_methods": frozenset({"exploit"}),
            "autonomous": True,  # armed, but ceiling defaults to `active`
        }
    )
    model = RoleScriptedChatModel(
        worker_replies=[WorkerResponse(command="msf -q", summary="pop it")],
        critic_replies=[CriticResponse(approved=True)],
    )
    app = _app(
        model,
        engagement=engagement,
        ledger=ledger,
        registry=registry,
        session_id="s1",
        thread_id=lambda: "t1",
        clock=lambda: _CLOCK,
    )

    state = _turn(app, "exploit it")

    held = state["commands"][-1]
    assert held.status == "proposed"
    assert "destructive" in held.summary
    assert state["command_rounds"] == 0  # the worker<->executor loop did not run


def test_findings_are_recorded_from_the_worker_response(ledger: Ledger) -> None:
    model = RoleScriptedChatModel(
        worker_replies=[
            WorkerResponse(
                summary="found something",
                findings=(
                    FindingDraft(
                        title="open telnet",
                        severity="high",
                        description="23/tcp open",
                    ),
                ),
            )
        ],
        critic_replies=[CriticResponse(approved=True)],
    )

    _turn(_pentest_app(model, ledger), "look")

    findings = ledger.findings_for("s1")
    assert [f.title for f in findings] == ["open telnet"]
    assert findings[0].severity == "high"


# --- conversation history ---------------------------------------------------


def test_history_reaches_the_next_turn() -> None:
    model = RoleScriptedChatModel(
        worker_replies=[
            WorkerResponse(summary="Noted, Jan."),
            WorkerResponse(summary="Your name is Jan."),
        ],
        critic_replies=[CriticResponse(approved=True)],
    )
    app = _app(model)

    _turn(app, "my name is Jan", thread="mem")
    _turn(app, "what is my name?", thread="mem")

    second_worker_prompt = model.prompts_for("worker")[-1]
    assert "Jan" in second_worker_prompt
    assert "my name is Jan" in second_worker_prompt
    assert "Jan" in model.prompts_for("planner")[-1]


def test_history_excludes_worker_scaffolding() -> None:
    model = RoleScriptedChatModel(
        worker_replies=[WorkerResponse(summary="first"), WorkerResponse(summary="two")],
        critic_replies=[CriticResponse(approved=True)],
    )
    app = _app(model)

    _turn(app, "first", thread="clean")
    _turn(app, "second question", thread="clean")

    prompt = model.prompts_for("planner")[-1]
    assert "You are the worker" not in prompt


def test_history_is_bounded(store: Store, tmp_path: Path) -> None:
    model = RoleScriptedChatModel(
        worker_replies=[WorkerResponse(summary="a" * 200)],
        critic_replies=[CriticResponse(approved=True)],
    )
    app = _app(model, store=store, history_messages=2, history_chars=120)

    for i in range(4):
        _turn(app, f"question {i} " + "z" * 100, thread="long")

    prompt = model.prompts_for("planner")[-1]
    assert "question 0" not in prompt


# --- retrieval (inlined ahead of the worker, on every provider) -------------


def _ingest(store: Store, tmp_path: Path) -> None:
    doc = tmp_path / "kb.md"
    doc.write_text("The skuggi mascot is a shadow badger.", encoding="utf-8")
    store.ingest([doc])


def test_context_is_inlined_ahead_of_the_worker(store: Store, tmp_path: Path) -> None:
    _ingest(store, tmp_path)
    model = RoleScriptedChatModel(
        worker_replies=[WorkerResponse(summary="A shadow badger.")],
        critic_replies=[CriticResponse(approved=True)],
    )
    app = _app(model, store=store)

    state = _turn(app, "who is the mascot?")

    assert "shadow badger" in (state.get("context") or "")
    assert "shadow badger" in model.prompts_for("worker")[0]


def test_no_context_when_the_index_is_empty(store: Store) -> None:
    model = RoleScriptedChatModel(
        worker_replies=[WorkerResponse(summary="answer")],
        critic_replies=[CriticResponse(approved=True)],
    )
    app = _app(model, store=store)

    assert _turn(app, "anything").get("context") is None


def test_no_store_is_not_an_error() -> None:
    model = RoleScriptedChatModel(
        worker_replies=[WorkerResponse(summary="answer")],
        critic_replies=[CriticResponse(approved=True)],
    )
    assert "answer" in _turn(_app(model), "q")["draft"]


# --- topology ---------------------------------------------------------------


def test_declared_routes_match_the_real_edges() -> None:
    app = _app(RoleScriptedChatModel())

    drawn = app.get_graph().draw_mermaid()

    for node in ("planner", "retriever", "worker", "executor", "critic", "bump"):
        assert node in drawn
    assert "respond" in drawn


def test_there_is_no_tools_node() -> None:
    app = _app(RoleScriptedChatModel())
    assert "tools" not in app.get_graph().nodes
