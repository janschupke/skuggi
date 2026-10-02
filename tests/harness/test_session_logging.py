"""L3: session logging, retrieval, replay and the private review, via AgentCore.

The engagement timeline (prompts, responses, commands, findings) and the
separate harness-interaction audit log (control verbs, CLI noise, reviews) are
exercised through the headless core, offline.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from skuggi.agent.core import AgentCore
from skuggi.agent.protocol import CriticResponse, WorkerResponse
from skuggi.frontend.commands import CommandAlias, CommandRegistry
from skuggi.providers import providers
from tests.conftest import offline_settings, wire_offline_core
from tests.fakes import RoleScriptedChatModel, ScriptedChatModel


@pytest.fixture
def core(tmp_path: Path, pentest_configs: Callable[..., Path]) -> Iterator[AgentCore]:
    pentest_configs()
    built = AgentCore(offline_settings(tmp_path, engagement="test-eng"))
    wire_offline_core(built)
    yield built
    built.close()


# --- the engagement timeline ------------------------------------------------


def test_turn_records_prompt_and_response_events(core: AgentCore) -> None:
    list(core.turn("what is exposed?"))
    kinds = [e.kind for e in core.ledger.events_for(core.session_id)]
    assert kinds[0] == "prompt"
    assert kinds[-1] == "response"
    texts = {e.kind: e.text for e in core.ledger.events_for(core.session_id)}
    assert texts["prompt"] == "what is exposed?"
    assert texts["response"]  # the critic-approved draft
    # the turn is closed: a later command is not misattributed to it
    assert core._current_turn_event_id is None


def test_agent_command_links_to_the_current_turn(core: AgentCore) -> None:
    """A command the executor records mid-turn is tagged with the driving prompt."""
    core.llm = RoleScriptedChatModel(
        worker_replies=[
            WorkerResponse(command="nmap 10.0.0.5", summary="scan", done=True)
        ],
        critic_replies=[CriticResponse(approved=True, reason="ok")],
    )
    core.graph = core._build()
    list(core.turn("scan the host"))

    events = core.ledger.events_for(core.session_id)
    prompt_id = next(e.id for e in events if e.kind == "prompt")
    command = core.ledger.commands_for(core.session_id)[-1]
    assert command.command == "nmap 10.0.0.5"
    assert command.turn_event_id == prompt_id


def test_run_proposal_outside_a_turn_is_unlinked(core: AgentCore) -> None:
    core.commands = CommandRegistry(
        commands=(CommandAlias(name="nmap-network", argv=("nmap", "-sn")),)
    )
    core.plan_cmd("nmap-network")
    assert core.ledger.commands_for(core.session_id)[-1].turn_event_id is None


def test_record_passthrough_timeline_vs_cli_noise(core: AgentCore) -> None:
    core.record_passthrough("nmap -sV 10.0.0.5")  # a real tool -> timeline
    core.record_passthrough("cd /tmp")  # navigation noise -> audit cli
    core.record_passthrough("   ")  # nothing at all

    cmds = core.ledger.commands_for(core.session_id)
    assert [c.status for c in cmds] == ["passthrough"]
    assert cmds[0].command == "nmap -sV 10.0.0.5"
    assert cmds[0].binary == "nmap"
    audit = core.ledger.audit_for(core.session_id)
    assert [(a.kind, a.detail) for a in audit] == [("cli", "cd /tmp")]


# --- the separate harness-interaction audit log -----------------------------


def test_note_interaction_writes_to_the_audit_log(core: AgentCore) -> None:
    core.note_interaction("mode", "blueteam")
    [row] = core.ledger.audit_for(core.session_id)
    assert (row.kind, row.verb, row.detail) == ("control", "mode", "blueteam")
    assert core.ledger.events_for(core.session_id) == []  # not on the timeline


# --- retrieval + replay -----------------------------------------------------


def test_list_sessions_and_transcript(core: AgentCore) -> None:
    list(core.turn("enumerate services"))
    sessions = core.archive.sessions()
    assert core.session_id in {s.session_id for s in sessions}
    text = core.archive.transcript()  # current session
    assert "enumerate services" in text
    # a short-prefix reference resolves the same session
    assert "enumerate services" in core.archive.transcript(core.session_id[:8])


def test_transcript_of_unknown_session(core: AgentCore) -> None:
    assert "no session found" in core.archive.transcript("deadbeef-nope")


# --- the private LLM review -------------------------------------------------


def test_review_feeds_the_timeline_and_is_audit_logged(core: AgentCore) -> None:
    list(core.turn("what is exposed?"))
    core.llm = cast(Any, ScriptedChatModel(replies=["you rushed recon; see cmd:1"]))

    out = core.archive.review()

    assert out == "you rushed recon; see cmd:1"
    # the session timeline actually reached the model's prompt (wired to an
    # offline fake, so read its recorded calls through a cast)
    prompt_text = cast("Any", core.llm).calls[-1][-1].text
    assert "Session timeline" in prompt_text
    assert "what is exposed?" in prompt_text
    # the critique is recorded to the audit log, never the report
    reviews = [a for a in core.ledger.audit_for(core.session_id) if a.kind == "review"]
    assert reviews
    assert reviews[-1].detail == out


def test_review_of_unknown_session_reports_it(core: AgentCore) -> None:
    assert "no session found" in core.archive.review("nope-nope")


def test_review_model_override_is_used(
    core: AgentCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    list(core.turn("hello"))
    core.settings = core.settings.model_copy(update={"review_model": "big-model"})
    seen: dict[str, str | None] = {}

    def fake_get_chat_model(_settings: object, *, model: str | None = None) -> object:
        seen["model"] = model
        return ScriptedChatModel(replies=["deep review"])

    monkeypatch.setattr(providers, "get_chat_model", fake_get_chat_model)
    assert core.archive.review() == "deep review"
    assert seen["model"] == "big-model"  # the override model was requested
