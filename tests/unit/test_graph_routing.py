"""L1: the critic's routing decision, as a pure function."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from skuggi.agent.executor import _record_findings
from skuggi.agent.graph import (
    GraphDeps,
    needs_pipeline,
    route_after_critic,
    route_after_plan,
)
from skuggi.agent.protocol import FindingDraft, FindingRefDraft, WorkerResponse
from skuggi.agent.requests import last_user_text, prior_turns, render_history
from skuggi.agent.state import AgentState
from skuggi.engagement.engagement import EngagementConfig, ThreatModel
from skuggi.persistence.ledger import open_ledger
from skuggi.tooling.registry import ToolRegistry, ToolSpec


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


@pytest.mark.parametrize(
    ("plan_action", "expected"),
    [
        ("answer", "respond"),  # a triaged direct answer skips the pipeline
        ("plan", "retriever"),  # a real plan continues into retrieval + worker
        (None, "retriever"),  # absent (older provider/fake) -> the pipeline
    ],
)
def test_route_after_plan(plan_action: str | None, expected: str) -> None:
    kwargs: dict[str, object] = {}
    if plan_action is not None:
        kwargs["plan_action"] = plan_action
    assert route_after_plan(_state(**kwargs)) == expected


_TOOLS = ToolRegistry(tools=(ToolSpec(name="nmap", binary="nmap", method="scan"),))


def _scoped_engagement() -> EngagementConfig:
    return EngagementConfig.model_validate(
        {
            "name": "e",
            "timezone": "UTC",
            "authorized_start": datetime(2000, 1, 1, tzinfo=UTC),
            "authorized_end": datetime(2999, 1, 1, tzinfo=UTC),
            "allowed_hosts": frozenset({"scanme.example"}),
        }
    )


def test_needs_pipeline_is_false_for_a_conversational_turn() -> None:
    deps = GraphDeps(registry=_TOOLS, engagement=_scoped_engagement())
    assert needs_pipeline("who are you?", deps) is False
    assert needs_pipeline("what can you do here?", deps) is False
    assert needs_pipeline("", deps) is False


def test_needs_pipeline_catches_an_ip_or_cidr_with_no_deps() -> None:
    assert needs_pipeline("have a look at 10.0.0.5", GraphDeps()) is True
    assert needs_pipeline("sweep 192.168.0.0/24", GraphDeps()) is True


def test_needs_pipeline_catches_an_in_scope_host() -> None:
    deps = GraphDeps(engagement=_scoped_engagement())
    assert needs_pipeline("poke at scanme.example please", deps) is True


def test_needs_pipeline_catches_a_known_tool_binary() -> None:
    deps = GraphDeps(registry=_TOOLS)
    assert needs_pipeline("could you run nmap for me", deps) is True
    # The binary must be a whole word, not an incidental substring.
    assert needs_pipeline("tell me about enmapment theory", deps) is False


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


class _ExplodingLedger:
    """A ledger whose finding write always fails, to exercise evidence loss."""

    def current_threat_model_version(self) -> int:
        return 0

    def latest_command_id(self, _session_id: str) -> int | None:
        return None

    def record_finding(self, **_kwargs: object) -> int:
        msg = "disk full"
        raise RuntimeError(msg)


def test_record_findings_logs_evidence_loss_and_reraises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A finding that fails to persist must not vanish silently.

    Losing a finding is the worst case for an engagement: it is named explicitly
    in the log as evidence loss, then re-raised so the turn is not reported as
    clean.
    """
    deps = GraphDeps(ledger=_ExplodingLedger(), session_id="s")  # type: ignore[arg-type]
    resp = WorkerResponse(
        findings=(
            FindingDraft(title="open port", severity="high", description="22/tcp"),
        )
    )
    with caplog.at_level("ERROR", logger="skuggi.graph"), pytest.raises(RuntimeError):
        _record_findings(deps, resp, command_id=1)
    assert any("evidence loss" in r.message for r in caplog.records)


def test_record_findings_scores_cvss_and_augments_with_threat_model(
    tmp_path: Path,
) -> None:
    engagement = EngagementConfig(
        name="e",
        timezone="UTC",
        authorized_start=datetime(2026, 1, 1, tzinfo=UTC),
        authorized_end=datetime(2026, 12, 31, tzinfo=UTC),
        taxonomies=frozenset({"wstg"}),
        threat_model=ThreatModel(confidentiality_requirement="high"),
    )
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s", engagement_name="e", mode="pentest")
        assert engagement.threat_model is not None
        led.record_threat_model(engagement.threat_model.model_dump_json(), note="init")
        deps = GraphDeps(ledger=led, session_id="s", engagement=engagement)
        resp = WorkerResponse(
            findings=(
                FindingDraft(
                    title="Reflected XSS",
                    description="unencoded reflection",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    refs=(FindingRefDraft(framework="wstg", ref_id="WSTG-CLNT-01"),),
                ),
            )
        )
        _record_findings(deps, resp, command_id=None)

        [row] = led.findings_for("s")
        assert row.cvss_version == "3.1"
        assert row.cvss_base == 6.1
        assert row.severity == "medium"  # derived, not model-chosen
        # The stored vector is the worker's intrinsic base -- the threat model is NOT
        # baked into it (so it can be rescored), but it IS reflected in the env score.
        assert "CR:H" not in (row.cvss_vector or "")
        assert row.cvss_environmental is not None
        assert row.cvss_score == row.cvss_environmental  # environmental is the overall
        assert row.cvss_tm_version == 1  # scored under the initial threat-model version

        [ref] = led.finding_refs_for(row.id)
        assert (ref.framework, ref.ref_id, ref.is_primary) == (
            "wstg",
            "WSTG-CLNT-01",
            1,
        )
        assert ref.url.startswith("https://owasp.org/")
