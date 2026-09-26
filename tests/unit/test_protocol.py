"""L1: the structured request/response protocol.

Covers the two things the graph will lean on: that phase advancement is decided
by code (never the model), and that ``structured_invoke`` yields a validated
instance on both the native and the JSON-contract (chatgpt) paths -- including
the single repair retry when the first non-native reply does not validate.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable, RunnableLambda

from skuggi import palette
from skuggi.protocol import (
    PHASES,
    STANCES,
    CommandBrief,
    CriticResponse,
    EngagementBrief,
    FindingBrief,
    PlannerResponse,
    RequestContext,
    Severity,
    WorkerResponse,
    clamp_phase,
    format_instructions,
    render_request,
    render_response,
    structured_invoke,
)
from tests.fakes import ScriptedChatModel


def test_severity_literal_matches_palette() -> None:
    assert set(palette.severities()) == set(Severity.__args__)  # type: ignore[attr-defined]


def test_phases_and_stances_are_ordered_tuples() -> None:
    assert PHASES[0] == "recon"
    assert PHASES[-1] == "reporting"
    assert STANCES == ("passive", "cautious", "balanced", "aggressive")


@pytest.mark.parametrize(
    ("current", "requested", "expected"),
    [
        ("recon", None, "recon"),
        ("recon", "recon", "recon"),
        ("recon", "enumeration", "enumeration"),  # forward one: honored
        ("recon", "exploitation", "enumeration"),  # forward jump: clamped to +1
        ("exploitation", "recon", "exploitation"),  # regress: refused
        ("reporting", "reporting", "reporting"),  # at the end: stays
    ],
)
def test_clamp_phase_is_forward_only_and_single_step(
    current: str, requested: str | None, expected: str
) -> None:
    assert clamp_phase(current, requested) == expected  # type: ignore[arg-type]


def test_render_request_includes_the_load_bearing_context() -> None:
    ctx = RequestContext(
        request="scan the host",
        phase="enumeration",
        engagement=EngagementBrief(
            name="acme", stance="cautious", autonomous=False, hosts=("scanme.example",)
        ),
        history="user: hi",
        findings=(
            FindingBrief(id=1, severity="high", title="open telnet", command_id=3),
        ),
        recent_commands=(CommandBrief(id=3, status="executed", command="nmap x"),),
        plan=("recon", "enumerate"),
    )
    rendered = render_request(ctx)
    assert "Phase:\nenumeration" in rendered
    assert "acme" in rendered
    assert "stance: cautious" in rendered
    assert "open telnet" in rendered
    assert "cmd:3" in rendered
    assert "nmap x" in rendered
    assert "1. recon" in rendered
    assert "Request:\nscan the host" in rendered


def test_render_response_is_deterministic_and_labelled() -> None:
    resp = WorkerResponse(
        command="nmap -sV 10.0.0.1",
        summary="probe services",
        stance="balanced",
        conclusions="host is up",
        findings=(),
    )
    text = render_response(resp)
    assert "Summary:\nprobe services" in text
    assert "Proposed command:\nnmap -sV 10.0.0.1" in text
    assert "Conclusions:\nhost is up" in text


def test_render_response_falls_back_when_empty() -> None:
    assert render_response(WorkerResponse()) == "(no answer)"


def test_format_instructions_carry_the_schema() -> None:
    text = format_instructions(CriticResponse)
    assert "JSON" in text
    assert "approved" in text


def test_structured_invoke_non_native_parses_json() -> None:
    llm = ScriptedChatModel()
    llm.replies = ['{"approved": true, "reason": "looks good"}']
    llm.calls = []
    out = structured_invoke(
        llm, CriticResponse, [HumanMessage(content="ok?")], native=False
    )
    assert out == CriticResponse(approved=True, reason="looks good")
    # The JSON contract was appended as a system message.
    assert any(isinstance(m, SystemMessage) and "JSON" in m.text for m in llm.calls[-1])


def test_structured_invoke_non_native_tolerates_a_code_fence() -> None:
    llm = ScriptedChatModel()
    llm.replies = ['here you go:\n```json\n{"approved": false, "reason": "scope"}\n```']
    llm.calls = []
    out = structured_invoke(
        llm, CriticResponse, [HumanMessage(content="ok?")], native=False
    )
    assert out.approved is False
    assert out.reason == "scope"


def test_structured_invoke_non_native_repairs_once() -> None:
    llm = ScriptedChatModel()
    llm.replies = ["not json at all", '{"approved": true, "reason": "fixed"}']
    llm.calls = []
    out = structured_invoke(
        llm, CriticResponse, [HumanMessage(content="ok?")], native=False, repair=True
    )
    assert out.reason == "fixed"
    assert len(llm.calls) == 2  # first reply, then the repair reply


def test_structured_invoke_non_native_raises_without_repair() -> None:
    llm = ScriptedChatModel()
    llm.replies = ["not json"]
    llm.calls = []
    with pytest.raises(ValueError, match="JSON"):
        structured_invoke(
            llm,
            CriticResponse,
            [HumanMessage(content="ok?")],
            native=False,
            repair=False,
        )


class _NativeFake(BaseChatModel):
    """A model whose ``with_structured_output`` returns a fixed instance."""

    obj: Any = None

    @property
    def _llm_type(self) -> str:
        return "native-fake"

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **kw: Any
    ) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=""))])

    def with_structured_output(self, schema: Any, **kwargs: Any) -> Runnable[Any, Any]:
        obj = self.obj
        return RunnableLambda(lambda _input: obj)


def test_structured_invoke_native_uses_with_structured_output() -> None:
    want = PlannerResponse(phase="recon", steps=("look",))
    llm = _NativeFake(obj=want)
    out = structured_invoke(
        llm, PlannerResponse, [HumanMessage(content="plan")], native=True
    )
    assert out == want
