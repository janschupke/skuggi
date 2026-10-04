"""L3: the forensics runner on a live (offline) AgentCore, streaming TurnEvents."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable, RunnableLambda

from skuggi.agent.core import AgentCore
from skuggi.forensics.schema import CaseProfile, ForensicsFinding, ForensicsVerdict
from tests.conftest import offline_settings


class _Examiner(BaseChatModel):
    verdict: ForensicsVerdict = ForensicsVerdict()

    @property
    def _llm_type(self) -> str:
        return "examiner"

    def with_structured_output(self, schema: Any, **kwargs: Any) -> Runnable[Any, Any]:
        return RunnableLambda(lambda _m: self.verdict)

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=""))])


def test_forensics_turn_without_a_case_yields_guidance(tmp_path: Path) -> None:
    core = AgentCore(offline_settings(tmp_path))
    try:
        core.set_mode("forensics")
        events = list(core.forensics_turn("triage"))
        assert len(events) == 1
        assert events[0].node == "error"
        assert "set case" in events[0].text
    finally:
        core.close()


def test_forensics_turn_examines_a_case_and_reports(tmp_path: Path) -> None:
    core = AgentCore(offline_settings(tmp_path))
    try:
        core.set_mode("forensics")
        core.set_case(tmp_path / "case1")
        assert core.case_mgr is not None
        (core.case_mgr.workspace.evidence_dir / "note.txt").write_text(
            "password=hunter2\n", encoding="utf-8"
        )
        core.llm = _Examiner(
            verdict=ForensicsVerdict(
                profile=CaseProfile(summary="one artifact"),
                findings=(
                    ForensicsFinding(
                        title="cleartext credential",
                        severity="high",
                        evidence_refs=("E1",),
                    ),
                ),
                summary="done",
            )
        )
        events = list(core.forensics_turn("triage"))
        kinds = [e.kind for e in events]
        assert "status" in kinds
        assert events[-1].kind == "final"
        # the confirmed finding reached the case ledger
        findings = core.case_mgr.ledger.findings_for(core.case_mgr.session_id)
        assert any(f.title == "cleartext credential" for f in findings)
    finally:
        core.close()
