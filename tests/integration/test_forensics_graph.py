"""L2: the forensics loop graph over a real ledger + workspace + analyzers, fake LLM.

Only the examiner LLM is faked (a scripted model dispatching on "You are the
forensics examiner"); the analyzer battery, the case ledger (evidence + procedure
+ findings), the artifact store and the report writer are all real. Proves the
chain of custody is recorded, the grounding gate forces an ungrounded finding
speculative, and the report separates confirmed from "to validate".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable, RunnableConfig, RunnableLambda
from langgraph.checkpoint.memory import InMemorySaver

from skuggi.engagement.workspace import Workspace
from skuggi.forensics.deps import ForensicsDeps
from skuggi.forensics.graph import build_forensics_graph, forensics_recursion_limit
from skuggi.forensics.schema import CaseProfile, ForensicsFinding, ForensicsVerdict
from skuggi.forensics.state import ForensicsState
from skuggi.persistence.ledger import open_ledger


class ExaminerModel(BaseChatModel):
    """Serves one scripted ForensicsVerdict to the examiner role."""

    verdict: ForensicsVerdict = ForensicsVerdict()

    @property
    def _llm_type(self) -> str:
        return "forensics-scripted"

    def _dispatch(self, messages: Any) -> Any:
        return self.verdict

    def with_structured_output(self, schema: Any, **kwargs: Any) -> Runnable[Any, Any]:
        return RunnableLambda(self._dispatch)

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=""))])


def _verdict() -> ForensicsVerdict:
    return ForensicsVerdict(
        profile=CaseProfile(
            summary="one text artifact", artifact_types=("text/plain",)
        ),
        findings=(
            ForensicsFinding(
                title="plaintext password present",
                severity="high",
                description="a credential string is in the clear",
                evidence_refs=("E1",),
            ),
            ForensicsFinding(
                title="exfiltration to a C2",
                severity="critical",
                description="inferred from the filename",
                evidence_refs=("E9",),  # does not resolve -> forced speculative
            ),
        ),
        summary="examined 1 artifact",
    )


def _case(tmp_path: Path) -> Workspace:
    ws = Workspace.at(tmp_path / "case1")
    ws.ensure_case()
    (ws.evidence_dir / "creds.txt").write_text(
        "username=root password=hunter2\n", encoding="utf-8"
    )
    return ws


def _run(deps: ForensicsDeps) -> None:
    app = build_forensics_graph(deps, InMemorySaver())
    config: RunnableConfig = {
        "configurable": {"thread_id": "forensics:t1"},
        "recursion_limit": forensics_recursion_limit(),
    }
    initial: ForensicsState = {
        "messages": [HumanMessage(content="triage")],
        "request": "triage",
    }
    for _ in app.stream(initial, config, stream_mode="updates"):
        pass


def test_forensics_run_records_custody_grounds_findings_and_reports(
    tmp_path: Path,
) -> None:
    ws = _case(tmp_path)
    with open_ledger(ws.case_ledger_path) as ledger:
        ledger.start_session("s1", engagement_name="case:case1", mode="forensics")
        deps = ForensicsDeps(
            llm=ExaminerModel(verdict=_verdict()),
            workspace=ws,
            ledger=ledger,
            session_id="s1",
            case_name="case1",
            output_root=ws.forensics_dir,
            vision=False,
        )
        _run(deps)

        # chain of custody: the file was acquired (hashed) and operations recorded
        evidence = ledger.evidence_for("s1")
        assert len(evidence) == 1
        assert evidence[0].sha256  # an integrity pin was stored
        procedure = ledger.procedure_for("s1")
        assert {p.operation for p in procedure} >= {"hash", "magic", "strings"}

        # grounding: the E1-backed finding is confirmed (recorded); the E9 one is not
        confirmed = ledger.findings_for("s1")
        titles = {f.title for f in confirmed}
        assert "plaintext password present" in titles
        assert "exfiltration to a C2" not in titles

    # a per-file artifact and a case report were written
    artifacts = list(ws.forensics_dir.rglob("*.json"))
    assert artifacts
    reports = list(ws.reports_dir.glob("*.md"))
    assert len(reports) == 1
    body = reports[0].read_text(encoding="utf-8")
    assert "Findings (confirmed)" in body
    assert "plaintext password present" in body
    assert "Speculative" in body
    assert "exfiltration to a C2" in body


def test_forensics_run_with_no_findings_writes_a_clean_report(tmp_path: Path) -> None:
    ws = _case(tmp_path)
    with open_ledger(ws.case_ledger_path) as ledger:
        ledger.start_session("s1", engagement_name="case:case1", mode="forensics")
        deps = ForensicsDeps(
            llm=ExaminerModel(verdict=ForensicsVerdict(summary="nothing of note")),
            workspace=ws,
            ledger=ledger,
            session_id="s1",
            case_name="case1",
            output_root=ws.forensics_dir,
            vision=False,
        )
        _run(deps)
        assert ledger.findings_for("s1") == []
    body = next(ws.reports_dir.glob("*.md")).read_text(encoding="utf-8")
    assert "No confirmed findings" in body
