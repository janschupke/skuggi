"""L2: the OSINT loop graph over a real saver + ledger + guard, fake model/net.

Only the LLM and the network are faked (a scripted OSINT model dispatching on
"You are the OSINT {role}", and an injected fetch returning canned bodies). The
scheduler, the guard, the collectors, the artifact store and the finding recorder
are all real -- the direct analogue of test_graph's autonomous-loop test.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any, cast

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable, RunnableLambda
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import Field

from skuggi.agent.protocol import FindingDraft
from skuggi.engagement.scope import OsintScope
from skuggi.engagement.workspace import Workspace
from skuggi.intel.collectors.base import CollectContext, HttpRequest
from skuggi.osint.collectors import default_collectors
from skuggi.osint.deps import OsintDeps
from skuggi.osint.graph import build_osint_graph, osint_recursion_limit
from skuggi.osint.schema import OsintPlan, OsintTask, OsintVerdict
from skuggi.osint.state import OsintState
from skuggi.persistence.ledger import Ledger, open_ledger


class OsintScriptedModel(BaseChatModel):
    """Serves an OsintPlan to the planner and an OsintVerdict to the verifier."""

    plan: OsintPlan = OsintPlan()
    verdicts: Sequence[OsintVerdict] = ()
    calls: list[str] = Field(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "osint-scripted"

    def _dispatch(self, messages: Any) -> Any:
        msgs = messages if isinstance(messages, list) else [messages]
        system = next((m.text for m in msgs if getattr(m, "type", "") == "system"), "")
        if "You are the OSINT planner" in system:
            self.calls.append("planner")
            return self.plan
        self.calls.append("verifier")
        seen = sum(1 for c in self.calls if c == "verifier")
        if not self.verdicts:
            return OsintVerdict(done=True)
        return self.verdicts[min(seen - 1, len(self.verdicts) - 1)]

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


_CRTSH = json.dumps([{"name_value": "mail.acme.com", "issuer_name": "LE"}])
_REPOS = json.dumps([{"full_name": "acme/site", "language": "Go"}])


def _fetch(req: HttpRequest) -> str | None:
    if "crt.sh" in req.url:
        return _CRTSH
    if "api.github.com/orgs/acme" in req.url:
        return _REPOS
    return None


def _scope() -> OsintScope:
    return OsintScope(
        domains=frozenset({"acme.com"}),
        github_orgs=frozenset({"acme"}),
        enabled_sources=frozenset({"crtsh", "github"}),
        passive_only=True,
    )


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with open_ledger(tmp_path / "ledger.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        yield led


def _deps(
    model: OsintScriptedModel, ledger: Ledger, ws: Workspace, **kw: object
) -> OsintDeps:
    base: dict[str, object] = {
        "llm": model,
        "osint": _scope(),
        "collectors": default_collectors(),
        "collect_context": CollectContext(fetch=_fetch, clean=lambda s: s),
        "workspace": ws,
        "ledger": ledger,
        "session_id": "s1",
        "max_tasks": 8,
        "max_replans": 2,
    }
    base.update(kw)
    return OsintDeps(**base)  # type: ignore[arg-type]


def _run(deps: OsintDeps, request: str = "map acme.com") -> OsintState:
    app = build_osint_graph(deps, InMemorySaver())
    config = {
        "configurable": {"thread_id": "osint:t1"},
        "recursion_limit": osint_recursion_limit(max_tasks=8, max_replans=2),
    }
    initial: OsintState = {
        "messages": [HumanMessage(content=request)],
        "request": request,
        "replan_count": 0,
        "max_replans": 2,
    }
    return cast("OsintState", app.invoke(initial, cast("Any", config)))


def _plan() -> OsintPlan:
    return OsintPlan(
        tasks=(
            OsintTask(id="t1", source="crtsh", subject="acme.com", objective="subs"),
            OsintTask(
                id="t2",
                source="github",
                subject="acme",
                objective="repos",
                depends_on=("t1",),
            ),
        )
    )


def test_loop_walks_the_dag_and_collects(tmp_path: Path, ledger: Ledger) -> None:
    model = OsintScriptedModel(
        plan=_plan(), verdicts=(OsintVerdict(done=True, summary="done"),)
    )
    ws = Workspace.at(tmp_path / "eng")
    ws.ensure()
    final = _run(_deps(model, ledger, ws))
    assert set(final["completed"]) == {"t1", "t2"}
    sources = {r.source for r in final["results"]}
    assert sources == {"crtsh", "github"}
    assert final["draft"] == "done"


def test_artifacts_are_written_per_subject_source(
    tmp_path: Path, ledger: Ledger
) -> None:
    model = OsintScriptedModel(plan=_plan(), verdicts=(OsintVerdict(done=True),))
    ws = Workspace.at(tmp_path / "eng")
    ws.ensure()
    _run(_deps(model, ledger, ws))
    assert (ws.osint_dir / "acme.com" / "crtsh.json").is_file()
    assert (ws.osint_dir / "acme" / "github.json").is_file()


def test_verifier_findings_reach_the_ledger(tmp_path: Path, ledger: Ledger) -> None:
    finding = FindingDraft(
        title="Exposed repo", description="public secret", severity="medium"
    )
    model = OsintScriptedModel(
        plan=_plan(), verdicts=(OsintVerdict(done=True, findings=(finding,)),)
    )
    ws = Workspace.at(tmp_path / "eng")
    ws.ensure()
    _run(_deps(model, ledger, ws))
    rows = ledger.findings_for("s1")
    assert any(r.title == "Exposed repo" for r in rows)


def test_out_of_scope_task_is_denied_not_collected(
    tmp_path: Path, ledger: Ledger
) -> None:
    plan = OsintPlan(
        tasks=(OsintTask(id="t1", source="crtsh", subject="evil.com", objective="x"),)
    )
    model = OsintScriptedModel(plan=plan, verdicts=(OsintVerdict(done=True),))
    ws = Workspace.at(tmp_path / "eng")
    ws.ensure()
    final = _run(_deps(model, ledger, ws))
    assert final["completed"] == ["t1"]  # marked done so the loop ends
    result = final["results"][0]
    assert result.items == ()
    assert "denied" in result.note


def test_loop_replans_to_close_gaps(tmp_path: Path, ledger: Ledger) -> None:
    # First plan has only crtsh; the verifier asks for more, the planner adds github.
    first = OsintPlan(
        tasks=(OsintTask(id="t1", source="crtsh", subject="acme.com", objective="s"),)
    )

    class TwoPhase(OsintScriptedModel):
        def _dispatch(self, messages: Any) -> Any:
            msgs = messages if isinstance(messages, list) else [messages]
            system = next(
                (m.text for m in msgs if getattr(m, "type", "") == "system"), ""
            )
            if "You are the OSINT planner" in system:
                self.calls.append("planner")
                n = sum(1 for c in self.calls if c == "planner")
                if n == 1:
                    return first
                return OsintPlan(
                    tasks=(
                        OsintTask(
                            id="t2", source="github", subject="acme", objective="r"
                        ),
                    )
                )
            self.calls.append("verifier")
            n = sum(1 for c in self.calls if c == "verifier")
            if n == 1:
                return OsintVerdict(
                    done=False, gaps=("github repos",), summary="partial"
                )
            return OsintVerdict(done=True, summary="complete")

    model = TwoPhase()
    ws = Workspace.at(tmp_path / "eng")
    ws.ensure()
    final = _run(_deps(model, ledger, ws))
    assert set(final["completed"]) == {"t1", "t2"}
    assert model.calls.count("planner") == 2  # re-planned once
    assert final["draft"] == "complete"


def test_replans_are_bounded(tmp_path: Path, ledger: Ledger) -> None:
    # The verifier always asks for more; the loop must still terminate at the cap.
    model = OsintScriptedModel(
        plan=_plan(), verdicts=(OsintVerdict(done=False, gaps=("more",)),)
    )
    ws = Workspace.at(tmp_path / "eng")
    ws.ensure()
    final = _run(_deps(model, ledger, ws))
    assert model.calls.count("planner") <= 3  # initial + max_replans(2)
    assert "draft" in final
