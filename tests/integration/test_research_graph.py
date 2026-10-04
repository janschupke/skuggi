"""L2: the research loop graph over a real saver + scheduler + collectors, fake net.

Only the LLM and the network are faked (a scripted research model dispatching on
"You are the research {role}", and an injected fetch returning canned bodies). The
scheduler, the scope guard, the collectors, the artifact store and the report
writer are all real. The sibling of test_osint_graph.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable, RunnableLambda
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import Field

from skuggi.intel.collectors import GitHubCollector, WebSearchCollector
from skuggi.intel.collectors.base import CollectContext, HttpRequest
from skuggi.research.collectors.cve import CveCollector
from skuggi.research.collectors.metasploit import MetasploitCollector
from skuggi.research.collectors.searchsploit import SearchsploitCollector
from skuggi.research.collectors.versions import VersionsCollector
from skuggi.research.deps import ResearchDeps
from skuggi.research.graph import build_research_graph, research_recursion_limit
from skuggi.research.schema import (
    ResearchPlan,
    ResearchProfile,
    ResearchTask,
    ResearchVerdict,
)
from skuggi.research.state import ResearchState

_NVD = (
    '{"vulnerabilities": [{"cve": {"id": "CVE-1", "descriptions": [], "metrics": {}}}]}'
)
_EOL = '[{"cycle": "6.4", "latest": "6.4.3", "eol": false}]'


def _fetch(req: HttpRequest) -> str | None:
    if "services.nvd.nist.gov" in req.url:
        return _NVD
    if "endoflife.date" in req.url:
        return _EOL
    return None


class ResearchScriptedModel(BaseChatModel):
    """Serves a ResearchPlan to the planner and ResearchVerdicts to the verifier."""

    plans: Sequence[ResearchPlan] = ()
    verdicts: Sequence[ResearchVerdict] = ()
    calls: list[str] = Field(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "research-scripted"

    def _dispatch(self, messages: Any) -> Any:
        msgs = messages if isinstance(messages, list) else [messages]
        system = next((m.text for m in msgs if getattr(m, "type", "") == "system"), "")
        if "You are the research planner" in system:
            seen = sum(1 for c in self.calls if c == "planner")
            self.calls.append("planner")
            return (
                self.plans[min(seen, len(self.plans) - 1)]
                if self.plans
                else ResearchPlan()
            )
        self.calls.append("verifier")
        seen = sum(1 for c in self.calls if c == "verifier")
        if not self.verdicts:
            return ResearchVerdict(done=True)
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


def _collectors() -> tuple[Any, ...]:
    # Deterministic regardless of host: local tools are forced unavailable.
    return (
        WebSearchCollector(),
        GitHubCollector(),
        VersionsCollector(),
        CveCollector(),
        SearchsploitCollector(run=lambda _a: None, have_tool=False),
        MetasploitCollector(load_cache=lambda: None),
    )


def _deps(model: ResearchScriptedModel, out: Path, **kw: object) -> ResearchDeps:
    base: dict[str, object] = {
        "llm": model,
        "collectors": _collectors(),
        "collect_context": CollectContext(fetch=_fetch, clean=lambda s: s),
        "output_root": out,
        "session_id": "s1",
        "max_tasks": 8,
        "max_replans": 2,
    }
    base.update(kw)
    return ResearchDeps(**base)  # type: ignore[arg-type]


def _run(deps: ResearchDeps, request: str = "wordpress") -> ResearchState:
    app = build_research_graph(deps, InMemorySaver())
    config = {
        "configurable": {"thread_id": "research:t1"},
        "recursion_limit": research_recursion_limit(max_tasks=8, max_replans=2),
    }
    initial: ResearchState = {
        "messages": [HumanMessage(content=request)],
        "request": request,
        "replan_count": 0,
        "max_replans": 2,
    }
    return cast("ResearchState", app.invoke(initial, cast("Any", config)))


def _plan() -> ResearchPlan:
    return ResearchPlan(
        tasks=(
            ResearchTask(
                id="v", source="versions", subject="wordpress", objective="ver"
            ),
            ResearchTask(
                id="c",
                source="cve",
                subject="wordpress",
                objective="cves",
                depends_on=("v",),
            ),
        )
    )


def test_loop_walks_the_dag_collects_and_writes_report(tmp_path: Path) -> None:
    out = tmp_path / "research"
    profile = ResearchProfile(subject="wordpress", latest_version="6.4.3")
    model = ResearchScriptedModel(
        plans=(_plan(),),
        verdicts=(ResearchVerdict(done=True, summary="here it is", profile=profile),),
    )
    final = _run(_deps(model, out))
    assert set(final["completed"]) == {"v", "c"}
    assert {r.source for r in final["results"]} == {"versions", "cve"}
    assert "here it is" in final["messages"][-1].text
    # per-source JSON artifacts + the Markdown report were written
    assert (out / "wordpress" / "versions.json").is_file()
    assert (out / "wordpress" / "cve.json").is_file()
    assert list(out.glob("wordpress-*.md"))


def test_loop_replans_to_close_gaps(tmp_path: Path) -> None:
    model = ResearchScriptedModel(
        plans=(
            ResearchPlan(
                tasks=(
                    ResearchTask(
                        id="v", source="versions", subject="wp", objective="x"
                    ),
                )
            ),
            ResearchPlan(
                tasks=(ResearchTask(id="c", source="cve", subject="wp", objective="y"),)
            ),
        ),
        verdicts=(
            ResearchVerdict(done=False, gaps=("need cves",)),
            ResearchVerdict(done=True, summary="done"),
        ),
    )
    final = _run(_deps(model, tmp_path / "research"), request="wp")
    assert set(final["completed"]) == {"v", "c"}
    assert model.calls.count("planner") == 2


def test_blocked_plan_routes_to_verifier(tmp_path: Path) -> None:
    # 'c' depends on a task id never in the plan -> nothing ready -> verifier ends.
    model = ResearchScriptedModel(
        plans=(
            ResearchPlan(
                tasks=(
                    ResearchTask(
                        id="c",
                        source="cve",
                        subject="wp",
                        objective="y",
                        depends_on=("missing",),
                    ),
                )
            ),
        ),
        verdicts=(ResearchVerdict(done=True, summary="blocked"),),
    )
    final = _run(_deps(model, tmp_path / "research"), request="wp")
    assert final.get("completed", []) == []
    assert "blocked" in final["messages"][-1].text


def test_report_write_failure_does_not_kill_the_loop(tmp_path: Path) -> None:
    # output_root points at a *file*, so the report write raises -> swallowed. An
    # empty plan keeps the collector out of it, isolating the respond-node guard.
    out = tmp_path / "research"
    out.write_text("i am a file", encoding="utf-8")
    model = ResearchScriptedModel(
        plans=(), verdicts=(ResearchVerdict(done=True, summary="ok"),)
    )
    final = _run(_deps(model, out))
    assert "ok" in final["messages"][-1].text
