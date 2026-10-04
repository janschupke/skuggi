"""L1: the research nodes -- plan dedupe/cap, collect dispatch, verify floor, respond.

The branchy per-node behaviour the graph test doesn't isolate: the planner's
dedupe/cap/replan-count, the collector's deny/no-collector/unavailable/no-ready
paths, the verifier's coverage floor, and the responder's report-write guards.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable, RunnableLambda

from skuggi.intel.collectors.base import CollectContext
from skuggi.intel.schema import IntelItem, IntelResult
from skuggi.research import nodes
from skuggi.research.collectors.cve import CveCollector
from skuggi.research.deps import ResearchDeps
from skuggi.research.schema import (
    ResearchPlan,
    ResearchProfile,
    ResearchTask,
    ResearchVerdict,
)
from skuggi.research.state import ResearchState


class _Model(BaseChatModel):
    """Returns one canned structured object for every structured call."""

    reply: Any = None

    @property
    def _llm_type(self) -> str:
        return "canned"

    def with_structured_output(self, schema: Any, **kwargs: Any) -> Runnable[Any, Any]:
        return RunnableLambda(lambda _m: self.reply)

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=""))])


def _ctx() -> CollectContext:
    return CollectContext(fetch=lambda _r: None, clean=lambda s: s)


def _task(source: str = "cve", tid: str = "t1") -> ResearchTask:
    return ResearchTask(
        id=tid,
        source=cast("Any", source),
        subject="wp",
        objective="o",
    )


def _state(**kw: Any) -> ResearchState:
    base: dict[str, Any] = {"messages": []}
    base.update(kw)
    return cast("ResearchState", base)


# ----- plan_node ---------------------------------------------------------------


def test_plan_node_dedupes_caps_and_counts_replans() -> None:
    plan = ResearchPlan(tasks=(_task(tid="a"), _task(tid="b"), _task(tid="c")))
    deps = ResearchDeps(llm=_Model(reply=plan), max_tasks=2)
    out = nodes.plan_node(_state(plan=[_task(tid="a")], replan_count=0), deps)
    ids = [t.id for t in cast("list[ResearchTask]", out["plan"])]
    assert ids == ["a", "b"]  # existing kept, 'a' not duplicated, capped at 2
    assert out["replan_count"] == 1  # had an existing plan -> this is a replan


def test_plan_node_first_pass_does_not_count_as_replan() -> None:
    deps = ResearchDeps(llm=_Model(reply=ResearchPlan(tasks=(_task(),))))
    out = nodes.plan_node(_state(), deps)
    assert out["replan_count"] == 0


# ----- collect_node / _collect_one --------------------------------------------


def test_collect_reaches_a_configured_collector() -> None:
    deps = ResearchDeps(collectors=(CveCollector(),), collect_context=_ctx())
    res = nodes._collect_one(_task(source="cve"), deps)
    assert res.note  # empty fetch -> empty result with a note, never a raise


def test_collect_no_collector_configured() -> None:
    deps = ResearchDeps(collectors=(), collect_context=_ctx())
    res = nodes._collect_one(_task("cve"), deps)
    assert "no collector configured" in res.note


def test_collect_unavailable_collector() -> None:
    class _Dead:
        source = "cve"

        def available(self, _ctx: CollectContext) -> bool:
            return False

        def collect(
            self, _t: Any, _c: CollectContext
        ) -> IntelResult:  # pragma: no cover
            raise AssertionError

    deps = ResearchDeps(collectors=(cast("Any", _Dead()),), collect_context=_ctx())
    res = nodes._collect_one(_task("cve"), deps)
    assert "unavailable" in res.note


def test_collect_node_no_ready_task_returns_empty() -> None:
    deps = ResearchDeps(collectors=(CveCollector(),), collect_context=_ctx())
    task = ResearchTask(
        id="t1", source="cve", subject="wp", objective="o", depends_on=("x",)
    )
    assert nodes.collect_node(_state(plan=[task], completed=[]), deps) == {}


def test_collect_node_records_and_persists(tmp_path: Path) -> None:
    deps = ResearchDeps(
        collectors=(CveCollector(),), collect_context=_ctx(), output_root=tmp_path
    )
    out = nodes.collect_node(
        _state(plan=[_task("cve")], completed=[], results=[]), deps
    )
    assert out["completed"] == ["t1"]
    assert len(cast("list[IntelResult]", out["results"])) == 1
    assert (tmp_path / "wp" / "cve.json").is_file()


# ----- verify_node -------------------------------------------------------------


def test_verify_sets_profile_gaps_done_and_floor() -> None:
    profile = ResearchProfile(subject="wp", latest_version="1.0")
    verdict = ResearchVerdict(done=False, gaps=("more",), summary="s", profile=profile)
    deps = ResearchDeps(
        llm=_Model(reply=verdict),
        collectors=(CveCollector(),),
        collect_context=_ctx(),
    )
    out = nodes.verify_node(_state(results=[]), deps)
    assert out["done"] is False
    assert out["gaps"] == ["more"]
    assert out["draft"] == "s"
    assert out["profile"] is profile


def test_available_sources_empty_without_context() -> None:
    deps = ResearchDeps(collectors=(CveCollector(),), collect_context=None)
    assert nodes._available_sources(deps) == []


# ----- respond_node ------------------------------------------------------------


def test_respond_writes_report_and_appends_path(tmp_path: Path) -> None:
    deps = ResearchDeps(collect_context=_ctx(), output_root=tmp_path)
    result = IntelResult(
        task_id="t",
        source="cve",
        subject="wp",
        items=(IntelItem(kind="cve", value="C"),),
    )
    out = nodes.respond_node(
        _state(
            draft="summary",
            request="wp",
            profile=ResearchProfile(subject="wp"),
            results=[result],
        ),
        deps,
    )
    text = cast("list[AIMessage]", out["messages"])[0].text
    assert "summary" in text
    assert "Report written to" in text
    assert list(tmp_path.glob("wp-*.md"))


def test_respond_without_output_root_just_summarizes() -> None:
    deps = ResearchDeps(collect_context=_ctx(), output_root=None)
    out = nodes.respond_node(_state(draft="hi"), deps)
    assert cast("list[AIMessage]", out["messages"])[0].text == "hi"
