"""L1: the research protocol models -- DAG + profile shape."""

from __future__ import annotations

from skuggi.intel.scheduler import Task
from skuggi.intel.schema import CollectTask
from skuggi.research.schema import (
    RESEARCH_SOURCES,
    ResearchPlan,
    ResearchTask,
    ResearchVerdict,
)


def test_research_sources_are_the_literal_members() -> None:
    assert "cve" in RESEARCH_SOURCES
    assert "websearch" in RESEARCH_SOURCES
    assert len(RESEARCH_SOURCES) == 7


def test_task_satisfies_the_shared_protocols() -> None:
    task = ResearchTask(id="t1", source="cve", subject="wp", objective="vulns")
    assert isinstance(task, Task)  # intel.scheduler
    assert isinstance(task, CollectTask)  # intel collectors


def test_plan_holds_a_dependency_dag() -> None:
    plan = ResearchPlan(
        tasks=(
            ResearchTask(id="a", source="versions", subject="wp", objective="v"),
            ResearchTask(
                id="b", source="cve", subject="wp", objective="c", depends_on=("a",)
            ),
        )
    )
    assert plan.tasks[1].depends_on == ("a",)


def test_verdict_defaults_to_not_done_no_profile() -> None:
    v = ResearchVerdict()
    assert v.done is False
    assert v.profile is None
    assert v.gaps == ()
