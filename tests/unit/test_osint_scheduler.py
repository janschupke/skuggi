"""L1: the OSINT scheduler -- pure DAG selection, every branch pinned."""

from __future__ import annotations

from skuggi.engagement.scope import OsintScope, OsintSource
from skuggi.osint.scheduler import (
    coverage_gaps,
    is_blocked,
    remaining,
    select_ready,
)
from skuggi.osint.schema import OsintItem, OsintResult, OsintTask


def _task(tid: str, *deps: str, source: OsintSource = "crtsh") -> OsintTask:
    return OsintTask(
        id=tid,
        source=source,
        subject="acme.com",
        objective="o",
        depends_on=deps,
    )


def test_remaining_excludes_completed() -> None:
    plan = [_task("a"), _task("b")]
    assert [t.id for t in remaining(plan, ["a"])] == ["b"]


def test_select_ready_respects_dependencies() -> None:
    plan = [_task("a"), _task("b", "a")]
    assert [t.id for t in select_ready(plan, [])] == ["a"]  # b blocked on a
    assert [t.id for t in select_ready(plan, ["a"])] == ["b"]  # now b is ready


def test_select_ready_skips_completed() -> None:
    plan = [_task("a"), _task("b")]
    assert [t.id for t in select_ready(plan, ["a"])] == ["b"]


def test_task_with_a_missing_dependency_is_never_ready() -> None:
    plan = [_task("a", "ghost")]  # depends on an id not in the plan
    assert select_ready(plan, []) == []
    assert is_blocked(plan, []) is True


def test_a_cycle_is_blocked() -> None:
    plan = [_task("a", "b"), _task("b", "a")]
    assert select_ready(plan, []) == []
    assert is_blocked(plan, []) is True


def test_not_blocked_when_work_is_runnable() -> None:
    assert is_blocked([_task("a")], []) is False


def test_not_blocked_when_nothing_remains() -> None:
    assert is_blocked([_task("a")], ["a"]) is False


def test_coverage_gaps_lists_unproduced_sources() -> None:
    osint = OsintScope(
        domains=frozenset({"acme.com"}),
        enabled_sources=frozenset({"crtsh", "github", "dns"}),
    )
    results = [
        OsintResult(
            task_id="t",
            source="crtsh",
            subject="acme.com",
            items=(OsintItem(kind="subdomain", value="x.acme.com"),),
        ),
        OsintResult(
            task_id="t2", source="github", subject="acme.com", items=()
        ),  # empty
    ]
    gaps = coverage_gaps(results, osint)
    assert "dns" in gaps  # never attempted
    assert "github" in gaps  # produced nothing
    assert "crtsh" not in gaps  # produced data
