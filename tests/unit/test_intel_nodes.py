"""L1: the shared intel collect step -- bounded-parallel, driver-serial, ordered."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import cast

from skuggi.intel.nodes import collect_ready
from skuggi.intel.schema import IntelResult


@dataclass(frozen=True)
class _Task:
    id: str
    source: str = "s"
    subject: str = "x"
    objective: str = "o"
    depends_on: tuple[str, ...] = ()


@dataclass
class _Probe:
    """Records concurrency: the peak number of collectors running at once."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    live: int = 0
    peak: int = 0
    order: list[str] = field(default_factory=list)

    def enter(self, task_id: str) -> None:
        with self.lock:
            self.live += 1
            self.peak = max(self.peak, self.live)
            self.order.append(task_id)

    def leave(self) -> None:
        with self.lock:
            self.live -= 1


def test_empty_ready_set_is_a_noop() -> None:
    out = collect_ready([], [], [], collect_one=_r, persist=lambda _r: None)
    assert out == {}


def _r(task: _Task) -> IntelResult:
    return IntelResult(task_id=task.id, source=task.source, subject=task.subject)


def test_independent_io_tasks_run_in_one_superstep_in_plan_order() -> None:
    plan = [_Task(f"t{i}") for i in range(5)]
    persisted: list[str] = []

    out = collect_ready(
        plan,
        [],
        [],
        collect_one=_r,
        persist=lambda r: persisted.append(r.task_id),
        max_workers=4,
    )
    # every ready task collected and completed this superstep
    assert out["completed"] == ["t0", "t1", "t2", "t3", "t4"]
    results = cast("list[IntelResult]", out["results"])
    assert [r.task_id for r in results] == ["t0", "t1", "t2", "t3", "t4"]
    assert persisted == ["t0", "t1", "t2", "t3", "t4"]  # deterministic plan order


def test_io_tasks_actually_run_concurrently() -> None:
    probe = _Probe()
    plan = [_Task(f"t{i}") for i in range(4)]

    def collect_one(task: _Task) -> IntelResult:
        probe.enter(task.id)
        time.sleep(0.05)  # overlap window
        probe.leave()
        return _r(task)

    collect_ready(
        plan, [], [], collect_one=collect_one, persist=lambda _r: None, max_workers=4
    )
    assert probe.peak > 1  # genuinely parallel, not serialized


def test_driver_backed_tasks_never_run_concurrently() -> None:
    probe = _Probe()
    plan = [_Task(f"d{i}") for i in range(3)]

    def collect_one(task: _Task) -> IntelResult:
        probe.enter(task.id)
        time.sleep(0.02)
        probe.leave()
        return _r(task)

    collect_ready(
        plan,
        [],
        [],
        collect_one=collect_one,
        persist=lambda _r: None,
        uses_driver=lambda _t: True,  # all driver-backed
        max_workers=4,
    )
    assert probe.peak == 1  # serial: a parallel superstep must never pool browsers


def test_results_ordered_by_plan_even_when_io_finishes_out_of_order() -> None:
    plan = [_Task("slow"), _Task("fast")]

    def collect_one(task: _Task) -> IntelResult:
        time.sleep(0.05 if task.id == "slow" else 0.0)
        return _r(task)

    out = collect_ready(
        plan, [], [], collect_one=collect_one, persist=lambda _r: None, max_workers=2
    )
    results = cast("list[IntelResult]", out["results"])
    assert [r.task_id for r in results] == ["slow", "fast"]


def test_a_bad_persist_is_swallowed_and_does_not_abort(caplog: object) -> None:
    plan = [_Task("t0"), _Task("t1")]

    def persist(result: IntelResult) -> None:
        if result.task_id == "t0":
            msg = "bad slug"
            raise ValueError(msg)

    out = collect_ready(plan, [], [], collect_one=_r, persist=persist, max_workers=2)
    assert out["completed"] == ["t0", "t1"]  # the run was not aborted by the bad write
