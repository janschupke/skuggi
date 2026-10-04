"""Pure DAG logic for the intelligence loops: dependency-aware task selection.

All the branchy scheduling lives here as total, side-effect-free functions over
a minimal :class:`Task` protocol (``id`` + ``depends_on``), so both the OSINT and
research graphs reuse it and it is exhaustively unit-testable. Nothing here
touches the LLM, the network, or disk.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from skuggi.intel.schema import IntelResult


@runtime_checkable
class Task(Protocol):
    """A schedulable unit: an id and the ids it depends on."""

    @property
    def id(self) -> str:
        """The task's unique id."""

    @property
    def depends_on(self) -> tuple[str, ...]:
        """The ids this task depends on (must complete first)."""


def remaining[T: Task](plan: list[T], completed: list[str]) -> list[T]:
    """Tasks not yet completed, order preserved."""
    done = set(completed)
    return [task for task in plan if task.id not in done]


def select_ready[T: Task](plan: list[T], completed: list[str]) -> list[T]:
    """Incomplete tasks whose every dependency is already completed.

    A dependency on an id not present in the plan is unsatisfiable, so such a task
    is never ready -- which ``is_blocked`` then surfaces rather than looping.
    """
    done = set(completed)
    ids = {task.id for task in plan}
    ready: list[T] = []
    for task in plan:
        if task.id in done:
            continue
        deps = set(task.depends_on)
        if deps <= done and deps <= ids | done:
            ready.append(task)
    return ready


def is_blocked[T: Task](plan: list[T], completed: list[str]) -> bool:
    """True when work remains but nothing is runnable (a cycle or a missing dep).

    The deterministic stop that keeps a malformed plan from spinning: the scheduler
    routes a blocked state to the verifier instead of back to the collector.
    """
    return bool(remaining(plan, completed)) and not select_ready(plan, completed)


def coverage_gaps(
    results: list[IntelResult], enabled_sources: Iterable[str]
) -> list[str]:
    """Enabled sources that produced no data yet (a deterministic coverage floor).

    The verifier (an LLM) judges semantic completeness; this is the backstop it is
    handed so an enabled source that was never run, or returned nothing, is visible
    as a gap regardless of the model's judgement.
    """
    produced = {result.source for result in results if result.items}
    return [source for source in sorted(enabled_sources) if source not in produced]
