"""Pure DAG logic for the OSINT loop: dependency-aware task selection.

All the branchy scheduling lives here as total, side-effect-free functions so the
graph nodes stay thin and this is exhaustively unit-testable (the branch-coverage
strategy). Nothing here touches the LLM, the network, or disk.
"""

from __future__ import annotations

from skuggi.engagement.scope import OsintScope, OsintSource
from skuggi.osint.schema import OsintResult, OsintTask


def remaining(plan: list[OsintTask], completed: list[str]) -> list[OsintTask]:
    """Tasks not yet completed, order preserved."""
    done = set(completed)
    return [task for task in plan if task.id not in done]


def select_ready(plan: list[OsintTask], completed: list[str]) -> list[OsintTask]:
    """Incomplete tasks whose every dependency is already completed.

    A dependency on an id not present in the plan is unsatisfiable, so such a task
    is never ready -- which ``is_blocked`` then surfaces rather than looping.
    """
    done = set(completed)
    ids = {task.id for task in plan}
    ready: list[OsintTask] = []
    for task in plan:
        if task.id in done:
            continue
        deps = set(task.depends_on)
        if deps <= done and deps <= ids | done:
            ready.append(task)
    return ready


def is_blocked(plan: list[OsintTask], completed: list[str]) -> bool:
    """True when work remains but nothing is runnable (a cycle or a missing dep).

    The deterministic stop that keeps a malformed plan from spinning: the scheduler
    routes a blocked state to the verifier instead of back to the collector.
    """
    return bool(remaining(plan, completed)) and not select_ready(plan, completed)


def coverage_gaps(results: list[OsintResult], osint: OsintScope) -> list[OsintSource]:
    """Enabled sources that produced no data yet (a deterministic coverage floor).

    The verifier (an LLM) judges semantic completeness; this is the backstop it is
    handed so an enabled source that was never run, or returned nothing, is visible
    as a gap regardless of the model's judgement.
    """
    produced = {result.source for result in results if result.items}
    return [
        source for source in sorted(osint.enabled_sources) if source not in produced
    ]
