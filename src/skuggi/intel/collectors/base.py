"""The collector abstraction: one pluggable handler per intelligence source.

Every source -- a first-party HTTP lookup, a browser-driven scrape, an Apify
actor, or a local-tool query -- implements the same :class:`Collector` protocol,
so a loop dispatches on ``task.source`` without knowing which kind backs it. This
module is the collector author's single import surface: it re-exports the
injectable HTTP seam (:mod:`skuggi.intel.http`) and the corpus schema
(:mod:`skuggi.intel.schema`) alongside the protocol and the ``empty_result``
helper.

The protocol is generic in the task type (``Collector[OsintTask]`` /
``Collector[ResearchTask]``), so a source-agnostic collector typed over
``CollectTask`` satisfies both, while a subsystem-specific one pins its own task.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from skuggi.intel.http import (
    ApifyRun,
    CollectContext,
    Driver,
    Fetch,
    HttpRequest,
    default_fetch,
)
from skuggi.intel.schema import CollectTask, IntelItem, IntelResult

__all__ = [
    "ApifyRun",
    "CollectContext",
    "CollectTask",
    "Collector",
    "Driver",
    "Fetch",
    "HttpRequest",
    "IntelItem",
    "IntelResult",
    "collector_for",
    "collector_uses_driver",
    "default_fetch",
    "empty_result",
]


@runtime_checkable
class Collector[TaskT: CollectTask](Protocol):
    """One intelligence source handler. A loop dispatches on ``source``."""

    @property
    def source(self) -> str:
        """The source name this collector handles (matches ``task.source``)."""
        ...

    def available(self, ctx: CollectContext) -> bool:
        """Whether this collector can run now (deps importable + creds present)."""
        ...

    def collect(self, task: TaskT, ctx: CollectContext) -> IntelResult:
        """Run the task and return its structured result (never raises)."""
        ...


def empty_result(task: CollectTask, note: str) -> IntelResult:
    """A no-data result for a task (dead source, nothing found) -- never an error."""
    return IntelResult(
        task_id=task.id, source=task.source, subject=task.subject, note=note
    )


def collector_uses_driver(collector: Collector[Any]) -> bool:
    """Whether this collector may drive a browser, so it must run serially.

    A collector that can render through ``ctx.driver_factory()`` (the active
    OSINT sources) sets ``uses_driver = True``; the collect step keeps those off
    the thread pool so a parallel superstep never spawns a browser pool (the one
    hard constraint on D1 parallelism). Everything else is pure I/O and defaults
    to False, so it may run concurrently.
    """
    return bool(getattr(collector, "uses_driver", False))


def collector_for[TaskT: CollectTask](
    source: str, collectors: tuple[Collector[TaskT], ...]
) -> Collector[TaskT] | None:
    """The collector handling ``source``, or None when none is registered.

    Generic over the task type so both loops share it: a narrower ``Literal``
    source (``OsintSource``/``ResearchSource``) is a ``str`` and matches here.
    """
    return next((c for c in collectors if c.source == source), None)
