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

from typing import Protocol, runtime_checkable

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
