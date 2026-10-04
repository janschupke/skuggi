"""The generic corpus an intelligence collector produces, shared by both loops.

``IntelItem`` is one datum (a subdomain, a repo, a CVE, a version) and
``IntelResult`` is one task's collected output -- deliberately source-agnostic so
one artifact schema serves every collector in both the OSINT and the research
loop. ``CollectTask`` is the minimal read-only view of a task a collector needs,
so ``osint.OsintTask`` and ``research.ResearchTask`` both satisfy it structurally
without either importing the other.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class IntelItem(BaseModel):
    """One datum a collector found (a subdomain, repo, cert, CVE, version, ...).

    Deliberately generic: ``kind`` names the datum type and ``attributes`` carries
    source-specific detail, so one schema serves every source without a per-source
    table.
    """

    model_config = ConfigDict(frozen=True)

    kind: str
    value: str
    attributes: dict[str, str] = Field(default_factory=dict)


class IntelResult(BaseModel):
    """One task's collected output, written as a JSON artifact and fed back.

    ``items`` is the structured corpus; ``note`` is a short free-text summary the
    verifier and the next planner pass read. An empty ``items`` with a ``note`` is a
    legitimate "nothing found / source unavailable" result -- never an error.
    """

    model_config = ConfigDict(frozen=True)

    task_id: str
    source: str
    subject: str
    items: tuple[IntelItem, ...] = ()
    note: str = ""


@runtime_checkable
class CollectTask(Protocol):
    """The read-only view of a task a collector reads (id/source/subject/objective).

    Read-only properties (not settable attributes) so a concrete task whose
    ``source`` is a narrower ``Literal`` still satisfies the protocol covariantly.
    Both ``OsintTask`` and ``ResearchTask`` match it without a shared base class.
    """

    @property
    def id(self) -> str:
        """The task's unique id."""

    @property
    def source(self) -> str:
        """The source name this task is dispatched to."""

    @property
    def subject(self) -> str:
        """The subject the task acts on."""

    @property
    def objective(self) -> str:
        """The concrete objective of the task."""
