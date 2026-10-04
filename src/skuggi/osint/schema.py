"""The strict structured protocol for the OSINT loop.

Kept out of ``agent.protocol`` (near its 700-line cap, and a different subsystem):
the OSINT planner's todo DAG, a collector's structured result, and the datum type
inside it. Findings the loop wants on the engagement report are NOT a new type --
the loop reuses ``agent.protocol.FindingDraft`` and the existing
``ledger.record_finding`` path, so OSINT findings flow through CVSS scoring,
review and the report with no parallel reporting code.

Every model is frozen and validates at the boundary, exactly like the turn
protocol, so ``structured_invoke`` can enforce the planner's schema and a test can
assert the DAG shape rather than eyeball a string.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from skuggi.agent.protocol import FindingDraft
from skuggi.engagement.scope import OsintSource


class OsintTask(BaseModel):
    """One unit of OSINT work the planner schedules.

    ``depends_on`` names the ids of tasks whose results this one needs first (e.g.
    enumerate subdomains before fetching each one's certificates), so the planner
    expresses a DAG and the scheduler walks it dependency-first. ``subject`` is the
    organization / domain / person / github org the task acts on -- scope-checked
    against the OSINT boundary before the task ever runs.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    source: OsintSource
    subject: str
    objective: str
    depends_on: tuple[str, ...] = ()


class OsintPlan(BaseModel):
    """The planner's strict output: the todo DAG (or an empty plan)."""

    model_config = ConfigDict(frozen=True)

    tasks: tuple[OsintTask, ...] = ()
    rationale: str = ""


class OsintItem(BaseModel):
    """One datum a collector found (a subdomain, repo, cert, role, email, …).

    Deliberately generic: ``kind`` names the datum type and ``attributes`` carries
    source-specific detail, so one artifact schema serves every source without a
    per-source table. The security-relevant subset is promoted to a ``FindingDraft``
    separately; this is the full machine-readable corpus.
    """

    model_config = ConfigDict(frozen=True)

    kind: str
    value: str
    attributes: dict[str, str] = Field(default_factory=dict)


class OsintResult(BaseModel):
    """One task's collected output, written as a JSON artifact and fed back.

    ``items`` is the structured corpus; ``note`` is a short free-text summary the
    verifier and the next planner pass read. An empty ``items`` with a ``note`` is a
    legitimate "nothing found / source unavailable" result -- never an error.
    """

    model_config = ConfigDict(frozen=True)

    task_id: str
    source: OsintSource
    subject: str
    items: tuple[OsintItem, ...] = ()
    note: str = ""


class OsintVerdict(BaseModel):
    """The verifier's strict output: coverage judgement + findings + a summary.

    ``done`` ends the loop; otherwise ``gaps`` (objectives/sources still to cover)
    feed the next planner pass, bounded by the replan cap. ``findings`` are the
    security-relevant items the verifier promotes -- reused ``FindingDraft``s that
    flow through the existing ledger/report path. ``summary`` is the operator-facing
    answer the loop renders.
    """

    model_config = ConfigDict(frozen=True)

    done: bool = False
    gaps: tuple[str, ...] = ()
    summary: str = ""
    findings: tuple[FindingDraft, ...] = ()
