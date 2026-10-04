"""The strict structured protocol for the OSINT loop.

The todo DAG (``OsintTask``/``OsintPlan``) and the verifier's verdict are
OSINT-specific; the collected corpus is not, so ``OsintItem``/``OsintResult`` are
the shared :mod:`skuggi.intel.schema` types, aliased here so the OSINT collectors
and nodes read in their own vocabulary. Findings the loop wants on the engagement
report are NOT a new type -- the loop reuses ``agent.protocol.FindingDraft`` and
the existing ``ledger.record_finding`` path, so OSINT findings flow through CVSS
scoring, review and the report with no parallel reporting code.

Every model is frozen and validates at the boundary, exactly like the turn
protocol, so ``structured_invoke`` can enforce the planner's schema and a test can
assert the DAG shape rather than eyeball a string.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from skuggi.agent.protocol import FindingDraft
from skuggi.engagement.scope import OsintSource
from skuggi.intel.schema import IntelItem, IntelResult

# The collected corpus is subsystem-agnostic (see skuggi.intel.schema); the OSINT
# loop reads it under its own names so collectors stay readable.
OsintItem = IntelItem
OsintResult = IntelResult


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
