"""The strict structured protocol for the public-source research loop.

The todo DAG (``ResearchTask``/``ResearchPlan``) and the verifier's verdict +
assembled profile are research-specific; the collected corpus is the shared
:mod:`skuggi.intel.schema` ``IntelItem``/``IntelResult``. Unlike the OSINT verdict
there are NO ``FindingDraft``s here -- research produces a structured report, not
ledger findings, so it stays decoupled from the engagement ledger.

Every model is frozen and validates at the boundary so ``structured_invoke`` can
enforce the planner/verifier schema and a test can assert the DAG + profile shape.
"""

from __future__ import annotations

from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict

# The public research sources. Every one is a passive, public-data recon query --
# there is deliberately no active/offensive source in this literal, so the loop
# structurally cannot scan a target. ``websearch``/``github`` are the shared
# intel collectors; the rest are research-specific.
ResearchSource = Literal[
    "websearch",
    "github",
    "versions",
    "cve",
    "exploitdb",
    "searchsploit",
    "metasploit",
]
RESEARCH_SOURCES: tuple[ResearchSource, ...] = get_args(ResearchSource)


class ResearchTask(BaseModel):
    """One unit of research work the planner schedules.

    ``depends_on`` names the ids of tasks whose results this one needs first (e.g.
    resolve the latest version before searching that version's CVEs), so the
    planner expresses a DAG and the scheduler walks it dependency-first.
    ``subject`` is a FREE tech/product/service/company string -- not scope-checked,
    because research targets no engagement asset; it only ever reads public data.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    source: ResearchSource
    subject: str
    objective: str
    depends_on: tuple[str, ...] = ()


class ResearchPlan(BaseModel):
    """The planner's strict output: the todo DAG (or an empty plan)."""

    model_config = ConfigDict(frozen=True)

    tasks: tuple[ResearchTask, ...] = ()
    rationale: str = ""


class VulnRef(BaseModel):
    """One known vulnerability / exploit reference the research surfaced.

    Purely descriptive: an identifier (``CVE-...`` / ``EDB-...`` / a metasploit
    module path), a short title, an optional severity/CVSS string, a public link,
    and the source it came from. This is report material, never a scored
    engagement finding.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    title: str = ""
    severity: str = ""
    url: str = ""
    source: str = ""


class ResearchProfile(BaseModel):
    """The verifier's assembled summary of the subject (the report's backbone).

    The structured answer a research run exists to produce: the latest version,
    the versions commonly deployed/supported, what the thing is built on (its
    stack / subsystems), and the known vulnerabilities + exploit links. Any field
    may be empty when a source produced nothing.
    """

    model_config = ConfigDict(frozen=True)

    subject: str
    latest_version: str = ""
    commonly_deployed_versions: tuple[str, ...] = ()
    built_on: tuple[str, ...] = ()
    known_vulnerabilities: tuple[VulnRef, ...] = ()
    notes: str = ""


class ResearchVerdict(BaseModel):
    """The verifier's strict output: coverage judgement + profile + a summary.

    ``done`` ends the loop; otherwise ``gaps`` (objectives/sources still to cover)
    feed the next planner pass, bounded by the replan cap. ``profile`` is the
    structured subject summary the report renders; ``summary`` is the operator-
    facing prose answer.
    """

    model_config = ConfigDict(frozen=True)

    done: bool = False
    gaps: tuple[str, ...] = ()
    summary: str = ""
    profile: ResearchProfile | None = None
