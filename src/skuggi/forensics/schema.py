"""The strict structured protocol for the forensics loop.

The collected corpus reuses the shared :mod:`skuggi.intel.schema`
``IntelItem``/``IntelResult`` (one result per evidence file, its analyzer
observations as items). Forensics-specific are the examiner's verdict types: a
``CaseProfile`` and severity-only ``ForensicsFinding``s, each carrying
``evidence_refs`` -- the anti-hallucination contract the loop enforces
deterministically (a finding whose refs do not resolve is demoted to speculative).
There is no CVSS here: a forensic finding is scored by a plain severity band.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

# Evidence IDs the collect phase assigns (``E1``, ``E2`` …) and feeds to the
# examiner; a finding cites these so grounding can be checked without trusting the
# model's prose.
ForensicsSeverity = Literal["info", "low", "medium", "high", "critical"]


class ForensicsFinding(BaseModel):
    """One examiner finding, grounded in cited evidence and severity-scored.

    ``evidence_refs`` name the evidence IDs (and/or observation offsets) the finding
    rests on. ``speculative`` is the model's own flag; the loop additionally FORCES
    it true when a ref does not resolve, so an ungrounded claim can never read as
    confirmed.
    """

    model_config = ConfigDict(frozen=True)

    title: str
    severity: ForensicsSeverity = "info"
    description: str = ""
    evidence_refs: tuple[str, ...] = ()
    speculative: bool = False


class CaseProfile(BaseModel):
    """The examiner's structured overview of the case (the report's backbone)."""

    model_config = ConfigDict(frozen=True)

    summary: str = ""
    artifact_types: tuple[str, ...] = ()
    notable: tuple[str, ...] = ()


class ForensicsVerdict(BaseModel):
    """The examiner's strict output: a case profile plus grounded findings."""

    model_config = ConfigDict(frozen=True)

    profile: CaseProfile | None = None
    findings: tuple[ForensicsFinding, ...] = ()
    summary: str = ""
