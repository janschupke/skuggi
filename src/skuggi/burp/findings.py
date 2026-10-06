"""Map a Burp scanner issue onto a skuggi :class:`FindingDraft`.

The scanner issue is the unit that becomes a finding. This module is the single
translation point: Burp severity -> the finding vocabulary, confidence -> whether
to auto-record or hold for review, request/response proof -> evidence items, and
CWE -> a finding ref. The resulting draft flows through the same
``record_finding_drafts`` sink the worker and the OSINT verifier use, so Burp
findings are indistinguishable from any other agent finding downstream.

A re-scan re-emits the same issues, so :func:`issue_dedup_key` gives each issue a
stable identity (type + locus) the caller uses to skip ones already recorded.
"""

from __future__ import annotations

from typing import cast

from skuggi.agent.protocol import (
    AffectedAsset,
    FindingDraft,
    FindingEvidenceItem,
    FindingRefDraft,
    Severity,
)
from skuggi.burp.models import BurpConfidence, HttpExchange, ScanIssue

# Burp confidence ranked low->high, so a caller can set a floor (e.g. "firm" to
# drop tentative issues from auto-recording).
_CONFIDENCE_RANK: dict[BurpConfidence, int] = {
    "tentative": 0,
    "firm": 1,
    "certain": 2,
}

# The dedup identity of an issue: its type and the exact locus it was proven on. A
# re-scan that re-reports the same issue yields the same key.
DedupKey = tuple[str, str, str, str]


def issue_dedup_key(issue: ScanIssue) -> DedupKey:
    """A stable identity for ``issue`` (type, host, path, parameter)."""
    return (issue.issue_type, issue.host, issue.path, issue.parameter)


def meets_confidence(issue: ScanIssue, floor: BurpConfidence) -> bool:
    """Whether ``issue``'s confidence is at least ``floor`` (for auto-recording)."""
    return _CONFIDENCE_RANK[issue.confidence] >= _CONFIDENCE_RANK[floor]


def _evidence_items(
    exchanges: tuple[HttpExchange, ...],
) -> tuple[FindingEvidenceItem, ...]:
    """The request/response proof items for an issue's attached exchanges."""
    items: list[FindingEvidenceItem] = []
    for exchange in exchanges:
        if exchange.request:
            items.append(FindingEvidenceItem(kind="request", content=exchange.request))
        if exchange.response:
            items.append(
                FindingEvidenceItem(kind="response", content=exchange.response)
            )
    return tuple(items)


def _refs(issue: ScanIssue) -> tuple[FindingRefDraft, ...]:
    """The finding refs for an issue's CWE ids (normalised, invalid ones dropped)."""
    refs: list[FindingRefDraft] = []
    for raw in issue.cwe:
        digits = raw.strip().upper().removeprefix("CWE-")
        if not digits.isdigit():
            continue
        try:
            refs.append(FindingRefDraft(framework="cwe", ref_id=f"CWE-{digits}"))
        except ValueError:
            continue
    return tuple(refs)


def _description(issue: ScanIssue) -> str:
    """The finding body: Burp's detail, background and the confidence it carries."""
    parts = [issue.detail.strip()]
    if issue.background.strip():
        parts.append(issue.background.strip())
    parts.append(f"(Burp confidence: {issue.confidence}.)")
    return "\n\n".join(p for p in parts if p)


def issue_to_draft(issue: ScanIssue) -> FindingDraft:
    """Translate one scanner issue into a recordable :class:`FindingDraft`.

    Burp reports no CVSS vector, so the finding carries Burp's qualitative severity
    directly (``high``/``medium``/``low``/``info`` -- Burp has no ``critical``
    band). The raw request/response pairs become evidence items (stored, never
    model-facing); the issue's confidence is surfaced in the description so a
    reviewer sees how firm the detection was.
    """
    affected = AffectedAsset(
        host=issue.host,
        port=str(issue.port) if issue.port else "",
        url=issue.url,
        parameter=issue.parameter,
    )
    return FindingDraft(
        title=issue.name,
        description=_description(issue),
        remediation=issue.remediation,
        severity=cast("Severity", issue.severity),
        affected=affected,
        evidence_items=_evidence_items(issue.evidence),
        refs=_refs(issue),
    )
