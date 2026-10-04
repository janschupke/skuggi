"""Render a forensics case run into a cited Markdown (+ optional PDF) report.

The forensics analogue of ``research.report``: it reads the chain of custody back
from the case ledger (acquisition + procedure), the confirmed findings (ledger),
and the examiner's profile + speculative candidates (the verdict), and composes a
Markdown case report. Confirmed findings cite their evidence; speculative
candidates are a clearly-marked "to validate" section so nothing unproven reads as
fact. The body is redacted before it touches disk and the path is confined under
the case ``forensics`` dir. PDF is best-effort (the ``pdf`` extra).
"""

from __future__ import annotations

from pathlib import Path

from skuggi.common.clock import file_stamp, now_iso
from skuggi.common.logs import get_logger
from skuggi.common.paths import confine_under, ensure_parent
from skuggi.common.text import slug
from skuggi.forensics.deps import ForensicsDeps
from skuggi.forensics.schema import ForensicsVerdict
from skuggi.persistence.ledger_schema import EvidenceRow, FindingRow, ProcedureRow
from skuggi.security.policy import RedactionPolicy
from skuggi.security.tripwire import scrub

log = get_logger(__name__)


def _acquisition_table(rows: list[EvidenceRow]) -> str:
    if not rows:
        return "## Evidence\n\n_No evidence acquired._"
    lines = [
        "## Evidence (acquisition)",
        "",
        "| ID | Source | Type | Size | SHA-256 |",
        "| --- | --- | --- | --- | --- |",
    ]
    lines.extend(
        f"| {r.note or r.id} | `{r.source_path}` | {r.media_type or '—'} "
        f"| {r.size} | `{r.sha256}` |"
        for r in rows
    )
    return "\n".join(lines)


def _procedure_table(rows: list[ProcedureRow]) -> str:
    if not rows:
        return "## Procedure\n\n_No operations recorded._"
    lines = [
        "## Procedure (chain of custody)",
        "",
        "| Step | Operation | Actor | Evidence | Output digest |",
        "| --- | --- | --- | --- | --- |",
    ]
    lines.extend(
        f"| {r.step} | {r.operation} | {r.actor} | {r.note or '—'} "
        f"| `{r.output_digest[:16]}…` |"
        for r in rows
    )
    return "\n".join(lines)


def _confirmed_findings(rows: list[FindingRow]) -> str:
    if not rows:
        return "## Findings\n\n_No confirmed findings._"
    lines = ["## Findings (confirmed)"]
    for f in rows:
        lines.append(f"\n### {f.severity.upper()}: {f.title}")
        if f.description:
            lines.append(f"\n{f.description}")
        if f.evidence:
            lines.append(f"\n_Evidence: {f.evidence}_")
    return "\n".join(lines)


def _speculative_section(verdict: ForensicsVerdict | None) -> str:
    if verdict is None:
        return ""
    specs = [f for f in verdict.findings if f.speculative]
    if not specs:
        return ""
    lines = ["## ⚠ Speculative — to validate", ""]
    lines.append(
        "_These are unproven hypotheses, not confirmed findings. Each must be "
        "corroborated against the evidence before it is relied on._\n"
    )
    for f in specs:
        refs = f", refs: {', '.join(f.evidence_refs)}" if f.evidence_refs else ""
        lines.append(f"- **[{f.severity}]** {f.title} — {f.description}{refs}")
    return "\n".join(lines)


def _profile_block(verdict: ForensicsVerdict | None) -> str:
    if verdict is None or verdict.profile is None:
        return ""
    p = verdict.profile
    lines = ["## Summary"]
    if p.summary:
        lines.append(f"\n{p.summary}")
    if p.artifact_types:
        lines.append(f"\n- **Artifact types:** {', '.join(p.artifact_types)}")
    if p.notable:
        lines.append(f"- **Notable:** {', '.join(p.notable)}")
    return "\n".join(lines)


def render_report(
    case_name: str,
    evidence: list[EvidenceRow],
    procedure: list[ProcedureRow],
    findings: list[FindingRow],
    verdict: ForensicsVerdict | None,
) -> str:
    """Compose the Markdown case report from the custody record + the verdict."""
    blocks = [
        f"# Forensics case: {case_name}",
        f"_generated {now_iso()}_",
        _profile_block(verdict),
        _acquisition_table(evidence),
        _procedure_table(procedure),
        _confirmed_findings(findings),
        _speculative_section(verdict),
    ]
    return "\n\n".join(b for b in blocks if b) + "\n"


def write_case_report(
    deps: ForensicsDeps, verdict: ForensicsVerdict | None
) -> Path | None:
    """Render + write the case report (Markdown, plus best-effort PDF); return its path.

    Reads the custody record back from the case ledger (the source of truth), so
    the report reflects exactly what was recorded. Returns ``None`` when no case
    ledger/output is wired (nothing to report).
    """
    if deps.ledger is None or deps.output_root is None:
        return None
    evidence = deps.ledger.evidence_for(deps.session_id)
    procedure = deps.ledger.procedure_for(deps.session_id)
    findings = deps.ledger.findings_for(deps.session_id)
    body = render_report(
        deps.case_name or "case", evidence, procedure, findings, verdict
    )
    policy = deps.redaction_policy or RedactionPolicy()
    name = f"{slug(deps.case_name or 'case')}-{file_stamp()}.md"
    # The human-facing report goes to the conventional reports/ dir; the per-file
    # JSON artifacts stay under output_root (forensics/).
    reports_dir = (
        deps.workspace.reports_dir if deps.workspace is not None else deps.output_root
    )
    path = confine_under(reports_dir, name)
    ensure_parent(path)
    path.write_text(scrub(body, policy), encoding="utf-8")
    _maybe_pdf(path, scrub(body, policy), deps.case_name or "case")
    return path


def _maybe_pdf(md_path: Path, body: str, title: str) -> None:
    """Render a sibling PDF, best effort (the optional ``pdf`` extra)."""
    try:
        from skuggi.persistence import pdf  # noqa: PLC0415

        pdf.markdown_to_pdf(
            body, md_path.with_suffix(".pdf"), title=f"Forensics case: {title}"
        )
    except (ImportError, OSError, ValueError) as exc:
        log.info("case PDF not rendered (%s); Markdown report is at %s", exc, md_path)
