"""The forensics loop's three nodes: collect -> examine -> respond.

``collect`` runs the deterministic analyzer battery (``forensics.collect``) and
records the chain of custody. ``examine`` asks the examiner for a structured
``ForensicsVerdict`` and then DETERMINISTICALLY grounds it -- any finding whose
``evidence_refs`` do not resolve to a collected evidence ID is forced speculative,
so the model can never promote an ungrounded claim to confirmed; confirmed findings
are recorded to the case ledger. ``respond`` writes the cited case report.
"""

from __future__ import annotations

from typing import cast

from langchain_core.messages import AIMessage

from skuggi.agent import requests
from skuggi.common.logs import get_logger
from skuggi.forensics import report as report_mod
from skuggi.forensics.collect import collect_evidence
from skuggi.forensics.deps import ForensicsDeps
from skuggi.forensics.schema import ForensicsFinding, ForensicsVerdict
from skuggi.intel.schema import IntelResult
from skuggi.persistence.ledger_schema import FindingAuthor
from skuggi.security.policy import RedactionPolicy

log = get_logger(__name__)

# How many observations per evidence item to show the examiner (the capture stays
# bounded; the full corpus is on disk as the JSON artifacts).
_ITEMS_SHOWN = 40


def collect_node(_state: dict[str, object], deps: ForensicsDeps) -> dict[str, object]:
    """Run the analyzer battery over the evidence; return the per-file results."""
    results = collect_evidence(deps)
    return {"results": results}


def _evidence_block(results: list[IntelResult]) -> str:
    """A bounded text view of the collected evidence + observations for the examiner."""
    blocks: list[str] = []
    for r in results:
        lines = [f"{r.task_id} ({r.subject}): {r.note}"]
        for item in r.items[:_ITEMS_SHOWN]:
            attrs = " ".join(f"{k}={v}" for k, v in item.attributes.items())
            lines.append(f"  - [{item.kind}] {item.value}  ({attrs})")
        if len(r.items) > _ITEMS_SHOWN:
            lines.append(f"  … {len(r.items) - _ITEMS_SHOWN} more observations")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks) if blocks else "(no evidence collected)"


def _ground(verdict: ForensicsVerdict, valid_ids: set[str]) -> ForensicsVerdict:
    """Force a finding speculative when its evidence refs do not all resolve.

    The anti-hallucination gate: the model's own ``speculative`` flag is honoured,
    but a finding with no refs, or any ref that is not a collected evidence ID, is
    additionally forced speculative -- an ungrounded claim can never read confirmed.
    """

    def _norm(value: str) -> str:
        return value.strip().upper()

    valid = {_norm(v) for v in valid_ids}
    grounded: list[ForensicsFinding] = []
    for f in verdict.findings:
        refs = tuple(ref for ref in f.evidence_refs)
        resolved = bool(refs) and all(_norm(ref) in valid for ref in refs)
        grounded.append(
            f
            if (resolved and not f.speculative)
            else f.model_copy(update={"speculative": True})
        )
    return verdict.model_copy(update={"findings": tuple(grounded)})


def examine_node(state: dict[str, object], deps: ForensicsDeps) -> dict[str, object]:
    """Ask the examiner for a verdict, ground it, and record confirmed findings."""
    results = cast("list[IntelResult]", state.get("results", []))
    policy = deps.redaction_policy or RedactionPolicy()
    verdict = requests.ask(
        deps.llm,
        deps.prompts.examiner,
        _evidence_block(results),
        ForensicsVerdict,
        policy=policy,
        native=deps.native_structured,
        label="examiner",
    )
    verdict = _ground(verdict, {r.task_id for r in results})
    # Record only CONFIRMED findings to the case ledger; speculative ones stay in
    # the verdict for the report's clearly-marked "to validate" section.
    if deps.ledger is not None:
        for f in verdict.findings:
            if f.speculative:
                continue
            deps.ledger.record_finding(
                session_id=deps.session_id,
                title=f.title,
                description=f.description,
                severity=f.severity,
                evidence=", ".join(f.evidence_refs),
                author=FindingAuthor.AGENT,
            )
    return {"verdict": verdict, "draft": verdict.summary, "done": True}


def respond_node(state: dict[str, object], deps: ForensicsDeps) -> dict[str, object]:
    """Write the cited case report and emit the operator-facing summary."""
    verdict = state.get("verdict")
    summary = str(state.get("draft", "")) or "forensic examination complete"
    written = report_mod.write_case_report(deps, verdict)  # type: ignore[arg-type]
    if written is not None:
        summary = f"{summary}\n\nReport written to {written}"
    return {"messages": [AIMessage(content=summary)], "draft": summary}
