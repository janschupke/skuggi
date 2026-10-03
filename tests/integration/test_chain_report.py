"""L2: the finding -> scoring -> report chain, end to end but offline.

The lab-free complement to ``tests/e2e/test_lab_engagement.py``'s report case.
It drives a real ``AgentCore`` turn (real guard, ledger, checkpointer; scripted
worker, fake embeddings) with the worker emitting a ``FindingDraft`` that carries
a ``cvss_vector``, then asserts the chain nobody tests end-to-end in the gate:
the worker's vector is scored by the harness, lands in the ledger with the
derived severity band, and renders into the right section of the Markdown report.

Non-autonomous by design, so the proposed command is recorded but never executed
-- no subprocess, so this runs inside ``make check`` with the rest of L2.
"""

from __future__ import annotations

from pathlib import Path

from skuggi.agent.core import AgentCore
from skuggi.agent.protocol import CriticResponse, FindingDraft, WorkerResponse
from skuggi.common import palette
from skuggi.frameworks import cvss
from tests.fakes import RoleScriptedChatModel
from tests.support import engaged_core, wire_offline_llm

# Pinned vectors with bands verified against skuggi's own CVSS oracle below.
_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"  # 10.0
_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5
_MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"  # 4.3
_IN_SCOPE_CMD = "curl -s http://10.0.0.5/"


def _scope(name: str, **over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "name": name,
        "timezone": "UTC",
        "authorized_start": "2000-01-01T00:00:00+00:00",
        "authorized_end": "2999-12-31T23:59:59+00:00",
        "daily_windows": [{"start": "00:00:00", "end": "23:59:59"}],
        "target_networks": ["10.0.0.0/8"],
        "allowed_hosts": [],
        "allowed_tools": ["curl", "nmap"],
        "allowed_methods": ["recon", "scan"],
        "autonomous": False,
    }
    base.update(over)
    return base


def _run_turn(
    tmp_path: Path,
    name: str,
    worker: WorkerResponse,
    *,
    scope_over: dict[str, object] | None = None,
) -> AgentCore:
    """A single offline, non-autonomous turn; returns the core for inspection."""
    core = engaged_core(tmp_path, _scope(name, **(scope_over or {})))
    wire_offline_llm(
        core,
        RoleScriptedChatModel(
            worker_replies=[worker],
            critic_replies=[CriticResponse(approved=True, reason="ok")],
        ),
    )
    list(core.turn("assess the host"))
    return core


def _report_text(core: AgentCore, *, approve: bool = True) -> str:
    if approve:
        for f in core.ledger.findings_for(core.session_id):
            core.ledger.set_finding_status(f.id, "approved")
    report = core.journal.write_report()
    assert isinstance(report, Path)
    return report.read_text(encoding="utf-8")


def test_cvss_vectors_score_to_the_expected_bands() -> None:
    """Pin the fixtures: the oracle, not a comment, defines each band."""
    assert cvss.score(_CRITICAL).severity == "critical"
    assert cvss.score(_HIGH).severity == "high"
    assert cvss.score(_MEDIUM).severity == "medium"


def test_worker_vector_becomes_ledger_band_and_report_section(tmp_path: Path) -> None:
    finding = FindingDraft(
        title="SQLi dumps password hashes",
        description="id= concatenates into a numeric SQL context.",
        evidence="admin:5f4dcc3b5aa765d61d8327deb882cf99 recovered via UNION",
        cvss_vector=_HIGH,
    )
    core = _run_turn(
        tmp_path,
        "chain-band",
        WorkerResponse(command=_IN_SCOPE_CMD, findings=(finding,), done=True),
    )

    # The harness scored the worker's vector into the ledger with the derived band.
    rows = core.ledger.findings_for(core.session_id)
    assert len(rows) == 1
    row = rows[0]
    assert row.cvss_vector == _HIGH
    assert row.cvss_severity == "high"
    assert row.severity == "high"  # derived band is the recorded severity
    assert finding.display_severity() == "high"  # protocol agrees with the ledger
    assert row.command_id is not None  # linked to the proposed command

    text = _report_text(core)
    assert "### HIGH (1)" in text
    assert finding.title in text
    assert f"_(from cmd:{row.command_id})_" in text
    assert _IN_SCOPE_CMD in text  # the command log carries the proposed command
    assert _HIGH in text  # the CVSS line prints the vector


def test_report_groups_findings_in_severity_order(tmp_path: Path) -> None:
    findings = (
        FindingDraft(title="med finding", description="d", cvss_vector=_MEDIUM),
        FindingDraft(title="crit finding", description="d", cvss_vector=_CRITICAL),
        FindingDraft(title="info note", description="d", severity="info"),
        FindingDraft(title="high finding", description="d", cvss_vector=_HIGH),
    )
    core = _run_turn(
        tmp_path,
        "chain-order",
        WorkerResponse(command=_IN_SCOPE_CMD, findings=findings, done=True),
    )
    text = _report_text(core)

    headings = ["### CRITICAL (1)", "### HIGH (1)", "### MEDIUM (1)", "### INFO (1)"]
    positions = [text.index(h) for h in headings]
    assert positions == sorted(positions)  # critical -> high -> medium -> info
    # The order matches the canonical palette order, not an accident of insertion.
    assert [h.split()[1] for h in headings] == [
        s.upper() for s in palette.severities() if s != "low"
    ]


def test_report_contains_only_approved_findings(tmp_path: Path) -> None:
    findings = (
        FindingDraft(title="approved one", description="d", cvss_vector=_HIGH),
        FindingDraft(title="left as draft", description="d", cvss_vector=_CRITICAL),
    )
    core = _run_turn(
        tmp_path,
        "chain-approve",
        WorkerResponse(command=_IN_SCOPE_CMD, findings=findings, done=True),
    )
    rows = {f.title: f for f in core.ledger.findings_for(core.session_id)}
    assert all(f.status == "draft" for f in rows.values())  # born draft

    core.ledger.set_finding_status(rows["approved one"].id, "approved")
    text = _report_text(core, approve=False)

    assert "approved one" in text
    assert "left as draft" not in text
    assert "### CRITICAL" not in text  # the only critical was left a draft
    assert "(1 draft/rejected excluded)" in text


def test_operator_finding_shares_the_chain(tmp_path: Path) -> None:
    """An operator `add finding` lands in the same ledger and report as the agent's."""
    core = engaged_core(tmp_path, _scope("chain-operator"))
    wire_offline_llm(core, RoleScriptedChatModel(worker_replies=[WorkerResponse()]))

    row = core.journal.record_finding(
        title="Operator-entered RCE", cvss_vector=_CRITICAL
    )
    assert row is not None
    assert row.author == "operator"
    assert row.cvss_severity == "critical"

    core.ledger.set_finding_status(row.id, "approved")
    report = core.journal.write_report()
    assert isinstance(report, Path)
    text = report.read_text(encoding="utf-8")
    assert "### CRITICAL (1)" in text
    assert "Operator-entered RCE" in text
