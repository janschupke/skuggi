"""The findings database boundary: stored raw, redacted before the model.

The audit question these pin: a finding may hold a secret (evidence lifted from a
target, an operator note); storage is acceptable, reaching the model is not.
These assert the model-facing finding path -- the per-turn FindingBrief -- never
carries a raw secret, that `evidence` reaches it at all, and that an
operator-added finding's title is redacted the same as the worker's.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from skuggi.agent.graph import GraphDeps, _finding_briefs
from skuggi.persistence.ledger import Ledger, open_ledger
from skuggi.security.policy import RedactionPolicy
from skuggi.security.tripwire import assert_clean
from skuggi.security.vault import SecretVault, open_vault

SECRET = "ghp_1234567890abcdefABCDEF1234567890abcd"
EVIDENCE_SECRET = "sk-abcdefghijklmnopqrstuvwxyz0123"


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with open_ledger(tmp_path / "ledger.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        yield led


@pytest.fixture
def vault(tmp_path: Path) -> Iterator[SecretVault]:
    with open_vault(tmp_path / ".vault.db") as vlt:
        yield vlt


def _deps(ledger: Ledger, vault: SecretVault) -> GraphDeps:
    return GraphDeps(
        ledger=ledger,
        session_id="s1",
        redaction_policy=RedactionPolicy(),
        vault=vault,
    )


def test_finding_brief_redacts_title_and_never_carries_evidence(
    ledger: Ledger, vault: SecretVault
) -> None:
    ledger.record_finding(
        session_id="s1",
        title=f"leaked token {SECRET}",
        description=f"the service returned {EVIDENCE_SECRET}",
        severity="high",
        evidence=f"raw dump: {EVIDENCE_SECRET}",
    )
    briefs = _finding_briefs(_deps(ledger, vault))
    assert briefs, "no brief produced"
    brief = briefs[0]
    # The title is redacted (and reversible via the vault)...
    assert SECRET not in brief.title
    assert vault.rehydrate(brief.title) == f"leaked token {SECRET}"
    # ...and the brief has no field that could carry evidence at all.
    rendered = f"{brief.id} {brief.severity} {brief.title} {brief.command_id}"
    assert EVIDENCE_SECRET not in rendered
    assert_clean(rendered, RedactionPolicy())


def test_operator_added_finding_title_is_redacted_too(
    ledger: Ledger, vault: SecretVault
) -> None:
    # An operator `add finding` stores raw (description defaults to the title).
    ledger.record_finding(
        session_id="s1",
        title=f"found creds {SECRET}",
        description=f"found creds {SECRET}",
        severity="medium",
    )
    briefs = _finding_briefs(_deps(ledger, vault))
    assert SECRET not in briefs[0].title


def test_storage_keeps_the_finding_raw(ledger: Ledger) -> None:
    # Storage is acceptable: the ledger holds the real text for the report.
    ledger.record_finding(
        session_id="s1",
        title=f"leaked token {SECRET}",
        description="d",
        severity="high",
        evidence=f"raw dump: {EVIDENCE_SECRET}",
    )
    row = ledger.findings_for("s1")[-1]
    assert SECRET in row.title
    assert EVIDENCE_SECRET in row.evidence
