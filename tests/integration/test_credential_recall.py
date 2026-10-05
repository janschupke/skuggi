"""Captured credentials are recalled by nature, engagement-wide, never by value.

Part of closing the write-only gap (G2): ``add cred`` already stored credentials
structurally (the secret vaulted, only a ``secret_ref`` placeholder kept), but they
never reached the agent. Recall now surfaces each credential's nature -- who/where
and the ``«CRED:id»`` placeholder the worker can use in a command -- across every
session of the engagement, with the plaintext secret never present in the brief.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from skuggi.agent.graph import GraphDeps, _credential_briefs
from skuggi.engagement.engagement import EngagementConfig
from skuggi.persistence.ledger import Ledger, open_ledger
from skuggi.security.policy import RedactionPolicy
from skuggi.security.vault import SecretVault, open_vault
from tests.integration.test_finding_recall import _engagement


@pytest.fixture
def vault(tmp_path: Path) -> Iterator[SecretVault]:
    with open_vault(tmp_path / ".vault.db") as vlt:
        yield vlt


def _deps(
    ledger: Ledger, vault: SecretVault, *, engagement: EngagementConfig | None
) -> GraphDeps:
    return GraphDeps(
        ledger=ledger,
        session_id="day2",
        engagement=engagement,
        redaction_policy=RedactionPolicy(),
        vault=vault,
    )


def test_credentials_recalled_across_sessions_by_nature(
    tmp_path: Path, vault: SecretVault
) -> None:
    """A credential captured in an earlier session is recalled in a fresh one."""
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("day1", engagement_name="e", mode="pentest")
        ref = vault.intern("hunter2", "CRED")
        led.record_credential(
            session_id="day1",
            host="web01",
            service="ssh",
            username="admin",
            secret_ref=ref,
            validated=True,
        )
        led.start_session("day2", engagement_name="e", mode="pentest")

        briefs = _credential_briefs(_deps(led, vault, engagement=_engagement()))
        assert len(briefs) == 1
        brief = briefs[0]
        assert (brief.host, brief.username, brief.service) == ("web01", "admin", "ssh")
        assert brief.secret_ref == ref
        # The placeholder is model-safe; the plaintext secret is not a field at all.
        assert "hunter2" not in f"{brief.model_dump()}"


def test_credentials_recall_dedupes_across_sessions(
    tmp_path: Path, vault: SecretVault
) -> None:
    """The same credential captured in two sessions collapses to one brief."""
    with open_ledger(tmp_path / "l.db") as led:
        ref = vault.intern("s3cr3t", "CRED")
        for sid in ("day1", "day2"):
            led.start_session(sid, engagement_name="e", mode="pentest")
            led.record_credential(
                session_id=sid,
                host="db1",
                service="psql",
                username="root",
                secret_ref=ref,
            )
        briefs = _credential_briefs(_deps(led, vault, engagement=_engagement()))
        assert [b.host for b in briefs] == ["db1"]


def test_credentials_recall_is_session_scoped_without_engagement(
    tmp_path: Path, vault: SecretVault
) -> None:
    """Agent-only mode (no engagement) falls back to the current session alone."""
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("day1", engagement_name="(none)", mode="pentest")
        led.record_credential(session_id="day1", host="old", username="u")
        led.start_session("day2", engagement_name="(none)", mode="pentest")
        led.record_credential(session_id="day2", host="cur", username="u")

        briefs = _credential_briefs(_deps(led, vault, engagement=None))
        assert [b.host for b in briefs] == ["cur"]
