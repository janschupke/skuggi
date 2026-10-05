"""The agent's finding recall is engagement-scoped, not session-scoped.

The audit gap these pin (G1): ``session_id`` is a fresh UUID every launch, so a
session-only recall would blank the agent's memory of what it found on an earlier
day of the same engagement. ``_finding_briefs`` must span every session of the
loaded engagement, and fall back to the session only in agent-only mode (no
engagement), where there is no engagement to scope to.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from skuggi.agent.graph import GraphDeps, _finding_briefs
from skuggi.engagement.engagement import EngagementConfig
from skuggi.persistence.ledger import Ledger, open_ledger
from skuggi.security.policy import RedactionPolicy
from skuggi.security.vault import SecretVault, open_vault


def _engagement(name: str = "e") -> EngagementConfig:
    return EngagementConfig.model_validate(
        {
            "name": name,
            "timezone": "UTC",
            "authorized_start": datetime(2026, 1, 1, tzinfo=UTC),
            "authorized_end": datetime(2026, 12, 31, 23, 59, tzinfo=UTC),
            "target_networks": ("10.0.0.0/8",),
            "allowed_hosts": frozenset({"scanme.example.com"}),
            "allowed_tools": frozenset({"nmap"}),
            "allowed_methods": frozenset({"scan"}),
        }
    )


@pytest.fixture
def vault(tmp_path: Path) -> Iterator[SecretVault]:
    with open_vault(tmp_path / ".vault.db") as vlt:
        yield vlt


def _deps(
    ledger: Ledger,
    vault: SecretVault,
    *,
    session_id: str,
    engagement: EngagementConfig | None,
) -> GraphDeps:
    return GraphDeps(
        ledger=ledger,
        session_id=session_id,
        engagement=engagement,
        redaction_policy=RedactionPolicy(),
        vault=vault,
    )


def test_recall_spans_prior_sessions_of_the_engagement(
    tmp_path: Path, vault: SecretVault
) -> None:
    """A finding from an earlier session is recalled in a fresh one, same engagement."""
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("day1", engagement_name="e", mode="pentest")
        led.record_finding(
            session_id="day1", title="open telnet", severity="high", description="d"
        )
        # A new launch: a brand-new session id, nothing recorded in it yet.
        led.start_session("day2", engagement_name="e", mode="pentest")

        briefs = _finding_briefs(
            _deps(led, vault, session_id="day2", engagement=_engagement())
        )
        assert [b.title for b in briefs] == ["open telnet"]


def test_agent_only_recall_stays_session_scoped(
    tmp_path: Path, vault: SecretVault
) -> None:
    """With no engagement loaded, recall falls back to the current session alone."""
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s0", engagement_name="(none)", mode="pentest")
        led.record_finding(
            session_id="s0", title="prior", severity="low", description="d"
        )
        led.start_session("s1", engagement_name="(none)", mode="pentest")
        led.record_finding(
            session_id="s1", title="current", severity="low", description="d"
        )

        briefs = _finding_briefs(_deps(led, vault, session_id="s1", engagement=None))
        assert [b.title for b in briefs] == ["current"]


def test_recall_respects_the_findings_limit(tmp_path: Path, vault: SecretVault) -> None:
    """The brief keeps only the most recent ``findings_limit`` across the engagement."""
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        for i in range(5):
            led.record_finding(
                session_id="s1", title=f"f{i}", severity="low", description="d"
            )
        deps = GraphDeps(
            ledger=led,
            session_id="s1",
            engagement=_engagement(),
            redaction_policy=RedactionPolicy(),
            vault=vault,
            findings_limit=2,
        )
        briefs = _finding_briefs(deps)
        assert [b.title for b in briefs] == ["f3", "f4"]
