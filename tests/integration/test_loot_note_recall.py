"""Structured loot and notes are recalled engagement-wide, by nature, redacted.

Closes the write-only half of G2 for the free-text journals: loot and notes are
structured ledger records now, recalled across the engagement's sessions. The body
is redacted at storage, and the graph re-cleans it as an egress net, so a secret in
a label/note never reaches a brief even if it slipped past the write-time redactor.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from skuggi.agent.graph import GraphDeps, _loot_briefs, _note_briefs
from skuggi.persistence.ledger import Ledger, open_ledger
from skuggi.security.policy import RedactionPolicy
from skuggi.security.redaction import redact
from skuggi.security.vault import SecretVault, open_vault
from tests.integration.test_finding_recall import _engagement

SECRET = "ghp_1234567890abcdefABCDEF1234567890abcd"


@pytest.fixture
def vault(tmp_path: Path) -> Iterator[SecretVault]:
    with open_vault(tmp_path / ".vault.db") as vlt:
        yield vlt


def _deps(ledger: Ledger, vault: SecretVault) -> GraphDeps:
    return GraphDeps(
        ledger=ledger,
        session_id="day2",
        engagement=_engagement(),
        redaction_policy=RedactionPolicy(),
        vault=vault,
    )


def _clean(vault: SecretVault) -> Callable[[str], str]:
    return lambda text: redact(text, RedactionPolicy(), vault)


def test_loot_recalled_across_sessions_by_nature(
    tmp_path: Path, vault: SecretVault
) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("day1", engagement_name="e", mode="pentest")
        led.record_loot(
            session_id="day1", kind="token", host="web01", label="api key on disk"
        )
        led.start_session("day2", engagement_name="e", mode="pentest")

        briefs = _loot_briefs(_deps(led, vault), _clean(vault))
        assert len(briefs) == 1
        assert (briefs[0].kind, briefs[0].host) == ("token", "web01")
        assert briefs[0].label == "api key on disk"


def test_loot_label_is_redacted_in_the_brief(
    tmp_path: Path, vault: SecretVault
) -> None:
    """A secret that reached the label is scrubbed by the graph's egress net."""
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("day2", engagement_name="e", mode="pentest")
        led.record_loot(session_id="day2", kind="token", host="h", label=SECRET)
        briefs = _loot_briefs(_deps(led, vault), _clean(vault))
        assert SECRET not in briefs[0].label
        assert vault.rehydrate(briefs[0].label) == SECRET


def test_notes_recalled_across_sessions_and_redacted(
    tmp_path: Path, vault: SecretVault
) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("day1", engagement_name="e", mode="pentest")
        led.record_note(
            session_id="day1", subject="recon", host="web01", text="telnet open"
        )
        led.record_note(session_id="day1", subject="leak", text=f"saw {SECRET}")
        led.start_session("day2", engagement_name="e", mode="pentest")

        briefs = _note_briefs(_deps(led, vault), _clean(vault))
        assert [b.subject for b in briefs] == ["recon", "leak"]
        assert briefs[0].host == "web01"
        leak = next(b for b in briefs if b.subject == "leak")
        assert SECRET not in leak.text
