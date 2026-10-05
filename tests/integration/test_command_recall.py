"""The agent's command recall spans turns, sourced from the ledger, redacted.

The audit gap these pin (G4): ``state["commands"]`` holds only the current turn's
trail -- the planner resets it each turn -- so the worker forgot what it ran on an
earlier turn. Recall is now a bounded ledger window, and because a persisted row
holds raw captured output, each brief is re-redacted on the way to the model
(secrets vaulted, never echoed).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from skuggi.agent.executor import brief_from_row
from skuggi.agent.graph import GraphDeps, _command_briefs
from skuggi.common.execution import CommandResult
from skuggi.persistence.ledger import Ledger, open_ledger
from skuggi.security.policy import RedactionPolicy
from skuggi.security.redaction import redact
from skuggi.security.vault import SecretVault, open_vault

SECRET = "ghp_1234567890abcdefABCDEF1234567890abcd"
_T0 = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        yield led


@pytest.fixture
def vault(tmp_path: Path) -> Iterator[SecretVault]:
    with open_vault(tmp_path / ".vault.db") as vlt:
        yield vlt


def _deps(ledger: Ledger, vault: SecretVault, *, limit: int = 10) -> GraphDeps:
    return GraphDeps(
        ledger=ledger,
        session_id="s1",
        redaction_policy=RedactionPolicy(),
        vault=vault,
        commands_limit=limit,
    )


def _executed(ledger: Ledger, command: str, stdout: str) -> int:
    return ledger.record_command(
        session_id="s1",
        thread_id="t1",
        command=command,
        binary=command.split(maxsplit=1)[0],
        method="scan",
        status="executed",
        result=CommandResult(
            command=command,
            exit_code=0,
            stdout=stdout,
            stderr="",
            started_at=_T0,
            finished_at=_T0,
        ),
    )


def test_recall_sources_prior_turns_from_the_ledger(
    ledger: Ledger, vault: SecretVault
) -> None:
    """A command from an earlier turn is recalled though the in-turn trail is empty."""
    _executed(ledger, "nmap -sV 10.0.0.5", "22/tcp open ssh")
    # A fresh turn: state["commands"] is empty, but the ledger remembers.
    briefs = _command_briefs(_deps(ledger, vault), {"messages": []}, lambda s: s)
    assert [b.command for b in briefs] == ["nmap -sV 10.0.0.5"]
    assert briefs[0].status == "executed"
    assert "22/tcp open ssh" in briefs[0].summary


def test_recall_respects_the_commands_limit(ledger: Ledger, vault: SecretVault) -> None:
    """Only the most recent ``commands_limit`` commands are recalled (oldest-first)."""
    for i in range(5):
        _executed(ledger, f"curl http://h/{i}", f"body {i}")
    briefs = _command_briefs(
        _deps(ledger, vault, limit=2), {"messages": []}, lambda s: s
    )
    assert [b.command for b in briefs] == ["curl http://h/3", "curl http://h/4"]


def test_recalled_output_is_redacted(ledger: Ledger, vault: SecretVault) -> None:
    """A secret captured in a command's output never re-enters a brief raw."""
    _executed(ledger, "env", f"GITHUB_TOKEN={SECRET}")
    clean = lambda text: redact(text, RedactionPolicy(), vault)  # noqa: E731
    briefs = _command_briefs(_deps(ledger, vault), {"messages": []}, clean)
    assert SECRET not in briefs[0].summary
    assert vault.rehydrate(briefs[0].summary) == f"exit=0\nGITHUB_TOKEN={SECRET}"


def test_brief_from_row_carries_reason_for_a_blocked_command(
    ledger: Ledger, vault: SecretVault
) -> None:
    """A non-executed row has no output; its brief carries the reason, no exit code."""
    cid = ledger.record_command(
        session_id="s1",
        thread_id="t1",
        command="nmap 9.9.9.9",
        binary="nmap",
        method="scan",
        status="blocked",
        reason="host out of scope",
    )
    row = next(r for r in ledger.commands_for("s1") if r.id == cid)
    brief = brief_from_row(row, lambda s: s)
    assert brief.status == "blocked"
    assert brief.exit_code is None
    assert brief.summary == "host out of scope"
