"""The worker's read-only `lookup` into its own record (G8).

The worker can query the engagement's accumulated record mid-turn -- past the
bounded briefs -- and the executor resolves it read-only, redacted, and loops the
result back. These pin the resolver's targets + redaction, and the loop routing.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from skuggi.agent.executor import execute_node, resolve_lookup, route_after_executor
from skuggi.agent.graph import GraphDeps
from skuggi.agent.protocol import WorkerResponse
from skuggi.common.execution import CommandResult
from skuggi.persistence.ledger import Ledger, open_ledger
from skuggi.security.policy import RedactionPolicy
from skuggi.security.vault import SecretVault, open_vault
from tests.integration.test_finding_recall import _engagement

SECRET = "ghp_1234567890abcdefABCDEF1234567890abcd"


@pytest.fixture
def vault(tmp_path: Path) -> Iterator[SecretVault]:
    with open_vault(tmp_path / ".vault.db") as vlt:
        yield vlt


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        yield led


def _deps(ledger: Ledger, vault: SecretVault, **kw: object) -> GraphDeps:
    return GraphDeps(
        ledger=ledger,
        session_id="s1",
        engagement=_engagement(),
        redaction_policy=RedactionPolicy(),
        vault=vault,
        **kw,  # type: ignore[arg-type]
    )


def test_lookup_findings_filters_and_redacts(
    ledger: Ledger, vault: SecretVault
) -> None:
    ledger.record_finding(
        session_id="s1",
        title="SQLi on /login",
        severity="high",
        description="d",
        affected_host="web01",
    )
    ledger.record_finding(
        session_id="s1", title=f"leaked {SECRET}", severity="low", description="d"
    )
    out = resolve_lookup(_deps(ledger, vault), "findings web01")
    assert "SQLi on /login" in out
    assert "leaked" not in out  # the other finding filtered out
    # A secret in a matched title is redacted.
    leaked = resolve_lookup(_deps(ledger, vault), "findings leaked")
    assert SECRET not in leaked


def test_lookup_loot_creds_notes(ledger: Ledger, vault: SecretVault) -> None:
    ledger.record_loot(session_id="s1", kind="hash", host="web01", label="ntlm hash")
    ledger.record_credential(
        session_id="s1", host="db1", username="root", secret_ref="«CRED:aa11»"
    )
    ledger.record_note(session_id="s1", subject="recon", host="web01", text="telnet")

    assert "ntlm hash" in resolve_lookup(_deps(ledger, vault), "loot")
    creds = resolve_lookup(_deps(ledger, vault), "creds db1")
    assert "root@db1" in creds
    assert "«CRED:aa11»" in creds  # the placeholder, usable; never a plaintext secret
    assert "telnet" in resolve_lookup(_deps(ledger, vault), "notes recon")


def test_lookup_command_reads_fuller_output_redacted(
    ledger: Ledger, vault: SecretVault
) -> None:
    cid = ledger.record_command(
        session_id="s1",
        thread_id="t",
        command="env",
        binary="env",
        method=None,
        status="executed",
        result=CommandResult(
            command="env",
            exit_code=0,
            stdout=f"TOKEN={SECRET}\n" + "x" * 3000,
            stderr="",
            started_at=datetime(2026, 6, 1, tzinfo=UTC),
            finished_at=datetime(2026, 6, 1, tzinfo=UTC),
        ),
    )
    out = resolve_lookup(_deps(ledger, vault), f"command {cid}")
    assert SECRET not in out
    assert len(out) > 1500  # more than the per-turn summary cap
    assert "(no command" in resolve_lookup(_deps(ledger, vault), "command 999")


def test_unknown_lookup_target_is_explained(ledger: Ledger, vault: SecretVault) -> None:
    assert "unknown lookup target" in resolve_lookup(_deps(ledger, vault), "bogus x")


def test_executor_resolves_a_lookup_and_loops_back(
    ledger: Ledger, vault: SecretVault
) -> None:
    ledger.record_loot(session_id="s1", kind="key", host="h", label="id_rsa")
    deps = _deps(ledger, vault, max_command_rounds=4)
    state = {"worker": WorkerResponse(lookup="loot", summary="checking")}
    update = execute_node(state, deps, Path.cwd())  # type: ignore[arg-type]
    assert update["command_rounds"] == 1
    assert "id_rsa" in update["lookups"][0]
    # With rounds left, the graph loops back to the worker to read the result.
    looped = {**state, **update}
    assert route_after_executor(looped, deps) == "worker"  # type: ignore[arg-type]
    # At the round cap, it stops looping and reviews instead.
    capped = {**looped, "command_rounds": 4}
    assert route_after_executor(capped, deps) == "critic"  # type: ignore[arg-type]
