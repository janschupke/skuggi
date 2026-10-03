"""The hard gate: no secret in command output ever reaches the model.

skuggi's autonomous loop feeds captured command output back to the worker. This
drives a real turn whose executed command emits planted secrets and asserts that
(a) not one raw secret appears in any prompt the model received, (b) the egress
tripwire agrees every prompt is clean, yet (c) the ledger still stored the output
raw and (d) the vault can rehydrate a placeholder back to the real value -- the
data-plane split end to end.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver

from skuggi.agent.graph import GraphDeps, build_graph, recursion_limit
from skuggi.agent.protocol import CriticResponse, WorkerResponse
from skuggi.agent.state import AgentState
from skuggi.common.execution import CommandResult
from skuggi.engagement.engagement import EngagementConfig
from skuggi.persistence.ledger import Ledger, open_ledger
from skuggi.security.policy import RedactionPolicy
from skuggi.security.tripwire import assert_clean
from skuggi.security.vault import SecretVault, open_vault
from skuggi.tooling.registry import ToolRegistry, ToolSpec
from tests.fakes import RoleScriptedChatModel

_REGISTRY = ToolRegistry(
    tools=(ToolSpec(name="echo", binary="echo", method="recon", requires_target=False),)
)
_CLOCK = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)

# Secrets planted in the executed command's output. Each must be scrubbed before
# any of it is fed back to the model, and vaulted so it can be rehydrated.
TOKEN = "ghp_1234567890abcdefABCDEF1234567890abcd"
EMAIL = "admin@victim-corp.example"
PASSWORD_LINE = "password: SuperSecret123!"
SECRETS = [TOKEN, EMAIL, "SuperSecret123!"]

_STDOUT = f"found creds {EMAIL} token={TOKEN}\n{PASSWORD_LINE}\n22/tcp open"


def _engagement() -> EngagementConfig:
    return EngagementConfig.model_validate(
        {
            "name": "e",
            "timezone": "UTC",
            "authorized_start": datetime(2000, 1, 1, tzinfo=UTC),
            "authorized_end": datetime(2999, 1, 1, tzinfo=UTC),
            "target_networks": ("10.0.0.0/8",),
            "allowed_tools": frozenset({"echo"}),
            "allowed_methods": frozenset({"recon"}),
            "autonomous": True,
        }
    )


def _policy() -> RedactionPolicy:
    return RedactionPolicy.from_scope(allow={"e", "10.0.0.0/8"})


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with open_ledger(tmp_path / "ledger.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        yield led


@pytest.fixture
def vault(tmp_path: Path) -> Iterator[SecretVault]:
    with open_vault(tmp_path / ".vault.db") as vlt:
        yield vlt


def _run_turn(ledger: Ledger, vault: SecretVault) -> RoleScriptedChatModel:
    model = RoleScriptedChatModel(
        worker_replies=[
            WorkerResponse(command="echo scan", summary="probe"),
            WorkerResponse(summary="done", done=True),
        ],
        critic_replies=[CriticResponse(approved=True)],
    )
    app = build_graph(
        GraphDeps(
            llm=model,
            engagement=_engagement(),
            ledger=ledger,
            registry=_REGISTRY,
            redaction_policy=_policy(),
            vault=vault,
            session_id="s1",
            thread_id=lambda: "t1",
            clock=lambda: _CLOCK,
        ),
        InMemorySaver(),
    )
    initial: AgentState = {
        "messages": [HumanMessage(content="probe it")],
        "revision_count": 0,
        "max_revisions": 2,
    }
    config: RunnableConfig = {
        "configurable": {"thread_id": "t1"},
        "recursion_limit": recursion_limit(max_revisions=4, max_command_rounds=4),
    }
    app.invoke(initial, config)
    return model


@pytest.fixture
def fake_run(monkeypatch: pytest.MonkeyPatch) -> None:
    def _run(argv: Sequence[str], **_kwargs: object) -> CommandResult:
        now = datetime.now(UTC)
        return CommandResult(
            command=" ".join(argv),
            exit_code=0,
            stdout=_STDOUT,
            stderr="",
            started_at=now,
            finished_at=now,
        )

    monkeypatch.setattr("skuggi.common.execution.run", _run)


@pytest.mark.usefixtures("fake_run")
def test_no_raw_secret_reaches_any_model_prompt(
    ledger: Ledger, vault: SecretVault
) -> None:
    model = _run_turn(ledger, vault)
    all_prompts = "\n".join(
        text for _role, msgs in model.calls for m in msgs for text in (m.text,)
    )
    assert all_prompts, "the model was never invoked"
    for secret in SECRETS:
        assert secret not in all_prompts, f"leaked: {secret!r}"
    # The output DID reach the worker's second pass -- as a placeholder, and with
    # the non-secret part intact.
    worker_second = model.prompts_for("worker")[-1]
    assert "22/tcp open" in worker_second
    assert "«" in worker_second


@pytest.mark.usefixtures("fake_run")
def test_every_captured_prompt_passes_the_tripwire(
    ledger: Ledger, vault: SecretVault
) -> None:
    model = _run_turn(ledger, vault)
    policy = _policy()
    for _role, msgs in model.calls:
        for message in msgs:
            assert_clean(message.text, policy)


@pytest.mark.usefixtures("fake_run")
def test_ledger_keeps_the_output_raw_but_vault_can_rehydrate(
    ledger: Ledger, vault: SecretVault
) -> None:
    _run_turn(ledger, vault)
    # Storage is acceptable: the ledger holds the real output for the report.
    stored = ledger.commands_for("s1")[-1]
    assert TOKEN in stored.stdout
    # And the vault round-trips the masked summary back to the real secret.
    assert vault.rehydrate(vault.intern(TOKEN, "TOKEN")) == TOKEN


# --- rehydration: a vaulted secret reaches the tool, never the model --------


def test_a_placeholder_in_a_command_is_rehydrated_for_the_tool(
    ledger: Ledger, vault: SecretVault, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[Sequence[str]] = []

    def _run(argv: Sequence[str], **_kwargs: object) -> CommandResult:
        captured.append(tuple(argv))
        now = datetime.now(UTC)
        return CommandResult(
            command=" ".join(argv),
            exit_code=0,
            stdout="ok",
            stderr="",
            started_at=now,
            finished_at=now,
        )

    monkeypatch.setattr("skuggi.common.execution.run", _run)

    # A secret the agent only ever saw as a placeholder.
    placeholder = vault.intern("SuperSecret123!", "PASSWORD")
    model = RoleScriptedChatModel(
        worker_replies=[
            WorkerResponse(command=f"echo {placeholder}", summary="use the cred"),
            WorkerResponse(summary="done", done=True),
        ],
        critic_replies=[CriticResponse(approved=True)],
    )
    app = build_graph(
        GraphDeps(
            llm=model,
            engagement=_engagement(),
            ledger=ledger,
            registry=_REGISTRY,
            redaction_policy=_policy(),
            vault=vault,
            session_id="s1",
            thread_id=lambda: "t1",
            clock=lambda: _CLOCK,
        ),
        InMemorySaver(),
    )
    config: RunnableConfig = {
        "configurable": {"thread_id": "t1"},
        "recursion_limit": recursion_limit(max_revisions=4, max_command_rounds=4),
    }
    app.invoke(
        {
            "messages": [HumanMessage(content="use it")],
            "revision_count": 0,
            "max_revisions": 2,
        },
        config,
    )

    # The tool received the REAL secret...
    assert captured, "the command never executed"
    assert "SuperSecret123!" in captured[-1]
    # ...but the ledger kept the placeholder form, and the model never saw the
    # real value in any prompt.
    assert placeholder in ledger.commands_for("s1")[-1].command
    assert "SuperSecret123!" not in ledger.commands_for("s1")[-1].command
    all_prompts = "\n".join(m.text for _r, msgs in model.calls for m in msgs)
    assert "SuperSecret123!" not in all_prompts
