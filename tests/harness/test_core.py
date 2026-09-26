"""L3: the headless AgentCore, offline.

The core is exercised without any front-end: turn events, session controls,
engagement data. Only the LLM and embeddings are faked.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from langchain_core.messages import AIMessage
from pydantic import SecretStr

from skuggi import probe as probe_mod
from skuggi.commands import CommandAlias, CommandRegistry
from skuggi.config import config_path
from skuggi.configs import ConfigError
from skuggi.core import AgentCore
from skuggi.registry import ToolSpec, ToolStatus
from tests.conftest import offline_settings, wire_offline_core


def _build_core(tmp_path: Path, *, engagement: str | None = "test-eng") -> AgentCore:
    core = AgentCore(offline_settings(tmp_path, engagement=engagement))
    wire_offline_core(core)
    return core


@pytest.fixture
def core(tmp_path: Path, pentest_configs: Callable[..., Path]) -> Iterator[AgentCore]:
    pentest_configs()
    built = _build_core(tmp_path)
    yield built
    built.close()


def test_turn_yields_a_final_answer(core: AgentCore) -> None:
    events = list(core.turn("what is exposed?"))
    finals = [e.text for e in events if e.kind == "final"]
    assert finals
    assert "the answer" in finals[-1]
    assert any(e.kind == "status" and e.node == "planner" for e in events)


def test_turn_errors_are_yielded_not_raised(core: AgentCore) -> None:
    class Exploding:
        def stream(self, *_a: object, **_k: object) -> object:
            msg = "boom"
            raise RuntimeError(msg)

    core.graph = Exploding()  # type: ignore[assignment]
    events = list(core.turn("x"))
    assert any(e.node == "error" and "boom" in e.text for e in events)


def test_set_mode_switches_and_validates(core: AgentCore) -> None:
    assert core.set_mode("blueteam") == "blueteam"
    assert core.mode == "blueteam"
    with pytest.raises(ValueError, match="unknown mode"):
        core.set_mode("nonsense")


def test_autonomous_toggles(core: AgentCore) -> None:
    assert core.set_autonomous(True) is True
    assert core.autonomous is True
    assert core.set_autonomous(False) is False
    assert core.set_autonomous(None) is True  # toggles from off


def test_set_provider_rejects_unknown_and_switches(core: AgentCore) -> None:
    with pytest.raises(ValueError, match="unknown provider"):
        core.set_provider("banana")
    core.set_provider("ollama")  # a valid (offline) rebuild
    assert core.provider == "ollama"


def test_set_model_requires_a_name(core: AgentCore) -> None:
    with pytest.raises(ValueError, match="required"):
        core.set_model("")


def test_threads(core: AgentCore) -> None:
    first = core.thread_id
    assert core.new_thread() != first
    core.set_thread("abc")
    assert core.thread_id == "abc"
    assert isinstance(core.list_threads(), list)


def test_describe_and_findings_and_report(core: AgentCore) -> None:
    described = core.describe_engagement()
    assert described is not None
    assert "test-eng" in described
    assert core.findings() == []
    path = core.write_report()
    assert path.suffix == ".md"
    assert path.parent == core.reports_dir


def test_doctor_and_install(core: AgentCore, monkeypatch: pytest.MonkeyPatch) -> None:
    spec = ToolSpec(name="nmap", binary="nmap", method="scan")
    status = ToolStatus(
        spec, found=True, path=Path("/usr/bin/nmap"), version="7", source="host"
    )
    monkeypatch.setattr(probe_mod, "probe", lambda *_a, **_k: [status])
    assert core.doctor_statuses() == [status]
    assert core.install_tool("ghost-tool") is None
    monkeypatch.setattr(probe_mod, "install_tool", lambda *_a, **_k: status)
    assert core.install_tool("nmap") == status


def test_ingest_indexes_a_file(core: AgentCore, tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text("some content", encoding="utf-8")
    assert core.ingest(doc) >= 1


def test_no_engagement_degrades(tmp_path: Path) -> None:
    core = _build_core(tmp_path, engagement=None)
    try:
        assert core.engagement is None
        assert core.autonomous is False
        assert core.describe_engagement() is None
        assert any("no engagement" in w for w in core.warnings)
        assert "run_command" not in {t.name for t in core.tools_list}
        with pytest.raises(ValueError, match="no engagement"):
            core.set_autonomous(True)
    finally:
        core.close()


# --- run command aliases (plan_run) -----------------------------------------

_ALIASES = CommandRegistry(
    commands=(
        CommandAlias(name="nmap-network", argv=("nmap", "-sn")),
        CommandAlias(name="nmap-host", argv=("nmap", "-sV", "-sC")),
    )
)


def test_plan_run_in_scope_records_proposed(core: AgentCore) -> None:
    core.commands = _ALIASES
    plan = core.plan_run("nmap-network", ["10.0.0.5"])
    assert plan.known
    assert plan.raw == "nmap -sn 10.0.0.5"  # the transparent resolved command
    assert plan.verdict is not None
    assert plan.verdict.allowed
    assert plan.command_id is not None
    row = core.ledger.commands_for(core.session_id)[-1]
    assert row.status == "proposed"
    assert row.command == "nmap -sn 10.0.0.5"


def test_plan_run_out_of_scope_is_blocked(core: AgentCore) -> None:
    core.commands = _ALIASES
    plan = core.plan_run("nmap-host", ["8.8.8.8"])  # not in target networks/hosts
    assert plan.known
    assert plan.verdict is not None
    assert not plan.verdict.allowed
    assert core.ledger.commands_for(core.session_id)[-1].status == "blocked"


def test_plan_run_unknown_alias(core: AgentCore) -> None:
    core.commands = _ALIASES
    plan = core.plan_run("bogus", [])
    assert not plan.known
    assert "unknown alias" in plan.note


def test_plan_run_without_engagement_skips_scope(tmp_path: Path) -> None:
    core = _build_core(tmp_path, engagement=None)
    try:
        core.commands = _ALIASES
        plan = core.plan_run("nmap-host", ["10.0.0.5"])
        assert plan.known
        assert plan.verdict is None
        assert "no engagement" in plan.note
        assert plan.raw == "nmap -sV -sC 10.0.0.5"
    finally:
        core.close()


# --- engagement wizard: create + hot-reload ---------------------------------


def _valid_scope(name: str) -> dict[str, object]:
    return {
        "name": name,
        "timezone": "UTC",
        "authorized_start": "2026-01-01T00:00:00+00:00",
        "authorized_end": "2026-12-31T23:59:59+00:00",
        "target_networks": ["10.0.0.0/24"],
        "allowed_tools": ["nmap"],
        "allowed_methods": ["scan"],
    }


def test_create_engagement_writes_scope_and_hot_loads(core: AgentCore) -> None:
    eng = core.create_engagement(_valid_scope("acme"))
    assert eng.name == "acme"
    assert core.engagement is not None
    assert core.engagement.name == "acme"  # hot-reloaded into the session
    # scope.json was written under the new engagement's workspace
    assert core.workspace is not None
    assert core.workspace.scope_path.is_file()
    assert "acme" in core.workspace.scope_path.read_text(encoding="utf-8")


def test_create_engagement_rejects_invalid_scope(core: AgentCore) -> None:
    with pytest.raises(ConfigError):
        core.create_engagement({"name": "bad"})  # missing required fields


def test_load_engagement_reopens_ledger_at_new_path(core: AgentCore) -> None:
    core.create_engagement(_valid_scope("beta"))
    assert core.workspace is not None
    # the ledger now lives under the beta workspace and has this session
    assert core.workspace.ledger_path.parent.name == "beta"
    assert core.ledger.findings_for(core.session_id) == []


# --- app config (the `config` verb) -----------------------------------------


def test_config_summary_redacts_secrets(core: AgentCore) -> None:
    core.settings = core.settings.model_copy(
        update={"openai_api_key": SecretStr("sk-super-secret")}
    )
    summary = core.config_summary()
    assert "sk-super-secret" not in summary
    assert "provider = ollama" in summary


def test_config_line_show_and_escalation(core: AgentCore) -> None:
    assert "provider = ollama" in (core.config_line("show") or "")
    assert core.config_line("") is not None  # empty == show
    assert core.config_line("please make retrieval faster") is None  # NL -> escalate


def test_apply_config_hot_applies_mode(core: AgentCore) -> None:
    msg = core.apply_config("mode", "blueteam")
    assert "applied live" in msg
    assert core.mode == "blueteam"
    persisted = json.loads(config_path().read_text(encoding="utf-8"))
    assert persisted["mode"] == "blueteam"


def test_apply_config_persists_and_notes_restart(core: AgentCore) -> None:
    msg = core.apply_config("retrieve_k", "9")
    assert "restart" in msg
    assert core.settings.retrieve_k == 9


def test_apply_config_rejects_bad_value(core: AgentCore) -> None:
    assert "invalid" in core.apply_config("retrieve_k", "not-an-int")


def test_apply_config_refuses_secret_key(core: AgentCore) -> None:
    assert "secret" in core.apply_config("openai_api_key", "sk-x")


def test_apply_config_unknown_key(core: AgentCore) -> None:
    assert "unknown" in core.apply_config("nope", "x")


def test_propose_config_parses_llm_lines(core: AgentCore) -> None:
    class _FakeLLM:
        def invoke(self, _prompt: object) -> AIMessage:
            return AIMessage(content="retrieve_k=8\ngarbage line\nprovider=anthropic")

    core.llm = cast(Any, _FakeLLM())
    proposals = core.propose_config("faster and use anthropic")
    assert ("retrieve_k", "8") in proposals
    assert ("provider", "anthropic") in proposals
    assert len(proposals) == 2  # the garbage line is dropped
