"""L3: the headless AgentCore, offline.

The core is exercised without any front-end: turn events, session controls,
engagement data. Only the LLM and embeddings are faked.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from skuggi import probe as probe_mod
from skuggi.commands import CommandAlias, CommandRegistry
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
