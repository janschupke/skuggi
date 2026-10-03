"""L3: the headless AgentCore, offline.

The core is exercised without any front-end: turn events, session controls,
engagement data. Only the LLM and embeddings are faked.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import SecretStr

from skuggi.agent.core import AgentCore
from skuggi.agent.protocol import ConfigEdit, ConfigProposal
from skuggi.common.execution import CommandResult
from skuggi.config.config import config_path
from skuggi.config.configs import ConfigError, load_commands
from skuggi.frontend import dispatch
from skuggi.install import update as update_mod
from skuggi.tooling import probe as probe_mod
from skuggi.tooling.commands import CommandAlias, CommandRegistry
from skuggi.tooling.registry import ToolSpec, ToolStatus
from tests.conftest import offline_settings, wire_offline_core
from tests.fakes import StructuredChatModel


def _build_core(tmp_path: Path) -> AgentCore:
    # The engagement (if any) is adopted by probing cwd, where `pentest_configs`
    # writes its scope; a test that skips that fixture boots agent-only.
    core = AgentCore(offline_settings(tmp_path))
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
    # Planner/critic scaffolding is logged, not streamed as operator events.
    scaffolding = {"planner", "retriever", "executor", "critic"}
    assert not [e for e in events if e.kind == "status" and e.node in scaffolding]


def test_turn_errors_are_yielded_not_raised(core: AgentCore) -> None:
    class Exploding:
        def stream(self, *_a: object, **_k: object) -> object:
            msg = "boom"
            raise RuntimeError(msg)

    core.graph = Exploding()  # type: ignore[assignment]
    events = list(core.turn("x"))
    assert any(e.node == "error" and "boom" in e.text for e in events)


def test_turn_survives_a_failed_closing_ledger_write(
    core: AgentCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A storage failure on the turn-closing event must not crash the loop.

    ``record_event(kind="response")`` runs in ``turn``'s ``finally``, outside the
    try that guards the turn body. If it raised, it would escape ``turn`` and kill
    the front-end loop with the answer already delivered; instead it degrades to a
    logged warning and the turn completes normally.
    """
    real = core.ledger.record_event

    def flaky(**kwargs: object) -> int:
        if kwargs.get("kind") == "response":
            msg = "db gone"
            raise RuntimeError(msg)
        return real(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(core.ledger, "record_event", flaky)
    # Must not raise despite the closing write failing.
    events = list(core.turn("what is exposed?"))
    assert any(e.kind == "final" for e in events)


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
    assert core.journal.findings() == []
    path = core.journal.write_report()
    assert isinstance(path, Path)  # md-only when pdf is not requested
    assert path.suffix == ".md"
    assert path.parent == core.reports_dir


def test_record_finding_and_journals(core: AgentCore) -> None:
    # A finding goes to the ledger and surfaces via findings() (severity lowered).
    row = core.journal.record_finding("High", "SQLi in /login")
    assert row is not None
    assert (row.severity, row.title) == ("high", "SQLi in /login")
    assert [f.title for f in core.journal.findings()] == ["SQLi in /login"]
    # A bad severity records nothing.
    assert core.journal.record_finding("spicy", "nope") is None
    assert len(core.journal.findings()) == 1

    # The notes journal is a workspace file, empty until written.
    assert core.journal.notes() == ""
    note_path = core.journal.add_note("port 8080 open")
    assert note_path is not None
    assert note_path.is_file()
    assert "port 8080 open" in core.journal.notes()

    # The loot journal behaves the same way.
    assert core.journal.loot() == ""
    assert core.journal.add_loot("cred admin:hunter2") is not None
    assert "hunter2" in core.journal.loot()


def test_journals_need_an_engagement_but_findings_do_not(tmp_path: Path) -> None:
    core = _build_core(tmp_path)
    try:
        assert core.workspace is None
        # No workspace -> no notes/loot file to write.
        assert core.journal.add_note("x") is None
        assert core.journal.notes() == ""
        assert core.journal.add_loot("y") is None
        assert core.journal.loot() == ""
        # Findings still record against the fallback ledger.
        assert core.journal.record_finding("low", "info leak") is not None
    finally:
        core.close()


def test_doctor_and_install(core: AgentCore, monkeypatch: pytest.MonkeyPatch) -> None:
    spec = ToolSpec(name="nmap", binary="nmap", method="scan")
    status = ToolStatus(
        spec, found=True, path=Path("/usr/bin/nmap"), version="7", source="host"
    )
    monkeypatch.setattr(probe_mod, "probe", lambda *_a, **_k: [status])
    assert core.doctor.tools() == [status]
    assert core.doctor.install("ghost-tool") is None
    monkeypatch.setattr(probe_mod, "install_tool", lambda *_a, **_k: status)
    assert core.doctor.install("nmap") == status


def test_ingest_indexes_a_file(core: AgentCore, tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text("some content", encoding="utf-8")
    assert core.ingest(doc) >= 1


def test_no_engagement_degrades(tmp_path: Path) -> None:
    core = _build_core(tmp_path)
    try:
        assert core.engagement is None
        assert core.autonomous is False
        assert core.describe_engagement() is None
        assert any("no engagement" in w for w in core.warnings)
        with pytest.raises(ValueError, match="no engagement"):
            core.set_autonomous(True)
    finally:
        core.close()


# --- cmd cheatsheet (plan_cmd / search / edit) ------------------------------

_ALIASES = CommandRegistry(
    commands=(
        CommandAlias(name="nmap-network", argv=("nmap", "-sn")),
        CommandAlias(name="nmap-host", argv=("nmap", "-sV", "-sC")),
    )
)


def _pin_target(core: AgentCore, target: str) -> None:
    """Pin the engagement's resolved ``${target}`` to one explicit host.

    Only ``primary_target`` is set (a plain string field) so ``model_copy`` does
    not need to re-validate the network objects, which it would not do anyway.
    The fixture scope already allows ``localhost`` and the 10/8 + 192.168/16 nets.
    """
    assert core.engagement is not None
    core.engagement = core.engagement.model_copy(update={"primary_target": target})


def test_plan_cmd_placeholder_target_records_proposed(core: AgentCore) -> None:
    # Two scope hosts -> no single ${target}; the command stays a template and
    # the tool/method/time are still enforced (so nmap/scan is in scope).
    core.commands = _ALIASES
    plan = core.cmds.plan("nmap-network")
    assert plan.known
    assert plan.raw == "nmap -sn ${target}"  # literal placeholder, no concrete host
    assert plan.verdict is not None
    assert plan.verdict.allowed
    assert "placeholder" in plan.note
    row = core.ledger.commands_for(core.session_id)[-1]
    assert row.status == "proposed"
    assert row.command == "nmap -sn ${target}"


def test_plan_cmd_resolved_target_is_scope_checked(core: AgentCore) -> None:
    core.commands = _ALIASES
    _pin_target(core, "10.0.0.5")  # inside the fixture's 10.0.0.0/8 network
    plan = core.cmds.plan("nmap-network")
    assert plan.verdict is not None
    assert plan.verdict.allowed
    assert "10.0.0.5" in plan.note


def test_plan_cmd_out_of_scope_is_blocked(core: AgentCore) -> None:
    core.commands = _ALIASES
    _pin_target(core, "8.8.8.8")  # explicit target outside every network/host
    plan = core.cmds.plan("nmap-host")
    assert plan.known
    assert plan.verdict is not None
    assert not plan.verdict.allowed
    assert core.ledger.commands_for(core.session_id)[-1].status == "blocked"


def test_plan_cmd_literal_argv_host_is_checked_even_without_a_target(
    core: AgentCore,
) -> None:
    """S7: a literal argv host is scope-checked even with no single ${target}.

    A multi-host engagement resolves no single target, but a host baked into the
    alias argv must still be checked, not waved through.
    """
    core.commands = CommandRegistry(
        commands=(CommandAlias(name="nmap-badhost", argv=("nmap", "-sV", "8.8.8.8")),)
    )
    plan = core.cmds.plan("nmap-badhost")
    assert plan.verdict is not None
    assert not plan.verdict.allowed  # was allowed before: targets were zeroed
    assert "8.8.8.8" in plan.verdict.reason
    assert core.ledger.commands_for(core.session_id)[-1].status == "blocked"


def test_plan_cmd_unknown_alias(core: AgentCore) -> None:
    core.commands = _ALIASES
    plan = core.cmds.plan("bogus")
    assert not plan.known
    assert "unknown alias" in plan.note


def test_search_commands_matches_by_substring(core: AgentCore) -> None:
    core.commands = _ALIASES
    assert {a.name for a in core.cmds.search("nmap")} == {
        "nmap-network",
        "nmap-host",
    }
    assert [a.name for a in core.cmds.search("host")] == ["nmap-host"]


def test_plan_cmd_without_engagement_skips_scope(tmp_path: Path) -> None:
    core = _build_core(tmp_path)
    try:
        core.commands = _ALIASES
        plan = core.cmds.plan("nmap-host")
        assert plan.known
        assert plan.verdict is None
        assert "no engagement" in plan.note
        assert plan.raw == "nmap -sV -sC ${target}"
    finally:
        core.close()


def test_add_update_remove_command_round_trips(core: AgentCore) -> None:
    core.commands = CommandRegistry()
    added = core.cmds.add({"name": "ping-sweep", "argv": ["nmap", "-sn"]})
    assert added.name == "ping-sweep"
    assert core.commands.alias_for("ping-sweep") is not None
    # Persisted to disk (hand-editable too): reloads with the alias present.
    on_disk = load_commands(core.settings.commands_path)
    assert on_disk.alias_for("ping-sweep") is not None
    with pytest.raises(ConfigError):  # a duplicate name is rejected
        core.cmds.add({"name": "ping-sweep", "argv": ["nmap", "-sn"]})
    core.cmds.update(
        "ping-sweep", {"name": "ping-sweep", "argv": ["nmap", "-sn", "-T4"]}
    )
    updated = core.commands.alias_for("ping-sweep")
    assert updated is not None
    assert updated.argv == ("nmap", "-sn", "-T4")
    assert core.cmds.remove("ping-sweep") is True
    assert core.cmds.remove("ping-sweep") is False


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


def test_adopt_engagement_reopens_ledger_at_new_path(
    core: AgentCore, tmp_path: Path
) -> None:
    beta = tmp_path / "beta"
    core.create_engagement(_valid_scope("beta"), root=beta)
    assert core.workspace is not None
    # the ledger now lives under the beta root (not the cwd engagement)
    assert core.workspace.root == beta
    assert core.workspace.ledger_path.parent == beta
    assert core.ledger.findings_for(core.session_id) == []


# --- app config (the `config` verb) -----------------------------------------


def test_config_summary_redacts_secrets(core: AgentCore) -> None:
    core.settings = core.settings.model_copy(
        update={"openai_api_key": SecretStr("sk-super-secret")}
    )
    summary = core.config.summary()
    assert "sk-super-secret" not in summary
    assert "provider = ollama" in summary


def test_config_line_show_and_escalation(core: AgentCore) -> None:
    assert "provider = ollama" in (core.config.line("show") or "")
    assert core.config.line("") is not None  # empty == show
    assert core.config.line("please make retrieval faster") is None  # NL -> escalate


def test_apply_config_hot_applies_mode(core: AgentCore) -> None:
    msg = core.config.apply("mode", "blueteam")
    assert "applied live" in msg
    assert core.mode == "blueteam"
    persisted = json.loads(config_path().read_text(encoding="utf-8"))
    assert persisted["mode"] == "blueteam"


def test_apply_config_persists_and_notes_restart(core: AgentCore) -> None:
    msg = core.config.apply("retrieve_k", "9")
    assert "restart" in msg
    assert core.settings.retrieve_k == 9


def test_apply_config_rejects_bad_value(core: AgentCore) -> None:
    assert "invalid" in core.config.apply("retrieve_k", "not-an-int")


def test_apply_config_refuses_secret_key(core: AgentCore) -> None:
    assert "secret" in core.config.apply("openai_api_key", "sk-x")


def test_apply_config_unknown_key(core: AgentCore) -> None:
    assert "unknown" in core.config.apply("nope", "x")


def test_apply_config_failed_live_switch_does_not_persist(
    core: AgentCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F4: a failed provider switch must not persist the value.

    If it did, config.json would re-apply (and maybe fail to boot) on restart.
    """

    def boom(_name: str) -> None:
        msg = "no credentials"
        raise RuntimeError(msg)

    monkeypatch.setattr(core, "set_provider", boom)
    msg = core.config.apply("provider", "openai")
    assert "live switch failed" in msg
    path = config_path()
    persisted = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    assert persisted.get("provider") != "openai"  # never persisted on failure


def test_propose_config_returns_structured_edits(core: AgentCore) -> None:
    core.llm = cast(
        Any,
        StructuredChatModel(
            obj=ConfigProposal(
                edits=(
                    ConfigEdit(key="retrieve_k", value="8"),
                    ConfigEdit(key="provider", value="anthropic"),
                    ConfigEdit(key="not_a_setting", value="x"),
                )
            )
        ),
    )
    proposals = core.config.propose("faster and use anthropic")
    assert ("retrieve_k", "8") in proposals
    assert ("provider", "anthropic") in proposals
    assert len(proposals) == 2  # the unknown key is dropped


# --- self-update (the `update` verb) ----------------------------------------


def _result(argv: list[str], *, exit_code: int, err: str = "") -> CommandResult:
    now = datetime.now(UTC)
    return CommandResult(
        command=" ".join(argv),
        exit_code=exit_code,
        stdout="ok\n" if exit_code == 0 else "",
        stderr=err,
        started_at=now,
        finished_at=now,
    )


def test_self_update_runs_pull_then_sync(
    core: AgentCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(update_mod, "is_uv_tool_env", lambda: False)
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> CommandResult:
        calls.append(argv)
        return _result(argv, exit_code=0)

    lines = list(core.self_update(runner))
    assert ["git", "pull", "--ff-only"] in calls
    assert ["uv", "sync", "--all-groups", "--all-extras"] in calls
    assert any("updated to skuggi" in line for line in lines)


def test_self_update_aborts_on_a_failed_step(
    core: AgentCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(update_mod, "is_uv_tool_env", lambda: False)
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> CommandResult:
        calls.append(argv)
        return _result(argv, exit_code=1 if argv[0] == "git" else 0, err="boom")

    lines = list(core.self_update(runner))
    assert any("aborted" in line for line in lines)
    # The failed pull short-circuits the sync step, whichever one it would be.
    assert [argv[0] for argv in calls] == ["git"]


def test_self_update_refreshes_the_tool_install_from_a_tool_env(
    core: AgentCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`uv sync` would sync the checkout's .venv, not the env skuggi is running in.

    Under `uv tool install --editable`, pulled *code* takes effect through the
    .pth, but a new *dependency* would land in the wrong environment -- so the
    tool install is what gets refreshed.
    """
    monkeypatch.setattr(update_mod, "is_uv_tool_env", lambda: True)
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> CommandResult:
        calls.append(argv)
        return _result(argv, exit_code=0)

    list(core.self_update(runner))
    assert ["git", "pull", "--ff-only"] in calls
    assert ["uv", "sync", "--all-groups", "--all-extras"] not in calls
    tool_install = next(argv for argv in calls if argv[:3] == ["uv", "tool", "install"])
    assert "--editable" in tool_install
    assert "--force" in tool_install


def test_self_update_refuses_when_there_is_no_checkout(
    core: AgentCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-editable install has no repo; running git in site-packages is worse."""
    monkeypatch.setattr(update_mod, "checkout_root", lambda **_k: None)
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> CommandResult:
        calls.append(argv)
        return _result(argv, exit_code=0)

    lines = list(core.self_update(runner))
    assert calls == []
    assert any("not running from a git checkout" in line for line in lines)
    assert any("uv tool install --editable" in line for line in lines)


def test_findings_review_approve_and_reject(core: AgentCore) -> None:
    keep = core.journal.record_finding("high", "SQLi in /login")
    drop = core.journal.record_finding("low", "banner leak")
    assert keep is not None
    assert drop is not None
    # Both operator-added, both born draft.
    assert all(
        f.status == "draft" and f.author == "operator" for f in core.journal.findings()
    )

    assert (
        dispatch.run_findings(core, f"approve {keep.id}")
        == f"approved finding [{keep.id}]"
    )
    msg = dispatch.run_findings(core, f"reject {drop.id} false positive")
    assert msg == f"rejected finding [{drop.id}]: false positive"
    bad = dispatch.run_findings(core, "approve 999")
    assert bad is not None
    assert bad.startswith("no such finding")
    assert dispatch.run_findings(core, "approve") == (
        "usage: findings [approve <id> | reject <id> <reason> | rescore [all|<id>]]"
    )
    # A bare `findings` (no action) defers to the caller's listing.
    assert dispatch.run_findings(core, "") is None

    # Only the approved one is report-eligible; the rejection reason is stored.
    approved = core.ledger.approved_findings_for(core.session_id)
    assert [f.id for f in approved] == [keep.id]
    rejected = core.ledger.finding(drop.id)
    assert rejected is not None
    assert rejected.review_reason == "false positive"


def test_threat_model_versioning_flags_and_rescore(core: AgentCore) -> None:
    # v1 exists from session start (initial, no threat model on the default scope).
    assert core.ledger.current_threat_model_version() == 1

    # A CVSS finding is scored under v1 with no environmental overlay.
    row = core.journal.record_finding(
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    )
    assert row is not None
    assert row.cvss_tm_version == 1
    assert row.cvss_environmental is None
    base_score = row.cvss_score

    # Operator sets a threat model -> v2, change logged, prior finding now outdated.
    msg = dispatch.run_threat_model(core, "high high high | crown-jewel asset")
    assert "now v2" in msg
    assert core.ledger.current_threat_model_version() == 2
    history = core.ledger.threat_model_history()
    assert history[-1].note == "crown-jewel asset"
    stale = core.ledger.finding(row.id)
    assert stale is not None
    assert stale.cvss_tm_version == 1  # unchanged until rescored (freeze)
    assert stale.cvss_score == base_score

    # Rescore lifts it to v2; the environmental score now exists and the vector is
    # still the threat-model-free base (reproducible).
    assert dispatch.run_findings(core, "rescore all") == (
        "rescored 1 finding(s) to the current threat model"
    )
    fresh = core.ledger.finding(row.id)
    assert fresh is not None
    assert fresh.cvss_tm_version == 2
    assert fresh.cvss_environmental is not None
    assert "CR:" not in (fresh.cvss_vector or "")
