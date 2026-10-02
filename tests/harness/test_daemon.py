"""L3: the wrapped-shell daemon's request routing (no real socket)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from skuggi.agent.core import AgentCore
from skuggi.frontend.daemon import Daemon
from skuggi.persistence import pdf as pdf_mod
from skuggi.tooling import probe as probe_mod
from skuggi.tooling.commands import CommandAlias, CommandRegistry
from skuggi.tooling.registry import ToolSpec, ToolStatus
from tests.conftest import offline_settings, wire_offline_core


def _core(tmp_path: Path) -> AgentCore:
    core = AgentCore(offline_settings(tmp_path, engagement="test-eng"))
    wire_offline_core(core)
    return core


@pytest.fixture
def daemon(tmp_path: Path, pentest_configs: Callable[..., Path]) -> Iterator[Daemon]:
    pentest_configs()
    core = _core(tmp_path)
    yield Daemon(core)
    core.close()


def _chunks(daemon: Daemon, msg: dict[str, object]) -> str:
    return "".join(str(r.get("chunk", "")) for r in daemon.handle_request(msg))


def _responses(daemon: Daemon, msg: dict[str, object]) -> list[dict[str, object]]:
    return list(daemon.handle_request(msg))


def test_op_exit_signals_shell_exit(daemon: Daemon) -> None:
    assert _responses(daemon, {"op": "exit"}) == [{"end": True, "exit": True}]


def test_blank_input_just_ends(daemon: Daemon) -> None:
    assert _responses(daemon, {"op": "input", "text": "  "}) == [
        {"end": True, "exit": False}
    ]


def test_bare_exit_word_leaves(daemon: Daemon) -> None:
    responses = _responses(daemon, {"op": "input", "text": "exit"})
    assert responses[-1] == {"end": True, "exit": True}


def test_plain_input_reaches_the_agent(daemon: Daemon) -> None:
    out = _chunks(daemon, {"op": "input", "text": "ask what is exposed?"})
    assert "the answer" in out
    assert "(planner)" in out


def test_slash_findings_lists_findings(daemon: Daemon) -> None:
    assert "no findings" in _chunks(daemon, {"op": "input", "text": "/findings"})


def test_slash_add_note_and_list(daemon: Daemon) -> None:
    assert "no notes yet" in _chunks(daemon, {"op": "input", "text": "/notes"})
    assert "noted" in _chunks(daemon, {"op": "input", "text": "/add note recon done"})
    assert "recon done" in _chunks(daemon, {"op": "input", "text": "/notes"})


def test_slash_add_loot_and_list(daemon: Daemon) -> None:
    assert "no loot yet" in _chunks(daemon, {"op": "input", "text": "/loot"})
    added = _chunks(daemon, {"op": "input", "text": "/add loot cred admin:hunter2"})
    assert "loot recorded" in added
    assert "hunter2" in _chunks(daemon, {"op": "input", "text": "/loot"})


def test_slash_add_finding_records_and_surfaces(daemon: Daemon) -> None:
    out = _chunks(daemon, {"op": "input", "text": "/add finding high SQLi in login"})
    assert "recorded" in out
    assert "SQLi in login" in out
    assert "SQLi in login" in _chunks(daemon, {"op": "input", "text": "/findings"})


def test_slash_add_usage_and_bad_severity(daemon: Daemon) -> None:
    assert "usage: add note" in _chunks(daemon, {"op": "input", "text": "/add"})
    assert "usage: add note" in _chunks(daemon, {"op": "input", "text": "/add note"})
    assert "usage: add finding" in _chunks(
        daemon, {"op": "input", "text": "/add finding high"}
    )
    bad = _chunks(daemon, {"op": "input", "text": "/add finding spicy bad one"})
    assert "unknown severity" in bad


def test_slash_add_note_without_engagement(tmp_path: Path) -> None:
    core = AgentCore(offline_settings(tmp_path, engagement=None))
    wire_offline_core(core)
    unscoped = Daemon(core)
    try:
        out = _chunks(unscoped, {"op": "input", "text": "/add note nowhere to go"})
        assert "no engagement loaded" in out
    finally:
        core.close()


def test_slash_report_writes(daemon: Daemon) -> None:
    assert "report written" in _chunks(daemon, {"op": "input", "text": "/report"})


def test_slash_visualize_writes(daemon: Daemon) -> None:
    out = _chunks(daemon, {"op": "input", "text": "/visualize"})
    assert "visualization written" in out


def test_slash_report_pdf_writes_both(
    daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_markdown_to_pdf(
        md_text: str, out: Path, *, title: str, generated_label: str | None = None
    ) -> Path:
        out.write_bytes(b"%PDF-fake")
        return out

    monkeypatch.setattr(pdf_mod, "markdown_to_pdf", fake_markdown_to_pdf)
    out = _chunks(daemon, {"op": "input", "text": "/report pdf"})
    assert "report written" in out
    assert "pdf written" in out


def test_slash_engagement_shows_scope(daemon: Daemon) -> None:
    assert "test-eng" in _chunks(daemon, {"op": "input", "text": "/engagement"})


def test_slash_doctor(daemon: Daemon, monkeypatch: pytest.MonkeyPatch) -> None:
    spec = ToolSpec(name="nmap", binary="nmap", method="scan")
    monkeypatch.setattr(
        probe_mod,
        "probe",
        lambda *_a, **_k: [
            ToolStatus(spec, found=True, path=Path("/x"), version="7", source="host")
        ],
    )
    monkeypatch.setattr(probe_mod, "probe_runtimes", lambda *_a, **_k: [])
    monkeypatch.setattr(probe_mod, "probe_net_tools", lambda *_a, **_k: [])
    assert "nmap" in _chunks(daemon, {"op": "input", "text": "/doctor"})


def test_slash_mode_switches_and_reports_error(daemon: Daemon) -> None:
    assert "blueteam" in _chunks(daemon, {"op": "input", "text": "/mode blueteam"})
    assert "unknown mode" in _chunks(daemon, {"op": "input", "text": "/mode nope"})


def test_slash_autonomous_toggles(daemon: Daemon) -> None:
    assert "ON" in _chunks(daemon, {"op": "input", "text": "/autonomous on"})
    assert "off" in _chunks(daemon, {"op": "input", "text": "/autonomous off"})


def test_slash_help_and_unknown(daemon: Daemon) -> None:
    assert "/skuggi" in _chunks(daemon, {"op": "input", "text": "/help"})
    assert "unknown verb" in _chunks(daemon, {"op": "input", "text": "/bogus"})


def test_verb_first_without_slash(daemon: Daemon) -> None:
    """The wrapped shell sends bare verbs (no leading slash)."""
    assert "no findings" in _chunks(daemon, {"op": "input", "text": "findings"})
    assert "the answer" in _chunks(daemon, {"op": "input", "text": "ask hello"})


def test_ask_without_prompt_shows_usage(daemon: Daemon) -> None:
    assert "usage: ask" in _chunks(daemon, {"op": "input", "text": "ask"})


def test_provider_and_model(daemon: Daemon) -> None:
    assert "switched to" in _chunks(daemon, {"op": "input", "text": "provider ollama"})
    assert "usage:" in _chunks(daemon, {"op": "input", "text": "model"})
    assert "switched to" in _chunks(daemon, {"op": "input", "text": "model qwen3"})


def test_provider_rejects_unknown(daemon: Daemon) -> None:
    assert "unknown" in _chunks(daemon, {"op": "input", "text": "provider banana"})


def test_provider_with_no_arg_shows_usage_and_setup_hint(daemon: Daemon) -> None:
    out = _chunks(daemon, {"op": "input", "text": "provider"})
    assert "usage: provider" in out
    assert "/skuggi setup" in out  # one-shot surface uses the shell grammar


def test_provider_without_a_credential_points_to_setup(daemon: Daemon) -> None:
    # Switching to a provider that has no key reports a setup hint, not a raw
    # "provider error: No OpenAI API key…".
    out = _chunks(daemon, {"op": "input", "text": "provider openai"})
    assert "openai isn't configured" in out
    assert "/skuggi setup" in out


def test_attached_hints_use_the_bare_chat_grammar(daemon: Daemon) -> None:
    # In the persistent chat loop (mode=loop), a hint uses bare-verb grammar,
    # not the /skuggi-prefixed shell grammar.
    lines = iter(["provider", None])
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(lines), emitted.append, mode="loop")
    out = "".join(str(e.get("chunk", "")) for e in emitted)
    assert "run setup to configure one" in out
    assert "/skuggi" not in out


def test_thread_new_list_switch(daemon: Daemon) -> None:
    # A turn checkpoints the current thread, so `list` has one to mark.
    _chunks(daemon, {"op": "input", "text": "ask hello"})
    assert "*" in _chunks(daemon, {"op": "input", "text": "thread list"})
    assert "new thread" in _chunks(daemon, {"op": "input", "text": "thread new"})
    assert "switched to thread" in _chunks(
        daemon, {"op": "input", "text": "thread abc123"}
    )


def test_history_and_trace(daemon: Daemon) -> None:
    _chunks(daemon, {"op": "input", "text": "ask hello"})
    assert "you:" in _chunks(daemon, {"op": "input", "text": "history"})
    assert _chunks(daemon, {"op": "input", "text": "trace"})  # non-empty


def test_ingest_usage_and_index(daemon: Daemon, tmp_path: Path) -> None:
    assert "usage: ingest" in _chunks(daemon, {"op": "input", "text": "ingest"})
    doc = tmp_path / "note.md"
    doc.write_text("hello world", encoding="utf-8")
    assert "indexed" in _chunks(daemon, {"op": "input", "text": f"ingest {doc}"})


def test_clear_is_repl_only(daemon: Daemon) -> None:
    assert "skuggi-repl" in _chunks(daemon, {"op": "input", "text": "clear"})


def test_doctor_install(daemon: Daemon, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        probe_mod, "install_tool", lambda *_a, **_k: None
    )  # unknown tool
    assert "unknown tool" in _chunks(
        daemon, {"op": "input", "text": "doctor install ghost"}
    )


def test_cmd_resolve_in_scope(daemon: Daemon) -> None:
    daemon.core.commands = CommandRegistry(
        commands=(CommandAlias(name="nmap-network", argv=("nmap", "-sn")),)
    )
    out = _chunks(daemon, {"op": "input", "text": "cmd nmap-network"})
    assert "$ nmap -sn ${target}" in out  # rendered command, literal placeholder
    assert "scope" in out


def test_cmd_resolve_out_of_scope(daemon: Daemon) -> None:
    daemon.core.commands = CommandRegistry(
        commands=(CommandAlias(name="nmap-host", argv=("nmap", "-sV", "-sC")),)
    )
    assert daemon.core.engagement is not None
    daemon.core.engagement = daemon.core.engagement.model_copy(
        update={
            "primary_target": "8.8.8.8",  # explicit target outside scope
            "allowed_hosts": frozenset(),
            "target_networks": (),
        }
    )
    out = _chunks(daemon, {"op": "input", "text": "cmd nmap-host"})
    assert "$ nmap -sV -sC ${target}" in out
    assert "OUT OF SCOPE" in out


def test_cmd_list_search_and_miss(daemon: Daemon) -> None:
    assert "no command aliases" in _chunks(daemon, {"op": "input", "text": "cmd"})
    daemon.core.commands = CommandRegistry(
        commands=(CommandAlias(name="nmap-host", argv=("nmap", "-sV")),)
    )
    assert "nmap-host" in _chunks(daemon, {"op": "input", "text": "cmd nmap"})
    assert "no cheatsheet entry matches" in _chunks(
        daemon, {"op": "input", "text": "cmd bogus"}
    )


# --- persistent interactive attach ------------------------------------------


def test_attach_routes_multiple_lines_over_one_session(daemon: Daemon) -> None:
    """One attach session dispatches successive lines against the warm core."""
    lines = iter(["/findings", "ask what is exposed?", "exit"])
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(lines, None), emitted.append)
    text = "".join(str(f.get("chunk", "")) for f in emitted)
    assert "no findings" in text  # first line routed as a control
    assert "the answer" in text  # second line reached the agent
    assert emitted[-1] == {"end": True, "exit": True}  # `exit` closed the session


def test_attach_stops_when_client_disconnects(daemon: Daemon) -> None:
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: None, emitted.append)  # immediate EOF
    assert emitted == []


def test_attach_continues_after_a_non_exit_turn(daemon: Daemon) -> None:
    """A non-exit line ends its turn (`exit` False) but keeps the session open."""
    lines = iter(["/findings", None])
    ends = []
    daemon.run_attached(
        lambda: next(lines, None),
        lambda r: ends.append(r) if r.get("end") else None,
    )
    assert ends == [{"end": True, "exit": False}]  # session stayed open, then EOF


def test_engagement_setup_one_shot_guides_to_the_loop(daemon: Daemon) -> None:
    out = _chunks(daemon, {"op": "input", "text": "engagement setup"})
    assert "interactive" in out  # one-shot cannot prompt; points at the loop


def test_cmd_add_one_shot_guides_to_the_loop(daemon: Daemon) -> None:
    out = _chunks(daemon, {"op": "input", "text": "cmd add"})
    assert "interactive" in out  # the editor needs the attach loop


def test_attach_cmd_editor_adds_an_alias(daemon: Daemon) -> None:
    answers = iter(
        [
            "cmd add",
            "scan-sweep",  # name
            "nmap -sn",  # command template
            "",  # description
            "",  # tool -> argv[0]
            "",  # label -> name sans prefix
            "",  # output_dir -> tool default
            "",  # output_flag -> tool default
            "",  # output -> keep default (True)
        ]
    )
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(answers, None), emitted.append)
    asks = [f["ask"] for f in emitted if "ask" in f]
    assert len(asks) == 8  # one prompt per alias field over the socket
    alias = daemon.core.commands.alias_for("scan-sweep")
    assert alias is not None  # hot-loaded into the warm core
    assert alias.argv == ("nmap", "-sn")
    assert "saved alias 'scan-sweep'" in "".join(
        str(f.get("chunk", "")) for f in emitted
    )


def test_attach_engagement_wizard_creates_and_hot_loads(daemon: Daemon) -> None:
    answers = iter(
        [
            "engagement setup",
            "acme",
            "UTC",
            "2026-01-01T00:00:00+00:00",
            "2026-12-31T23:59:59+00:00",
            "",  # daily windows -> any
            "10.0.0.0/24",
            "",  # hosts
            "nmap",
            "scan",
            "no",
        ]
    )
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(answers, None), emitted.append)
    asks = [f["ask"] for f in emitted if "ask" in f]
    assert len(asks) == 10  # one prompt per field, round-tripped over the socket
    assert daemon.core.engagement is not None
    assert daemon.core.engagement.name == "acme"  # hot-loaded into the warm core
    assert "loaded" in "".join(str(f.get("chunk", "")) for f in emitted)


# --- config verb ------------------------------------------------------------


def test_config_show_one_shot(daemon: Daemon) -> None:
    assert "provider = ollama" in _chunks(
        daemon, {"op": "input", "text": "config show"}
    )


def test_config_mechanical_one_shot(daemon: Daemon) -> None:
    out = _chunks(daemon, {"op": "input", "text": "config retrieve_k 7"})
    assert "retrieve_k = 7" in out
    assert daemon.core.settings.retrieve_k == 7


def test_config_nl_one_shot_points_at_the_loop(daemon: Daemon) -> None:
    out = _chunks(daemon, {"op": "input", "text": "config make it faster"})
    assert "chat loop" in out  # one-shot cannot confirm; needs the attach loop


def test_attach_config_request_confirms_and_applies(
    daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The LLM proposal is unit-tested in test_core; stub it so the attach flow
    # (propose -> confirm -> apply, applied to the warm core) is what's exercised.
    monkeypatch.setattr(
        daemon.core.config, "propose", lambda _request: [("mode", "blueteam")]
    )
    # The confirm is a menu now: the daemon emits a {"choose"} frame and the
    # client sends back the selected option ("yes").
    answers = iter(["config switch to blue team", "yes"])
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(answers, None), emitted.append)
    assert [f["choose"] for f in emitted if "choose" in f]  # asked to confirm
    assert daemon.core.mode == "blueteam"  # applied to the warm core
    assert "applied live" in "".join(str(f.get("chunk", "")) for f in emitted)


def test_record_op_logs_a_passthrough_command(daemon: Daemon) -> None:
    """The shell hook's fire-and-forget record op logs without a chat reply."""
    responses = _responses(daemon, {"op": "record", "text": "nmap -sV 10.0.0.5"})
    assert responses == [{"end": True, "exit": False}]
    cmds = daemon.core.ledger.commands_for(daemon.core.session_id)
    assert [c.status for c in cmds] == ["passthrough"]


def test_replay_lists_and_renders(daemon: Daemon) -> None:
    _chunks(daemon, {"op": "input", "text": "ask what is exposed?"})
    listing = _chunks(daemon, {"op": "input", "text": "replay list"})
    assert daemon.core.session_id[:8] in listing
    assert "*" in listing  # the current session is marked
    assert "what is exposed?" in _chunks(daemon, {"op": "input", "text": "replay"})


def test_review_routes_to_the_core(
    daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(daemon.core.archive, "review", lambda _ref: "you rushed recon")
    assert "you rushed recon" in _chunks(daemon, {"op": "input", "text": "review"})


def test_memory_add_list_and_forget(daemon: Daemon) -> None:
    assert "nothing remembered yet" in _chunks(
        daemon, {"op": "input", "text": "memory"}
    )
    added = _chunks(
        daemon, {"op": "input", "text": "memory add Prefer ffuf over gobuster"}
    )
    assert "remembered" in added
    assert "Prefer ffuf over gobuster" in _chunks(
        daemon, {"op": "input", "text": "memory"}
    )
    [row] = daemon.core.memory.entries()
    assert "forgotten" in _chunks(
        daemon, {"op": "input", "text": f"memory forget {row.id}"}
    )
    assert daemon.core.memory.entries() == []


def test_control_verbs_are_audited_but_ask_is_not(daemon: Daemon) -> None:
    _chunks(daemon, {"op": "input", "text": "mode blueteam"})  # control -> audit
    _chunks(daemon, {"op": "input", "text": "ask hello"})  # engagement -> timeline
    audit = daemon.core.ledger.audit_for(daemon.core.session_id)
    verbs_seen = {a.verb for a in audit if a.kind == "control"}
    assert "mode" in verbs_seen
    assert "ask" not in verbs_seen


def test_update_verb_streams_core_output(
    daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    # self_update's subprocess logic is unit-tested in test_core; here just prove
    # the `update` verb routes to it and streams its lines.
    monkeypatch.setattr(
        daemon.core, "self_update", lambda: iter(["updating\n", "done\n"])
    )
    out = _chunks(daemon, {"op": "input", "text": "update"})
    assert "updating" in out
    assert "done" in out
