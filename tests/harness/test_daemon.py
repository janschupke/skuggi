"""L3: the wrapped-shell daemon's request routing (no real socket)."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from skuggi.agent.turn_runner import TurnEvent
from skuggi.engagement.runtime_env import EngagementEnv
from skuggi.frontend import attach
from skuggi.frontend.daemon import Daemon
from skuggi.persistence import pdf as pdf_mod
from skuggi.tooling import probe as probe_mod
from skuggi.tooling.commands import CommandAlias, CommandRegistry
from skuggi.tooling.registry import ToolRegistry, ToolSpec, ToolStatus
from tests.harness.conftest import candidates, chunks, daemon_core, responses


def test_op_exit_signals_shell_exit(daemon: Daemon) -> None:
    assert responses(daemon, {"op": "exit"}) == [{"end": True, "exit": True}]


def test_complete_op_walks_the_verb_noun_tree(daemon: Daemon) -> None:
    top = candidates(daemon, [])
    assert {"show", "set", "cmd", "reconcile", "help"} <= set(top)
    assert "engagement" in candidates(daemon, ["set"])  # grouping-verb noun
    assert "engagement" in candidates(daemon, ["show"])
    recon = candidates(daemon, ["reconcile"])
    assert {"diff", "all", "config.json", "tools.json"} <= set(recon)
    assert "config.json" in candidates(daemon, ["reconcile", "diff"])
    assert candidates(daemon, ["bogus-verb"]) == []  # unknown -> no candidates


def test_blank_input_just_ends(daemon: Daemon) -> None:
    assert responses(daemon, {"op": "input", "text": "  "}) == [
        {"end": True, "exit": False}
    ]


def test_bare_exit_word_leaves(daemon: Daemon) -> None:
    frames = responses(daemon, {"op": "input", "text": "exit"})
    assert frames[-1] == {"end": True, "exit": True}


def test_plain_input_reaches_the_agent(daemon: Daemon) -> None:
    out = chunks(daemon, {"op": "input", "text": "ask what is exposed?"})
    assert "the answer" in out  # the clean answer reaches the operator
    assert "(planner)" not in out  # internal chatter no longer leaks to the shell
    assert "(critic)" not in out


def test_agent_streams_phase_labels_as_pending_frames(daemon: Daemon) -> None:
    # A slow turn must show what it is doing: each phase is a `pending` frame so
    # the client's spinner relabels live (planning -> working -> reviewing), while
    # the answer is a single trailing chunk so the spinner turns right up to it.
    frames = responses(daemon, {"op": "input", "text": "ask what is exposed?"})
    pending = [str(f["pending"]) for f in frames if "pending" in f]
    assert pending  # the turn announced its phases
    assert all(label.endswith("...") for label in pending)
    assert any("working" in label for label in pending)
    answer = "".join(str(f.get("chunk", "")) for f in frames)
    assert "the answer" in answer


def test_slash_findings_lists_findings(daemon: Daemon) -> None:
    assert "no findings" in chunks(daemon, {"op": "input", "text": "/show findings"})


def test_slash_add_note_and_list(daemon: Daemon) -> None:
    assert "no notes yet" in chunks(daemon, {"op": "input", "text": "/show notes"})
    added = chunks(daemon, {"op": "input", "text": "/add note recon all ports open"})
    assert "note recorded" in added
    assert "all ports open" in chunks(daemon, {"op": "input", "text": "/show notes"})


def test_slash_add_loot_and_list(daemon: Daemon) -> None:
    assert "no loot yet" in chunks(daemon, {"op": "input", "text": "/show loot"})
    added = chunks(
        daemon, {"op": "input", "text": "/add loot cred web01 admin:hunter2"}
    )
    assert "loot recorded" in added
    assert "hunter2" in chunks(daemon, {"op": "input", "text": "/show loot"})


def test_slash_add_finding_records_and_surfaces(daemon: Daemon) -> None:
    out = chunks(daemon, {"op": "input", "text": "/add finding high SQLi in login"})
    assert "recorded" in out
    assert "SQLi in login" in out
    assert "SQLi in login" in chunks(daemon, {"op": "input", "text": "/show findings"})


def test_slash_add_usage_and_bad_severity(daemon: Daemon) -> None:
    bare = chunks(daemon, {"op": "input", "text": "/add"})
    assert "note" in bare  # the noun list
    assert "memory" in bare
    assert "add note" in chunks(daemon, {"op": "input", "text": "/add note"})
    assert "add finding" in chunks(daemon, {"op": "input", "text": "/add finding high"})
    bad = chunks(daemon, {"op": "input", "text": "/add finding spicy bad one"})
    assert "unknown severity" in bad


def test_slash_add_note_without_engagement(tmp_path: Path) -> None:
    core = daemon_core(tmp_path)
    unscoped = Daemon(core)
    try:
        out = chunks(unscoped, {"op": "input", "text": "/add note nowhere to go"})
        assert "no engagement loaded" in out
    finally:
        core.close()


def test_slash_report_writes(daemon: Daemon) -> None:
    assert "report written" in chunks(daemon, {"op": "input", "text": "/report"})


def test_slash_visualize_writes(daemon: Daemon) -> None:
    out = chunks(daemon, {"op": "input", "text": "/visualize"})
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
    out = chunks(daemon, {"op": "input", "text": "/report pdf"})
    assert "report written" in out
    assert "pdf written" in out


def test_slash_engagement_shows_scope(daemon: Daemon) -> None:
    assert "test-eng" in chunks(daemon, {"op": "input", "text": "/show engagement"})


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
    assert "nmap" in chunks(daemon, {"op": "input", "text": "/doctor"})


def test_slash_mode_switches_and_reports_error(daemon: Daemon) -> None:
    assert "blueteam" in chunks(daemon, {"op": "input", "text": "/set mode blueteam"})
    assert "unknown mode" in chunks(daemon, {"op": "input", "text": "/set mode nope"})


def test_slash_autonomous_toggles(daemon: Daemon) -> None:
    assert "ON" in chunks(daemon, {"op": "input", "text": "/set autonomous on"})
    assert "off" in chunks(daemon, {"op": "input", "text": "/set autonomous off"})


def test_slash_help_and_unknown(daemon: Daemon) -> None:
    assert "/skuggi" in chunks(daemon, {"op": "input", "text": "/help"})
    assert "unknown command" in chunks(daemon, {"op": "input", "text": "/bogus"})


def test_verb_first_without_slash(daemon: Daemon) -> None:
    """The wrapped shell sends bare verbs (no leading slash)."""
    assert "no findings" in chunks(daemon, {"op": "input", "text": "show findings"})
    assert "the answer" in chunks(daemon, {"op": "input", "text": "ask hello"})


def test_ask_without_prompt_shows_usage(daemon: Daemon) -> None:
    assert "usage: ask" in chunks(daemon, {"op": "input", "text": "ask"})


def test_provider_and_model(daemon: Daemon) -> None:
    out = chunks(daemon, {"op": "input", "text": "set provider ollama"})
    assert "switched to" in out
    # A no-value `set model` one-shot points at the interactive picker.
    assert "interactive" in chunks(daemon, {"op": "input", "text": "set model"})
    assert "switched to" in chunks(daemon, {"op": "input", "text": "set model qwen3"})


def test_provider_rejects_unknown(daemon: Daemon) -> None:
    assert "unknown" in chunks(daemon, {"op": "input", "text": "set provider banana"})


def test_set_provider_with_no_value_points_to_the_picker(daemon: Daemon) -> None:
    out = chunks(daemon, {"op": "input", "text": "set provider"})
    assert "interactive" in out
    assert "/skuggi set provider" in out  # one-shot surface uses the shell grammar


def test_provider_without_a_credential_points_to_set_provider(daemon: Daemon) -> None:
    # Switching to a provider that has no key reports a set-provider hint, not a
    # raw "provider error: No OpenAI API key…".
    out = chunks(daemon, {"op": "input", "text": "set provider openai"})
    assert "openai isn't configured" in out
    assert "/skuggi set provider" in out


def test_attached_hints_use_the_bare_chat_grammar(daemon: Daemon) -> None:
    # In the persistent chat loop (mode=loop), a hint uses bare-verb grammar,
    # not the /skuggi-prefixed shell grammar.
    lines = iter(["set provider openai", None])
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(lines), emitted.append, mode="loop")
    out = "".join(str(e.get("chunk", "")) for e in emitted)
    assert "run set provider to add a key" in out
    assert "/skuggi" not in out


def test_attached_help_uses_the_bare_chat_grammar(daemon: Daemon) -> None:
    # `help` in the chat loop must list the bare verbs the operator actually
    # types there (`show config`), never the `/skuggi show config` shell grammar.
    lines = iter(["help", "help show", None])
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(lines), emitted.append, mode="loop")
    out = "".join(str(e.get("chunk", "")) for e in emitted)
    assert "/skuggi" not in out
    assert "show <what>" in out  # the collapsed grouping-verb row, bare
    assert "show status" in out  # a noun row from `help show`, bare


def test_thread_new_list_switch(daemon: Daemon) -> None:
    # A turn checkpoints the current thread, so `list` has one to mark.
    chunks(daemon, {"op": "input", "text": "ask hello"})
    assert "*" in chunks(daemon, {"op": "input", "text": "show threads"})
    assert "new thread" in chunks(daemon, {"op": "input", "text": "set thread new"})
    assert "switched to thread" in chunks(
        daemon, {"op": "input", "text": "set thread abc123"}
    )


def test_history_and_trace(daemon: Daemon) -> None:
    chunks(daemon, {"op": "input", "text": "ask hello"})
    assert "you:" in chunks(daemon, {"op": "input", "text": "show history"})
    assert chunks(daemon, {"op": "input", "text": "show trace"})  # non-empty


def test_ingest_usage_and_index(daemon: Daemon, tmp_path: Path) -> None:
    assert "ingest <path>" in chunks(daemon, {"op": "input", "text": "ingest"})
    doc = tmp_path / "note.md"
    doc.write_text("hello world", encoding="utf-8")
    assert "indexed" in chunks(daemon, {"op": "input", "text": f"ingest {doc}"})


def test_clear_is_repl_only(daemon: Daemon) -> None:
    assert "skuggi-repl" in chunks(daemon, {"op": "input", "text": "clear"})


def test_doctor_install(daemon: Daemon, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        probe_mod, "install_tool", lambda *_a, **_k: None
    )  # unknown tool
    assert "unknown tool" in chunks(
        daemon, {"op": "input", "text": "doctor install ghost"}
    )


def _register_ghost(daemon: Daemon) -> ToolSpec:
    spec = ToolSpec(name="ghost", binary="ghost", method="scan")
    daemon.core.registry = ToolRegistry(tools=(spec,))
    return spec


def test_doctor_install_success(
    daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = _register_ghost(daemon)
    status = ToolStatus(
        spec=spec, found=True, path=Path("/usr/bin/ghost"), version="9.9", source="brew"
    )
    monkeypatch.setattr(probe_mod, "install_tool", lambda *_a, **_k: status)
    out = chunks(daemon, {"op": "input", "text": "doctor install ghost"})
    assert "installed ghost (9.9) via brew" in out


def test_doctor_install_failure(
    daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = _register_ghost(daemon)
    status = ToolStatus(
        spec=spec, found=False, path=None, version=None, source="missing"
    )
    monkeypatch.setattr(probe_mod, "install_tool", lambda *_a, **_k: status)
    out = chunks(daemon, {"op": "input", "text": "doctor install ghost"})
    assert "install failed or unavailable for ghost" in out


def test_cmd_resolve_in_scope(daemon: Daemon) -> None:
    daemon.core.commands = CommandRegistry(
        commands=(CommandAlias(name="nmap-network", argv=("nmap", "-sn")),)
    )
    out = chunks(daemon, {"op": "input", "text": "cmd nmap-network"})
    assert "$ nmap -sn ${target}" in out  # rendered command, literal placeholder
    assert "scope" in out


def test_cmd_resolve_out_of_scope(daemon: Daemon) -> None:
    daemon.core.commands = CommandRegistry(
        commands=(CommandAlias(name="nmap-host", argv=("nmap", "-sV", "-sC")),)
    )
    assert daemon.core.engagement is not None
    daemon.core.engagement = daemon.core.engagement.model_copy(
        update={"allowed_hosts": frozenset(), "target_networks": ()}
    )
    # A manual env target outside the (now empty) scope -> out of scope.
    daemon.core.apply_env(EngagementEnv(target="8.8.8.8"))
    out = chunks(daemon, {"op": "input", "text": "cmd nmap-host"})
    assert "$ nmap -sV -sC ${target}" in out
    assert "OUT OF SCOPE" in out


def test_cmd_list_search_and_miss(daemon: Daemon) -> None:
    assert "no command aliases" in chunks(daemon, {"op": "input", "text": "cmd"})
    daemon.core.commands = CommandRegistry(
        commands=(CommandAlias(name="nmap-host", argv=("nmap", "-sV")),)
    )
    assert "nmap-host" in chunks(daemon, {"op": "input", "text": "cmd nmap"})
    assert "no cheatsheet entry matches" in chunks(
        daemon, {"op": "input", "text": "cmd bogus"}
    )


def _raw(daemon: Daemon, msg: dict[str, object]) -> str:
    """Like `chunks`, but WITHOUT stripping SGR -- so highlighting is visible."""
    return "".join(str(r.get("chunk", "")) for r in daemon.handle_request(msg))


_REVERSE = "\x1b[7m"  # the SGR introducer Rich emits for the `reverse` match style


def test_cmd_search_highlights_the_matched_substring(daemon: Daemon) -> None:
    daemon.core.commands = CommandRegistry(
        commands=(
            CommandAlias(name="nmap-host", argv=("nmap", "-sV"), description="scan it"),
            CommandAlias(name="web-dir", argv=("curl",), description="d"),
        )
    )
    out = _raw(daemon, {"op": "input", "text": "cmd nmap"})
    # the query is reverse-video, and the full name + literal target survive
    assert _REVERSE in out
    assert f"{_REVERSE}nmap" in out
    assert "nmap-host" in chunks(daemon, {"op": "input", "text": "cmd nmap"})
    assert "${target}" in out
    # the listing stays filtered to the hit
    assert "web-dir" not in out


def test_cmd_list_has_nothing_to_highlight(daemon: Daemon) -> None:
    daemon.core.commands = CommandRegistry(
        commands=(
            CommandAlias(name="nmap-host", argv=("nmap", "-sV"), description="d"),
        )
    )
    out = _raw(daemon, {"op": "input", "text": "cmd list"})
    assert _REVERSE not in out  # blank query -> no match style
    # alignment/content preserved (ANSI-stripped)
    assert "nmap-host" in chunks(daemon, {"op": "input", "text": "cmd list"})


# --- config verb ------------------------------------------------------------


def test_config_show_one_shot(daemon: Daemon) -> None:
    assert "provider = ollama" in chunks(daemon, {"op": "input", "text": "show config"})


def test_config_mechanical_one_shot(daemon: Daemon) -> None:
    out = chunks(daemon, {"op": "input", "text": "set config retrieve_k 7"})
    assert "retrieve_k = 7" in out
    assert daemon.core.settings.retrieve_k == 7


def test_config_nl_one_shot_points_at_the_loop(daemon: Daemon) -> None:
    out = chunks(daemon, {"op": "input", "text": "set config make it faster"})
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
    # client sends back the selected option ("approve" for an agentic gated write).
    answers = iter(["set config switch to blue team", "approve"])
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(answers, None), emitted.append)
    assert [f["choose"] for f in emitted if "choose" in f]  # asked to confirm
    assert daemon.core.mode == "blueteam"  # applied to the warm core
    assert "applied live" in "".join(str(f.get("chunk", "")) for f in emitted)


def test_record_op_logs_a_passthrough_command(daemon: Daemon) -> None:
    """The shell hook's fire-and-forget record op logs without a chat reply."""
    frames = responses(daemon, {"op": "record", "text": "nmap -sV 10.0.0.5"})
    assert frames == [{"end": True, "exit": False}]
    cmds = daemon.core.ledger.commands_for(daemon.core.session_id)
    assert [c.status for c in cmds] == ["passthrough"]


def test_replay_lists_and_renders(daemon: Daemon) -> None:
    chunks(daemon, {"op": "input", "text": "ask what is exposed?"})
    listing = chunks(daemon, {"op": "input", "text": "replay list"})
    assert daemon.core.session_id[:8] in listing
    assert "*" in listing  # the current session is marked
    assert "what is exposed?" in chunks(daemon, {"op": "input", "text": "replay"})


def test_review_routes_to_the_core(
    daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(daemon.core.archive, "review", lambda _ref: "you rushed recon")
    assert "you rushed recon" in chunks(daemon, {"op": "input", "text": "review"})


def test_one_shot_ask_announces_a_memory_but_writes_nothing(
    daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A one-shot `ask` has no loop to confirm against: it announces, never writes."""
    cand = ["Prefer ffuf over gobuster"]
    monkeypatch.setattr(daemon.core.memory, "propose_capture", lambda _t: cand)
    out = chunks(daemon, {"op": "input", "text": "ask always prefer ffuf"})
    assert "suggests remembering" in out
    assert "Prefer ffuf over gobuster" in out
    assert "not written" in out
    assert daemon.core.memory.entries() == [], "a one-shot ask must not write memory"


def test_memory_add_list_and_forget(daemon: Daemon) -> None:
    assert "(no memories yet)" in chunks(daemon, {"op": "input", "text": "show memory"})
    added = chunks(
        daemon, {"op": "input", "text": "add memory Prefer ffuf over gobuster"}
    )
    assert "remembered" in added
    assert "Prefer ffuf over gobuster" in chunks(
        daemon, {"op": "input", "text": "show memory"}
    )
    [row] = daemon.core.memory.entries()
    assert "forgotten" in chunks(
        daemon, {"op": "input", "text": f"remove memory {row.id}"}
    )
    assert daemon.core.memory.entries() == []


def test_control_verbs_are_audited_but_ask_is_not(daemon: Daemon) -> None:
    chunks(daemon, {"op": "input", "text": "set mode blueteam"})  # control -> audit
    chunks(daemon, {"op": "input", "text": "ask hello"})  # engagement -> timeline
    audit = daemon.core.ledger.audit_for(daemon.core.session_id)
    verbs_seen = {a.verb for a in audit if a.kind == "control"}
    assert "set" in verbs_seen
    assert "ask" not in verbs_seen


def test_update_verb_streams_core_output(
    daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    # self_update's subprocess logic is unit-tested in test_core; here just prove
    # the `update` verb routes to it and streams its lines.
    monkeypatch.setattr(
        daemon.core, "self_update", lambda: iter(["updating\n", "done\n"])
    )
    out = chunks(daemon, {"op": "input", "text": "update"})
    assert "updating" in out
    assert "done" in out


def test_agent_relays_a_multiline_error_in_full(
    daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A pydantic ValidationError spans several lines; the daemon must not truncate
    # the error node to its first line, or the field/reason are lost (which
    # hid the real planner crash behind a bare "1 validation error").
    err = (
        "ValidationError: 1 validation error for PlannerResponse\n"
        "phase\n  Field required"
    )
    monkeypatch.setattr(
        daemon.core,
        "turn",
        lambda _text: iter([TurnEvent("status", err, node="error")]),
    )
    out = "".join(
        str(frame.get("chunk", "")) for frame in daemon._agent("ask who are you?")
    )
    assert "phase" in out
    assert "Field required" in out


# --- show <noun> / set interactive / scaffold over the daemon ---------------


def test_show_status_db_config(daemon: Daemon) -> None:
    assert "engagement test-eng" in chunks(
        daemon, {"op": "input", "text": "show status"}
    )
    assert "skuggi session ended" in chunks(daemon, {"op": "input", "text": "show db"})
    assert "provider = ollama" in chunks(daemon, {"op": "input", "text": "show config"})


def test_show_provider_and_model(daemon: Daemon) -> None:
    assert "provider ollama" in chunks(daemon, {"op": "input", "text": "show provider"})
    assert "model" in chunks(daemon, {"op": "input", "text": "show model"})


def test_show_tools_filters(daemon: Daemon, monkeypatch: pytest.MonkeyPatch) -> None:
    spec = ToolSpec(name="nmap", binary="nmap", method="scan")
    monkeypatch.setattr(
        probe_mod,
        "probe",
        lambda *_a, **_k: [
            ToolStatus(spec, found=True, path=Path("/x"), version="7", source="host")
        ],
    )
    assert "nmap" in chunks(daemon, {"op": "input", "text": "show tools all"})
    assert "no missing tools" in chunks(
        daemon, {"op": "input", "text": "show tools missing"}
    )
    assert "usage:" in chunks(daemon, {"op": "input", "text": "show tools bogus"})


def test_show_unknown_noun_shows_usage(daemon: Daemon) -> None:
    out = chunks(daemon, {"op": "input", "text": "show bogus"})
    assert "usage:" in out
    assert "config" in out


def test_set_thread_new_and_switch(daemon: Daemon) -> None:
    assert "new thread" in chunks(daemon, {"op": "input", "text": "set thread new"})
    assert "switched to thread" in chunks(
        daemon, {"op": "input", "text": "set thread abc123"}
    )


def test_remove_memory_all(daemon: Daemon) -> None:
    chunks(daemon, {"op": "input", "text": "add memory prefer ffuf"})
    assert "cleared" in chunks(daemon, {"op": "input", "text": "remove memory all"})
    assert daemon.core.memory.entries() == []


def test_findings_review_usage(daemon: Daemon) -> None:
    out = chunks(daemon, {"op": "input", "text": "findings"})
    assert "usage:" in out
    assert "show findings" in out


def test_set_engagement_scaffolds_and_adopts_over_socket(
    daemon: Daemon, tmp_path: Path
) -> None:
    root = tmp_path / "new-eng"
    out = chunks(daemon, {"op": "input", "text": f"set engagement {root}"})
    assert "scaffolded" in out
    assert "adopted engagement" in out
    assert (root / "scope.json").is_file()
    assert daemon.core.workspace is not None
    assert daemon.core.workspace.root == root


def test_cmd_resolve_does_not_invoke_the_planner(daemon: Daemon) -> None:
    daemon.core.commands = CommandRegistry(
        commands=(CommandAlias(name="nmap-network", argv=("nmap", "-sn")),)
    )
    out = chunks(daemon, {"op": "input", "text": "cmd nmap-network"})
    assert "$ nmap -sn ${target}" in out
    assert "(planner)" not in out  # resolve returns control; no agent turn fires


def test_help_for_a_verb_lists_nouns(daemon: Daemon) -> None:
    out = chunks(daemon, {"op": "input", "text": "help show"})
    assert "/skuggi show status" in out
    assert "/skuggi show tools" in out


def test_is_set_interactive_detects_no_value_forms() -> None:
    assert attach.is_set_interactive("set provider")
    assert attach.is_set_interactive("set model")
    assert attach.is_set_interactive("set listener")
    assert not attach.is_set_interactive("set provider openai")
    assert not attach.is_set_interactive("set mode pentest")
    assert not attach.is_set_interactive("show status")


def test_set_listener_one_shot_points_at_the_chat_loop(daemon: Daemon) -> None:
    out = chunks(daemon, {"op": "input", "text": "set listener"})
    assert "interactive" in out
    assert "/skuggi set listener" in out  # the shell grammar for the chat loop


def test_attach_set_listener_picks_interface_and_port(
    daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        probe_mod,
        "local_interfaces",
        lambda *_a, **_k: [("eth0", "192.168.1.10"), ("tun0", "10.8.0.2")],
    )
    # The chat line, the chosen interface label, then the port.
    answers = iter(["set listener", "tun0  10.8.0.2", "4444"])
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(answers, None), emitted.append)
    assert any("choose" in f for f in emitted)  # the interface picker frame
    assert daemon.core.env.lhost == "10.8.0.2"
    assert daemon.core.env.lport == "4444"


def test_attach_set_model_round_trips_a_choose_frame(daemon: Daemon) -> None:
    answers = iter(["set model", "qwen3"])
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(answers, None), emitted.append)
    assert any("choose" in f for f in emitted)  # the model picker frame


def test_login_does_not_deadlock(daemon: Daemon) -> None:
    """Regression for audit B2: _login must not re-acquire the handler lock.

    Driven in a thread with a timeout so a regression (the non-reentrant lock
    re-acquired under handle_request's lock) fails loudly instead of hanging the
    whole suite.
    """

    def fake_login(notify: object = None) -> str:
        if callable(notify):
            notify("opening browser")
        return "acct"

    daemon.core.login_chatgpt = fake_login  # type: ignore[method-assign]
    out: list[str] = []

    def run() -> None:
        out.append(chunks(daemon, {"op": "input", "text": "login"}))

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=5.0)
    assert not t.is_alive(), "login deadlocked (re-acquired the handler lock)"
    assert "logged in to chatgpt" in out[0]
