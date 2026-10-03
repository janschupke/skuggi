"""L3: the REPL end to end, offline, through its real entry points.

The console is injected so rendered output is assertable without a terminal.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from pathlib import Path

import pytest
from rich.console import Console

from skuggi.frontend import menu, verbs
from skuggi.frontend.tui import Tui
from tests.conftest import offline_settings, wire_offline_core
from tests.fakes import FakePromptSession


@pytest.fixture
def tui(tmp_path: Path) -> tuple[Tui, io.StringIO]:
    """A REPL wired to a scripted model, with no network anywhere."""
    buffer = io.StringIO()
    app = Tui(offline_settings(tmp_path), console=Console(file=buffer, width=100))
    # Offline doubles (no engagement here).
    wire_offline_core(app.core)
    return app, buffer


def _out(buffer: io.StringIO) -> str:
    return buffer.getvalue()


# --- dispatch ---------------------------------------------------------------


@pytest.mark.parametrize("command", ["/quit", "/exit"])
def test_quit_aliases_end_the_session(
    tui: tuple[Tui, io.StringIO], command: str
) -> None:
    app, _ = tui
    assert app.dispatch(command) is False


def test_unknown_command_is_reported(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    assert app.dispatch("/nope") is None
    assert "unknown command" in _out(buffer)


def test_help_and_dispatch_do_not_drift(tui: tuple[Tui, io.StringIO]) -> None:
    """Every documented command must be handled, and vice versa.

    This is the drift a help table and an if/elif chain always develop.
    """
    app, _ = tui
    assert set(app._commands) == verbs.KNOWN - {"ask", "exit"}


def test_provider_switch_rebuilds_the_graph(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    before = app.graph
    app.dispatch("/set provider anthropic")
    assert "isn't configured" in _out(buffer), (
        "no ANTHROPIC_API_KEY in this environment"
    )
    assert app.graph is before, "a failed switch must keep the working graph"


def test_invalid_provider_is_rejected(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    before = app.graph
    app.dispatch("/set provider banana")
    assert "unknown provider" in _out(buffer)
    assert app.graph is before


def test_set_model_switches_directly(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.dispatch("/set model qwen3")
    assert "switched to" in _out(buffer)


def test_set_model_interactive_keeps_current_on_abort(
    tui: tuple[Tui, io.StringIO], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, buffer = tui
    # No name -> the picker opens; aborting it (menu returns None) keeps the model.
    monkeypatch.setattr(menu, "select", lambda *_a, **_k: None)
    app.dispatch("/set model")
    assert "keeping the current model" in _out(buffer)


def test_set_provider_interactive_can_be_cancelled(
    tui: tuple[Tui, io.StringIO], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, buffer = tui
    # No name -> the guided setup opens; aborting the provider menu cancels it.
    monkeypatch.setattr(menu, "select", lambda *_a, **_k: None)
    app.dispatch("/set provider")
    assert "setup cancelled" in _out(buffer)


def test_thread_new_changes_the_id(tui: tuple[Tui, io.StringIO]) -> None:
    app, _ = tui
    first = app.thread_id
    app.dispatch("/set thread new")
    assert app.thread_id != first


def test_bare_thread_is_also_new(tui: tuple[Tui, io.StringIO]) -> None:
    app, _ = tui
    first = app.thread_id
    app.dispatch("/set thread")
    assert app.thread_id != first


def test_thread_list_is_empty_before_any_turn(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.dispatch("/show threads")
    assert "(no threads yet)" in _out(buffer)


def test_thread_switch_sets_the_id(tui: tuple[Tui, io.StringIO]) -> None:
    app, _ = tui
    app.dispatch("/set thread abc123")
    assert app.thread_id == "abc123"


def test_ingest_requires_an_argument(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.dispatch("/ingest")
    assert "usage:" in _out(buffer)


def test_ingest_indexes_a_directory(
    tui: tuple[Tui, io.StringIO], tmp_path: Path
) -> None:
    """Regression: Path was once used here without being imported."""
    app, buffer = tui
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "a.md").write_text("content", encoding="utf-8")

    app.dispatch(f"/ingest {docs}")

    assert "indexed 1 chunk" in _out(buffer)


def test_help_renders_grouped_sections(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.dispatch("/help")
    out = _out(buffer)
    assert "Commands" in out  # a group subheading
    assert "/show" in out  # the grouping verb, collapsed to one row


def test_help_for_a_verb_lists_its_nouns(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.dispatch("/help show")
    out = _out(buffer)
    assert "/show status" in out
    assert "/show tools" in out


# --- a full turn ------------------------------------------------------------


def test_turn_streams_the_answer_and_reports_the_other_nodes(
    tui: tuple[Tui, io.StringIO],
) -> None:
    app, buffer = tui

    app.turn("what is the answer?")
    output = _out(buffer)

    assert "the answer" in output
    assert "(planner)" in output
    assert "(critic)" in output
    assert "You are the worker" not in output, "scaffolding must not render"


def test_turn_persists_history_and_history_shows_it(
    tui: tuple[Tui, io.StringIO],
) -> None:
    app, buffer = tui
    app.turn("first question")
    buffer.truncate(0)
    buffer.seek(0)

    app.dispatch("/show history")
    output = _out(buffer)

    assert "first question" in output
    assert "the answer" in output


def test_trace_is_empty_without_tool_use(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.turn("q")
    buffer.truncate(0)
    buffer.seek(0)
    app.dispatch("/show trace")
    assert "no command activity" in _out(buffer)


def test_a_failing_turn_does_not_kill_the_repl(
    tui: tuple[Tui, io.StringIO],
) -> None:
    app, buffer = tui

    class Exploding:
        def stream(self, *_args: object, **_kwargs: object) -> object:
            msg = "provider exploded"
            raise RuntimeError(msg)

    app.core.graph = Exploding()  # type: ignore[assignment]
    app.turn("boom")

    output = _out(buffer)
    assert "(error)" in output
    assert "provider exploded" in output


def test_run_loops_until_end_of_input(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.session = FakePromptSession(["", "/set thread new", "/quit"])  # type: ignore[assignment]

    app.run()

    assert "bye." in _out(buffer)


def test_replay_review_and_control_audit(
    tui: tuple[Tui, io.StringIO], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, buffer = tui
    # review is stubbed (the LLM path is covered in test_session_logging)
    monkeypatch.setattr(app.core.archive, "review", lambda _ref: "you rushed recon")
    app.dispatch("/review")
    assert "you rushed recon" in _out(buffer)

    app.dispatch("/replay list")  # the current session is listed
    assert app.session_id[:8] in _out(buffer)
    app.dispatch("/replay")  # render the (empty) current session
    assert "No activity recorded" in _out(buffer)

    # a control verb is recorded to the audit log, an agent turn is not
    app.dispatch("/set mode blueteam")
    audit = app.core.ledger.audit_for(app.session_id)
    assert any(a.kind == "control" and a.verb == "set" for a in audit)


def test_memory_add_list_and_forget(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.dispatch("/show memory")  # nothing yet
    assert "(no memories yet)" in _out(buffer)

    app.dispatch("/add memory Prefer ffuf over gobuster")
    assert "remembered" in _out(buffer)
    app.dispatch("/show memory")
    assert "Prefer ffuf over gobuster" in _out(buffer)

    [row] = app.core.memory.entries()
    app.dispatch(f"/remove memory {row.id}")
    assert "forgotten" in _out(buffer)
    assert app.core.memory.entries() == []


def test_memory_add_requires_text(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.dispatch("/add memory")
    assert "usage:" in _out(buffer)


def test_memory_duplicate_forget_usage_and_clear(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.dispatch("/add memory prefer ffuf")
    app.dispatch("/add memory PREFER ffuf")  # case-insensitive duplicate
    assert "already remembered" in _out(buffer)
    app.dispatch("/remove memory nope")  # non-numeric id
    assert "usage:" in _out(buffer)
    app.dispatch("/remove memory all")
    assert "cleared 1 preference" in _out(buffer)
    assert app.core.memory.entries() == []


# --- notes / loot / findings (operator-recorded artifacts) ------------------


def test_add_note_without_engagement_explains(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui  # the repl fixture has no engagement loaded
    app.dispatch("/add note nowhere to write this")
    assert "no engagement loaded" in _out(buffer)


def test_notes_and_loot_empty_without_engagement(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.dispatch("/show notes")
    assert "no notes yet" in _out(buffer)
    app.dispatch("/show loot")
    assert "no loot yet" in _out(buffer)


def test_add_usage_and_bad_severity(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.dispatch("/add")  # no sub-command
    assert "usage:" in _out(buffer)
    app.dispatch("/add finding spicy a title")  # severity not valid
    assert "unknown severity" in _out(buffer)


def test_add_and_list_with_engagement(
    tmp_path: Path, pentest_configs: Callable[..., Path]
) -> None:
    pentest_configs()
    buffer = io.StringIO()
    app = Tui(
        offline_settings(tmp_path, engagement="test-eng"),
        console=Console(file=buffer, width=100),
    )
    wire_offline_core(app.core)
    try:
        app.dispatch("/add note found a subdomain")
        app.dispatch("/add loot token abc123")
        app.dispatch("/add finding medium open redirect on /go")
        app.dispatch("/show notes")
        app.dispatch("/show loot")
        app.dispatch("/show findings")
        out = _out(buffer)
        assert "noted" in out
        assert "loot recorded" in out
        assert "recorded" in out
        assert "found a subdomain" in out
        assert "token abc123" in out
        assert "open redirect on /go" in out
    finally:
        app.close()


# --- show status / tools in agent-only mode ---------------------------------


def test_show_status_lists_pending_without_engagement(
    tui: tuple[Tui, io.StringIO],
) -> None:
    app, buffer = tui  # the repl fixture has no engagement loaded
    app.dispatch("/show status")
    out = _out(buffer)
    assert "engagement " in out
    assert "scope an engagement" in out  # a pending next step


def test_show_tools_scoped_is_empty_in_agent_only_mode(
    tui: tuple[Tui, io.StringIO], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, buffer = tui
    monkeypatch.setattr(
        app.core.doctor, "tools", list
    )  # probe not needed; filter short-circuits on no engagement
    app.dispatch("/show tools scoped")
    assert "no scoped tools" in _out(buffer)
