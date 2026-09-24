"""L3: the REPL end to end, offline, through its real entry points.

The console is injected so rendered output is assertable without a terminal.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from rich.console import Console

from skuggi.config import Settings
from skuggi.tools import build_tools
from skuggi.tui import HELP, Tui
from skuggi.vectorstore import Store
from tests.fakes import (
    CountingFakeEmbeddings,
    FakePromptSession,
    RoleScriptedChatModel,
)


@pytest.fixture
def tui(tmp_path: Path) -> tuple[Tui, io.StringIO]:
    """A REPL wired to a scripted model, with no network anywhere."""
    buffer = io.StringIO()
    settings = Settings(
        provider="ollama",  # constructs without credentials or network
        sqlite_path=tmp_path / "sessions.db",
        faiss_path=tmp_path / "faiss",
        history_path=tmp_path / ".repl_history",
    )
    app = Tui(settings, console=Console(file=buffer, width=100))
    # Swap in offline doubles: the real ollama embeddings would try to reach
    # localhost:11434 the moment anything is ingested.
    app.core.store = Store(settings.faiss_path, CountingFakeEmbeddings())
    app.core.tools_list = build_tools(app.core.store, root=tmp_path)
    app.core.llm = RoleScriptedChatModel(
        worker_replies=["the answer"], critic_replies=["APPROVED: ok"]
    )
    app.core.graph = app.core._build()
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
    documented = {row[0].split()[0] for row in HELP} | {"/exit"}
    assert documented == set(app._commands)


def test_provider_switch_rebuilds_the_graph(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    before = app.graph
    app.dispatch("/provider anthropic")
    assert "provider error" in _out(buffer), "no ANTHROPIC_API_KEY in this environment"
    assert app.graph is before, "a failed switch must keep the working graph"


def test_invalid_provider_is_rejected(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    before = app.graph
    app.dispatch("/provider banana")
    assert "unknown provider" in _out(buffer)
    assert app.graph is before


def test_model_requires_an_argument(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.dispatch("/model")
    assert "usage:" in _out(buffer)


def test_thread_new_changes_the_id(tui: tuple[Tui, io.StringIO]) -> None:
    app, _ = tui
    first = app.thread_id
    app.dispatch("/thread new")
    assert app.thread_id != first


def test_bare_thread_is_also_new(tui: tuple[Tui, io.StringIO]) -> None:
    app, _ = tui
    first = app.thread_id
    app.dispatch("/thread")
    assert app.thread_id != first


def test_thread_list_is_empty_before_any_turn(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.dispatch("/thread list")
    assert "(no threads)" in _out(buffer)


def test_thread_switch_sets_the_id(tui: tuple[Tui, io.StringIO]) -> None:
    app, _ = tui
    app.dispatch("/thread abc123")
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


def test_help_renders_every_row(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.dispatch("/help")
    assert "/trace" in _out(buffer)


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

    app.dispatch("/history")
    output = _out(buffer)

    assert "first question" in output
    assert "the answer" in output


def test_trace_is_empty_without_tool_use(tui: tuple[Tui, io.StringIO]) -> None:
    app, buffer = tui
    app.turn("q")
    buffer.truncate(0)
    buffer.seek(0)
    app.dispatch("/trace")
    assert "no tool activity" in _out(buffer)


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
    app.session = FakePromptSession(["", "/thread new", "/quit"])  # type: ignore[assignment]

    app.run()

    assert "bye." in _out(buffer)
