"""L3: the shell wrapper's routing and prompt injection.

The PTY event loop needs a real terminal and is exercised by hand; the routing
it delegates to (ShellHarness, build_shell_invocation) is tested here.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from pathlib import Path

import pytest
from rich.console import Console

from skuggi.config import Settings
from skuggi.shell import (
    SHIELD,
    ShellHarness,
    build_shell_invocation,
    is_skuggi_command,
    skuggi_body,
)
from skuggi.tui import Tui
from skuggi.vectorstore import Store
from tests.fakes import CountingFakeEmbeddings, RoleScriptedChatModel


def _tui(tmp_path: Path) -> Tui:
    settings = Settings(
        provider="ollama",
        sqlite_path=tmp_path / "sessions.db",
        faiss_path=tmp_path / "faiss",
        history_path=tmp_path / ".repl_history",
        ledger_path=tmp_path / "ledger.db",
    )
    app = Tui(settings, console=Console(file=io.StringIO(), width=100))
    app.store = Store(settings.faiss_path, CountingFakeEmbeddings())
    app.llm = RoleScriptedChatModel(
        worker_replies=["ok"], critic_replies=["APPROVED: ok"]
    )
    app.tools_list = app._build_tools()
    app.graph = app._build()
    return app


# --- helpers ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("/skuggi scan", True),
        ("/skuggi", True),
        ("  /skuggi x", True),
        ("ls -la", False),
    ],
)
def test_is_skuggi_command(line: str, expected: bool) -> None:
    assert is_skuggi_command(line) is expected


def test_skuggi_body_strips_the_prefix() -> None:
    assert skuggi_body("/skuggi scan the host") == "scan the host"


# --- prompt injection -------------------------------------------------------


def test_zsh_invocation_injects_via_zdotdir(tmp_path: Path) -> None:
    argv, env = build_shell_invocation("/bin/zsh", tmp_path, home=Path("/home/u"))
    assert argv == ["/bin/zsh"]
    assert env["ZDOTDIR"] == str(tmp_path)
    zshrc = (tmp_path / ".zshrc").read_text(encoding="utf-8")
    assert SHIELD in zshrc
    assert "/home/u/.zshrc" in zshrc


def test_bash_invocation_uses_an_rcfile(tmp_path: Path) -> None:
    argv, _ = build_shell_invocation("/bin/bash", tmp_path, home=Path("/home/u"))
    assert "--rcfile" in argv
    rcfile = Path(argv[argv.index("--rcfile") + 1])
    assert SHIELD in rcfile.read_text(encoding="utf-8")


def test_unknown_shell_degrades(tmp_path: Path) -> None:
    argv, env = build_shell_invocation("/usr/bin/fish", tmp_path, home=Path("/home/u"))
    assert argv == ["/usr/bin/fish"]
    assert env == {"SKUGGI_ACTIVE": "1"}


# --- routing ----------------------------------------------------------------


def test_passthrough_command_is_forwarded_and_logged(tmp_path: Path) -> None:
    app = _tui(tmp_path)
    harness = ShellHarness(app)
    assert harness.handle_line("ls -la") == "ls -la"
    rows = app.ledger.commands_for(app.session_id)
    assert [r.status for r in rows] == ["passthrough"]
    assert rows[0].binary == "ls"


def test_skuggi_slash_routes_to_dispatch(
    tmp_path: Path, pentest_configs: Callable[..., Path]
) -> None:
    pentest_configs()
    app = _tui(tmp_path)
    assert app.engagement is not None
    assert ShellHarness(app).handle_line("/skuggi /engagement") is None
    assert "test-eng" in app.console.file.getvalue()  # type: ignore[attr-defined]


def test_skuggi_input_routes_to_the_agent(tmp_path: Path) -> None:
    app = _tui(tmp_path)
    # A skuggi turn is handled internally; nothing is forwarded to the shell.
    assert ShellHarness(app).handle_line("/skuggi what is exposed?") is None
    # The passthrough log stays empty because the line never reached the shell.
    assert app.ledger.commands_for(app.session_id) == []


def test_blank_line_is_forwarded(tmp_path: Path) -> None:
    app = _tui(tmp_path)
    assert ShellHarness(app).handle_line("") == ""
