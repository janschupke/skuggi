"""L3: the wrapped-shell daemon's request routing (no real socket)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from skuggi import registry as registry_mod
from skuggi.config import Settings
from skuggi.core import AgentCore
from skuggi.daemon import Daemon
from skuggi.registry import ToolSpec, ToolStatus
from skuggi.vectorstore import Store
from tests.fakes import CountingFakeEmbeddings, RoleScriptedChatModel


def _core(tmp_path: Path) -> AgentCore:
    settings = Settings(
        provider="ollama",
        sqlite_path=tmp_path / "sessions.db",
        faiss_path=tmp_path / "faiss",
        history_path=tmp_path / ".repl_history",
        engagement="test-eng",
    )
    core = AgentCore(settings)
    core.store = Store(settings.faiss_path, CountingFakeEmbeddings())
    core.llm = RoleScriptedChatModel(
        worker_replies=["the answer"], critic_replies=["APPROVED: ok"]
    )
    core.tools_list = core.build_tools()
    core.graph = core._build()
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
    out = _chunks(daemon, {"op": "input", "text": "what is exposed?"})
    assert "the answer" in out
    assert "(planner)" in out


def test_slash_findings_lists_findings(daemon: Daemon) -> None:
    assert "no findings" in _chunks(daemon, {"op": "input", "text": "/findings"})


def test_slash_report_writes(daemon: Daemon) -> None:
    assert "report written" in _chunks(daemon, {"op": "input", "text": "/report"})


def test_slash_engagement_shows_scope(daemon: Daemon) -> None:
    assert "test-eng" in _chunks(daemon, {"op": "input", "text": "/engagement"})


def test_slash_doctor(daemon: Daemon, monkeypatch: pytest.MonkeyPatch) -> None:
    spec = ToolSpec(name="nmap", binary="nmap", method="scan")
    monkeypatch.setattr(
        registry_mod,
        "probe",
        lambda *_a, **_k: [
            ToolStatus(spec, found=True, path=Path("/x"), version="7", source="host")
        ],
    )
    monkeypatch.setattr(registry_mod, "probe_runtimes", lambda *_a, **_k: [])
    monkeypatch.setattr(registry_mod, "probe_net_tools", lambda *_a, **_k: [])
    assert "nmap" in _chunks(daemon, {"op": "input", "text": "/doctor"})


def test_slash_mode_switches_and_reports_error(daemon: Daemon) -> None:
    assert "blueteam" in _chunks(daemon, {"op": "input", "text": "/mode blueteam"})
    assert "unknown mode" in _chunks(daemon, {"op": "input", "text": "/mode nope"})


def test_slash_autonomous_toggles(daemon: Daemon) -> None:
    assert "ON" in _chunks(daemon, {"op": "input", "text": "/autonomous on"})
    assert "off" in _chunks(daemon, {"op": "input", "text": "/autonomous off"})


def test_slash_help_and_unknown(daemon: Daemon) -> None:
    assert "/skuggi" in _chunks(daemon, {"op": "input", "text": "/help"})
    assert "unknown control" in _chunks(daemon, {"op": "input", "text": "/bogus"})
