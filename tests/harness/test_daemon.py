"""L3: the wrapped-shell daemon's request routing (no real socket)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from skuggi import probe as probe_mod
from skuggi.core import AgentCore
from skuggi.daemon import Daemon
from skuggi.registry import ToolSpec, ToolStatus
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


def test_slash_report_writes(daemon: Daemon) -> None:
    assert "report written" in _chunks(daemon, {"op": "input", "text": "/report"})


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
    assert "usage: model" in _chunks(daemon, {"op": "input", "text": "model"})
    assert "switched to" in _chunks(daemon, {"op": "input", "text": "model qwen3"})


def test_provider_rejects_unknown(daemon: Daemon) -> None:
    assert "unknown" in _chunks(daemon, {"op": "input", "text": "provider banana"})


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
