"""L3: the headless AgentCore, offline.

The core is exercised without any front-end: turn events, session controls,
engagement data. Only the LLM and embeddings are faked.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from skuggi import registry as registry_mod
from skuggi.config import Settings
from skuggi.core import AgentCore
from skuggi.registry import ToolSpec, ToolStatus
from skuggi.vectorstore import Store
from tests.fakes import CountingFakeEmbeddings, RoleScriptedChatModel


def _build_core(tmp_path: Path, *, engagement: str | None = "test-eng") -> AgentCore:
    settings = Settings(
        provider="ollama",
        sqlite_path=tmp_path / "sessions.db",
        faiss_path=tmp_path / "faiss",
        history_path=tmp_path / ".repl_history",
        engagement=engagement,
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
    monkeypatch.setattr(registry_mod, "probe", lambda *_a, **_k: [status])
    assert core.doctor_statuses() == [status]
    assert core.install_tool("ghost-tool") is None
    monkeypatch.setattr(registry_mod, "install_tool", lambda *_a, **_k: status)
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
