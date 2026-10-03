"""L1: the Claude CLI chat model -- message flattening and subprocess handling."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from skuggi.providers import claude_cli_chat
from skuggi.providers.claude_cli_chat import (
    ClaudeCliChatModel,
    ClaudeCliError,
    _split_messages,
    build_claude_cli_chat_model,
)


def _fake_run(
    captured: list[list[str]],
    stdout: str = "",
    *,
    returncode: int = 0,
    stderr: str = "",
) -> Callable[..., SimpleNamespace]:
    def run(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        captured.append(argv)
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    return run


def test_split_messages_separates_system_from_conversation() -> None:
    system, convo = _split_messages(
        [
            SystemMessage(content="be terse"),
            HumanMessage(content="hello"),
            AIMessage(content="hi"),
            HumanMessage(content="again"),
        ]
    )
    assert system == "be terse"
    assert convo == "User: hello\n\nAssistant: hi\n\nUser: again"


def test_generate_parses_result(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        subprocess, "run", _fake_run(calls, json.dumps({"result": "the answer"}))
    )
    model = ClaudeCliChatModel(model="haiku", binary="claude")
    result = model.invoke([HumanMessage(content="q")])
    assert result.content == "the answer"
    assert calls[0][:2] == ["claude", "-p"]
    assert "--model" in calls[0]
    assert "haiku" in calls[0]


def test_generate_passes_system_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        subprocess, "run", _fake_run(calls, json.dumps({"result": "ok"}))
    )
    model = ClaudeCliChatModel(model="sonnet", binary="claude")
    model.invoke([SystemMessage(content="rules"), HumanMessage(content="q")])
    assert "--append-system-prompt" in calls[0]
    assert "rules" in calls[0]


def test_generate_raises_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess, "run", _fake_run([], "", returncode=1, stderr="not logged in")
    )
    model = ClaudeCliChatModel(model="haiku", binary="claude")
    with pytest.raises(ClaudeCliError, match="not logged in"):
        model.invoke([HumanMessage(content="q")])


def test_generate_raises_on_non_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", _fake_run([], "not json at all"))
    model = ClaudeCliChatModel(model="haiku", binary="claude")
    with pytest.raises(ClaudeCliError, match="not JSON"):
        model.invoke([HumanMessage(content="q")])


def test_generate_raises_when_result_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess, "run", _fake_run([], json.dumps({"other": "field"}))
    )
    model = ClaudeCliChatModel(model="haiku", binary="claude")
    with pytest.raises(ClaudeCliError, match="no 'result'"):
        model.invoke([HumanMessage(content="q")])


def test_is_available_reflects_which(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _b: "/usr/bin/claude")
    assert claude_cli_chat.is_available() is True
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    assert claude_cli_chat.is_available() is False


def test_build_raises_when_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    with pytest.raises(ClaudeCliError, match="not installed"):
        build_claude_cli_chat_model("haiku")


def test_build_uses_resolved_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _b: "/opt/claude")
    model = build_claude_cli_chat_model("opus")
    assert model.binary == "/opt/claude"
    assert model.model == "opus"
