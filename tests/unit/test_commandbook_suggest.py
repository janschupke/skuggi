"""L1: CommandBook proposal helpers -- build/preview/apply a suggested alias."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from skuggi.agent.commandbook import CommandBook, _proposal_raw
from skuggi.agent.core import AgentCore
from skuggi.agent.protocol import CmdProposal
from skuggi.config.configs import ConfigError
from skuggi.tooling.commands import CommandRegistry
from skuggi.tooling.registry import ToolRegistry, ToolSpec

_TOOLS = ToolRegistry(tools=(ToolSpec(name="nmap", binary="nmap", method="scan"),))


def _book(tmp_path: Path) -> CommandBook:
    core = SimpleNamespace(
        commands=CommandRegistry(),
        registry=_TOOLS,
        settings=SimpleNamespace(commands_path=tmp_path / "commands.json"),
    )
    return CommandBook(cast("AgentCore", core))


def test_proposal_raw_drops_blank_optionals() -> None:
    raw = _proposal_raw(CmdProposal(name="x", argv=("nmap", "-F")))
    assert raw == {"name": "x", "argv": ("nmap", "-F")}
    raw2 = _proposal_raw(
        CmdProposal(name="x", argv=("nmap",), description="d", tool="nmap", label="l")
    )
    assert raw2["description"] == "d"
    assert raw2["tool"] == "nmap"
    assert raw2["label"] == "l"


def test_preview_renders_the_command(tmp_path: Path) -> None:
    book = _book(tmp_path)
    rendered = book.preview_proposal(CmdProposal(name="nmap-fast", argv=("nmap", "-F")))
    assert rendered.startswith("nmap -F")
    assert "${target}" in rendered  # the tool requires a target


def test_preview_rejects_an_invalid_alias(tmp_path: Path) -> None:
    book = _book(tmp_path)
    with pytest.raises(ConfigError):
        # a label with a shell metacharacter is rejected by CommandAlias
        book.preview_proposal(
            CmdProposal(name="bad", argv=("nmap",), label="x; rm -rf /")
        )


def test_apply_adds_then_updates(tmp_path: Path) -> None:
    book = _book(tmp_path)
    added = book.apply_proposal(CmdProposal(name="nmap-fast", argv=("nmap", "-F")))
    assert added == "cmd added: nmap-fast"
    assert book._core.commands.alias_for("nmap-fast") is not None
    # same name again -> update path
    updated = book.apply_proposal(CmdProposal(name="nmap-fast", argv=("nmap", "-sV")))
    assert updated == "cmd updated: nmap-fast"
    alias = book._core.commands.alias_for("nmap-fast")
    assert alias is not None
    assert alias.argv == ("nmap", "-sV")
