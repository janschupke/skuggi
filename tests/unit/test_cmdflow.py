"""L1: the guided cheatsheet editor -- answer shaping, retry, abort."""

from __future__ import annotations

from collections.abc import Callable

from skuggi.config.configs import ConfigError
from skuggi.frontend.cmdflow import collect_alias, run_cmd_editor
from skuggi.frontend.commands import CommandAlias

_VALID = CommandAlias(name="nmap-host", argv=("nmap", "-sV", "-sC"))

# The editor asks eight questions: name, argv, description, tool, label,
# output_dir, output_flag, output.
_BLANKS = [""] * 8


def _answers(*items: str | None) -> Callable[[str], str | None]:
    it = iter(items)
    return lambda _prompt: next(it, None)


def test_collect_alias_shapes_the_command_template() -> None:
    raw = collect_alias(
        _answers("nmap-host", "nmap -sV -sC", "scan a host", "", "", "", "", "")
    )
    assert raw is not None
    assert raw["name"] == "nmap-host"
    assert raw["argv"] == ["nmap", "-sV", "-sC"]  # shlex-split into a list
    assert raw["description"] == "scan a host"
    CommandAlias.model_validate(raw)  # the shaped dict validates


def test_collect_alias_aborts_when_ask_returns_none() -> None:
    assert collect_alias(_answers("nmap-host", None)) is None


def test_collect_alias_edit_keeps_existing_on_blank() -> None:
    raw = collect_alias(_answers(*_BLANKS), existing=_VALID)
    assert raw is not None
    assert raw["name"] == "nmap-host"  # blank kept the existing value
    assert raw["argv"] == ["nmap", "-sV", "-sC"]


def test_run_cmd_editor_applies_and_reports_saved() -> None:
    notes: list[str] = []
    alias = run_cmd_editor(
        _answers("nmap-host", "nmap -sV -sC", *_BLANKS[2:]),
        lambda _raw: _VALID,
        notes.append,
    )
    assert alias is _VALID
    assert any("saved" in n for n in notes)


def test_run_cmd_editor_retries_on_rejection() -> None:
    calls = {"n": 0}

    def apply(_raw: dict[str, object]) -> CommandAlias:
        calls["n"] += 1
        if calls["n"] == 1:
            msg = "duplicate name"
            raise ConfigError(msg)
        return _VALID

    notes: list[str] = []
    ask = _answers(*(["x"] * 20))  # two full passes of answers
    alias = run_cmd_editor(ask, apply, notes.append)
    assert alias is _VALID
    assert calls["n"] == 2
    assert any("rejected" in n for n in notes)


def test_run_cmd_editor_cancelled_on_abort() -> None:
    notes: list[str] = []
    alias = run_cmd_editor(
        _answers("nmap-host", None), lambda _raw: _VALID, notes.append
    )
    assert alias is None
    assert any("cancelled" in n for n in notes)
