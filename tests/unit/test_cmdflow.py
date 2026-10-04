"""L1: the guided cheatsheet editor -- answer shaping, retry, abort."""

from __future__ import annotations

from collections.abc import Callable

from skuggi.config.configs import ConfigError
from skuggi.frontend.cmdflow import collect_alias, run_cmd_editor
from skuggi.tooling.commands import CommandAlias

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


# --- cmd suggest (LLM-proposed alias, gated confirm) ------------------------

from skuggi.agent.grants import SessionGrants  # noqa: E402
from skuggi.agent.protocol import CmdProposal  # noqa: E402
from skuggi.frontend.cmdflow import run_cmd_suggest  # noqa: E402
from skuggi.frontend.confirm import SESSION, Choose  # noqa: E402

_PROPOSAL = CmdProposal(name="nmap-fast", argv=("nmap", "-F"))


def _choose_const(answer: str | None) -> Choose:
    return lambda _p, _o, _d: answer


class _Saver:
    def __init__(self) -> None:
        self.saved: list[CmdProposal] = []

    def __call__(self, proposal: CmdProposal) -> str:
        self.saved.append(proposal)
        return f"cmd added: {proposal.name}"


def test_suggest_nothing_proposed() -> None:
    notes: list[str] = []
    save = _Saver()
    run_cmd_suggest(
        "x",
        choose=_choose_const("approve"),
        notify=notes.append,
        propose=lambda _r: CmdProposal(),  # empty name/argv
        preview=lambda _p: "unused",
        apply=save,
        grants=SessionGrants(),
    )
    assert save.saved == []
    assert any("no alias proposed" in n for n in notes)


def test_suggest_invalid_proposal_is_reported() -> None:
    notes: list[str] = []
    save = _Saver()

    def boom(_p: CmdProposal) -> str:
        msg = "bad label"
        raise ConfigError(msg)

    run_cmd_suggest(
        "x",
        choose=_choose_const("approve"),
        notify=notes.append,
        propose=lambda _r: _PROPOSAL,
        preview=boom,
        apply=save,
        grants=SessionGrants(),
    )
    assert save.saved == []
    assert any("invalid proposal" in n for n in notes)


def test_suggest_declined_does_not_save() -> None:
    save = _Saver()
    run_cmd_suggest(
        "x",
        choose=_choose_const("deny"),
        notify=lambda _m: None,
        propose=lambda _r: _PROPOSAL,
        preview=lambda _p: "nmap -F ${target}",
        apply=save,
        grants=SessionGrants(),
    )
    assert save.saved == []


def test_suggest_confirmed_saves_and_previews() -> None:
    notes: list[str] = []
    save = _Saver()
    run_cmd_suggest(
        "x",
        choose=_choose_const("approve"),
        notify=notes.append,
        propose=lambda _r: _PROPOSAL,
        preview=lambda _p: "nmap -F ${target}",
        apply=save,
        grants=SessionGrants(),
    )
    assert save.saved == [_PROPOSAL]
    assert any("nmap -F ${target}" in n for n in notes)


def test_suggest_session_grant_recorded() -> None:
    grants = SessionGrants()
    run_cmd_suggest(
        "x",
        choose=_choose_const(SESSION),
        notify=lambda _m: None,
        propose=lambda _r: _PROPOSAL,
        preview=lambda _p: "nmap -F ${target}",
        apply=_Saver(),
        grants=grants,
    )
    assert grants.granted("cmd-edit")
