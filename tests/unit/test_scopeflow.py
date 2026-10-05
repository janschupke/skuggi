"""L1: the interactive, gated scope-edit confirm flow (front-end-agnostic)."""

from __future__ import annotations

from skuggi.agent.grants import SessionGrants
from skuggi.agent.protocol import ScopeEdit
from skuggi.frontend.confirm import Choose
from skuggi.frontend.scopeflow import run_scope_request

_EDIT = ScopeEdit(field="allowed_tools", action="add", value="nikto")
_ROWS = [("allowed_tools", "nmap", "nmap, nikto")]


def _choose(answer: str | None) -> Choose:
    def choose(_p: str, _o: list[str], _d: str | None) -> str | None:
        return answer

    return choose


class _Apply:
    """A recording ``apply`` stub returning the summary line."""

    def __init__(self) -> None:
        self.calls: list[list[ScopeEdit]] = []

    def __call__(self, edits: list[ScopeEdit]) -> str:
        self.calls.append(edits)
        return "applied"


def test_nothing_proposed_is_reported() -> None:
    notes: list[str] = []
    app = _Apply()
    run_scope_request(
        "x",
        choose=_choose("approve"),
        notify=notes.append,
        propose=lambda _r: [],
        preview=lambda _e: _ROWS,
        apply=app,
        grants=SessionGrants(),
    )
    assert app.calls == []
    assert any("no changes" in n for n in notes)


def test_invalid_edit_is_reported_not_applied() -> None:
    notes: list[str] = []
    app = _Apply()

    def boom(_e: list[ScopeEdit]) -> list[tuple[str, str, str]]:
        msg = "bad CIDR"
        raise ValueError(msg)

    run_scope_request(
        "x",
        choose=_choose("approve"),
        notify=notes.append,
        propose=lambda _r: [_EDIT],
        preview=boom,
        apply=app,
        grants=SessionGrants(),
    )
    assert app.calls == []
    assert any("invalid edit" in n for n in notes)


def test_declining_does_not_apply() -> None:
    app = _Apply()
    run_scope_request(
        "x",
        choose=_choose("deny"),
        notify=lambda _m: None,
        propose=lambda _r: [_EDIT],
        preview=lambda _e: _ROWS,
        apply=app,
        grants=SessionGrants(),
    )
    assert app.calls == []


def test_confirming_applies_and_shows_the_diff() -> None:
    notes: list[str] = []
    app = _Apply()
    run_scope_request(
        "x",
        choose=_choose("approve"),
        notify=notes.append,
        propose=lambda _r: [_EDIT],
        preview=lambda _e: _ROWS,
        apply=app,
        grants=SessionGrants(),
    )
    assert app.calls == [[_EDIT]]
    assert any("allowed_tools: nmap -> nmap, nikto" in n for n in notes)


def test_scope_edit_does_not_record_a_session_grant() -> None:
    # Scope edits are authorization changes: approving applies the edit but never
    # records a standing grant, so the next edit is confirmed again (audit C4).
    grants = SessionGrants()
    app = _Apply()
    run_scope_request(
        "x",
        choose=_choose("approve"),
        notify=lambda _m: None,
        propose=lambda _r: [_EDIT],
        preview=lambda _e: _ROWS,
        apply=app,
        grants=grants,
    )
    assert app.calls == [[_EDIT]]
    assert not grants.granted("scope-edit")
