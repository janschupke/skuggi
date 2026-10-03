"""L1: the per-session grant broker and the shared gated-write confirm step."""

from __future__ import annotations

from skuggi.agent.grants import SessionGrants
from skuggi.frontend.confirm import SESSION, Choose, confirm_write


def _choose(answer: str | None) -> Choose:
    def choose(_prompt: str, _options: list[str], _default: str | None) -> str | None:
        return answer

    return choose


def test_grants_start_empty_and_record() -> None:
    grants = SessionGrants()
    assert not grants.granted("install")
    assert grants.active() == ()
    grants.grant("install")
    assert grants.granted("install")
    assert grants.active() == ("install",)


def test_active_is_sorted() -> None:
    grants = SessionGrants()
    grants.grant("scope-edit")
    grants.grant("cmd-edit")
    assert grants.active() == ("cmd-edit", "scope-edit")


def test_revoke_all_clears_and_counts() -> None:
    grants = SessionGrants()
    grants.grant("install")
    grants.grant("config")
    assert grants.revoke_all() == 2
    assert grants.active() == ()
    assert grants.revoke_all() == 0


def test_confirm_yes_applies_without_granting() -> None:
    grants = SessionGrants()
    assert confirm_write(
        "install", grants=grants, choose=_choose("yes"), notify=lambda _m: None
    )
    assert not grants.granted("install")


def test_confirm_no_and_abort_decline() -> None:
    grants = SessionGrants()
    assert not confirm_write(
        "install", grants=grants, choose=_choose("no"), notify=lambda _m: None
    )
    assert not confirm_write(
        "install", grants=grants, choose=_choose(None), notify=lambda _m: None
    )


def test_confirm_session_option_grants() -> None:
    grants = SessionGrants()
    assert confirm_write(
        "install", grants=grants, choose=_choose(SESSION), notify=lambda _m: None
    )
    assert grants.granted("install")


def test_confirm_auto_applies_under_a_grant_and_announces() -> None:
    grants = SessionGrants()
    grants.grant("install")
    notes: list[str] = []
    calls: list[int] = []

    def choose(*_a: object) -> str | None:
        calls.append(1)
        return "no"

    assert confirm_write("install", grants=grants, choose=choose, notify=notes.append)
    assert calls == []  # a standing grant must not prompt
    assert any("session grant for install" in n for n in notes)  # never silent
