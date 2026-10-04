"""L1: the interactive, gated memory-capture flow (front-end-agnostic)."""

from __future__ import annotations

from skuggi.agent.grants import SessionGrants
from skuggi.frontend.confirm import SESSION, Choose
from skuggi.frontend.memoryflow import announce_capture, run_memory_capture

_CANDIDATES = ["Prefer ffuf over gobuster"]


def _choose(answer: str | None) -> Choose:
    def choose(_p: str, _o: list[str], _d: str | None) -> str | None:
        return answer

    return choose


class _Apply:
    """A recording ``apply`` stub returning the summary line."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, candidates: list[str]) -> str:
        self.calls.append(candidates)
        return "remembered: [1] Prefer ffuf over gobuster"


def test_no_candidates_is_a_silent_noop() -> None:
    notes: list[str] = []
    app = _Apply()
    run_memory_capture(
        [],
        choose=_choose("approve"),
        notify=notes.append,
        apply=app,
        grants=SessionGrants(),
        interactive=True,
    )
    assert app.calls == []
    assert notes == []


def test_confirming_applies_and_shows_the_summary() -> None:
    notes: list[str] = []
    app = _Apply()
    run_memory_capture(
        _CANDIDATES,
        choose=_choose("approve"),
        notify=notes.append,
        apply=app,
        grants=SessionGrants(),
        interactive=True,
    )
    assert app.calls == [_CANDIDATES]
    assert any("suggests remembering" in n for n in notes)
    assert any("remembered:" in n for n in notes)


def test_declining_does_not_write() -> None:
    notes: list[str] = []
    app = _Apply()
    run_memory_capture(
        _CANDIDATES,
        choose=_choose("deny"),
        notify=notes.append,
        apply=app,
        grants=SessionGrants(),
        interactive=True,
    )
    assert app.calls == []
    assert any("not remembered" in n for n in notes)


def test_session_grant_is_recorded() -> None:
    grants = SessionGrants()
    run_memory_capture(
        _CANDIDATES,
        choose=_choose(SESSION),
        notify=lambda _m: None,
        apply=_Apply(),
        grants=grants,
        interactive=True,
    )
    assert grants.granted("memory")


def test_announce_capture_is_empty_without_candidates() -> None:
    assert announce_capture([], hint="/skuggi add memory") == []


def test_announce_capture_lists_candidates_and_the_hint() -> None:
    lines = announce_capture(_CANDIDATES, hint="/skuggi add memory")
    joined = "".join(lines)
    assert all(line.endswith("\n") for line in lines)
    assert "suggests remembering" in joined
    assert "Prefer ffuf over gobuster" in joined
    assert "not written" in joined
    assert "/skuggi add memory" in joined


def test_non_interactive_announces_but_never_writes() -> None:
    notes: list[str] = []
    app = _Apply()
    run_memory_capture(
        _CANDIDATES,
        choose=_choose("approve"),  # must never be consulted
        notify=notes.append,
        apply=app,
        grants=SessionGrants(),
        interactive=False,
    )
    assert app.calls == [], "a one-shot context must not write memory"
    assert any("suggests remembering" in n for n in notes)
    assert any("not written" in n for n in notes)
