"""L1: the interactive config-request confirm flow (front-end-agnostic)."""

from __future__ import annotations

from skuggi.configflow import Choose, run_config_request


class _Recorder:
    """Captures applied edits and returns the status string apply() must yield."""

    def __init__(self) -> None:
        self.applied: list[tuple[str, str]] = []

    def apply(self, key: str, value: str) -> str:
        self.applied.append((key, value))
        return f"{key} = {value}"


def _choose(answer: str | None) -> Choose:
    """A choose() stub that always returns `answer` regardless of the options."""

    def choose(_prompt: str, _options: list[str], _default: str | None) -> str | None:
        return answer

    return choose


def test_applies_each_proposal_on_yes() -> None:
    rec = _Recorder()
    run_config_request(
        "make it faster",
        choose=_choose("yes"),
        notify=lambda _m: None,
        propose=lambda _r: [("retrieve_k", "8"), ("max_tool_rounds", "2")],
        apply=rec.apply,
    )
    assert rec.applied == [("retrieve_k", "8"), ("max_tool_rounds", "2")]


def test_declines_on_no() -> None:
    rec = _Recorder()
    run_config_request(
        "x",
        choose=_choose("no"),
        notify=lambda _m: None,
        propose=lambda _r: [("mode", "blueteam")],
        apply=rec.apply,
    )
    assert rec.applied == []


def test_reports_when_nothing_proposed() -> None:
    notes: list[str] = []
    run_config_request(
        "x",
        choose=_choose("yes"),
        notify=notes.append,
        propose=lambda _r: [],
        apply=_Recorder().apply,
    )
    assert any("no changes" in n for n in notes)


def test_abort_applies_nothing() -> None:
    rec = _Recorder()
    run_config_request(
        "x",
        choose=_choose(None),  # operator aborted the confirm menu
        notify=lambda _m: None,
        propose=lambda _r: [("mode", "blueteam")],
        apply=rec.apply,
    )
    assert rec.applied == []
