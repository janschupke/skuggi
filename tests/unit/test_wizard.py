"""L1: the engagement Q&A wizard -- answer shaping, retry, abort."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from skuggi.config.configs import ConfigError
from skuggi.engagement.engagement import EngagementConfig
from skuggi.frontend.wizard import collect_scope, run_wizard

_VALID = EngagementConfig(
    name="x",
    timezone="UTC",
    authorized_start=datetime(2026, 1, 1, tzinfo=UTC),
    authorized_end=datetime(2026, 12, 31, tzinfo=UTC),
)


def _answers(*items: str | None) -> Callable[[str], str | None]:
    it = iter(items)
    return lambda _prompt: next(it, None)


def test_collect_scope_shapes_answers_into_valid_scope() -> None:
    raw = collect_scope(
        _answers(
            "acme",
            "UTC",
            "2026-01-01T00:00:00+00:00",
            "2026-12-31T23:59:59+00:00",
            "09:00-17:00, 20:00-22:00",
            "192.0.2.0/24, 198.51.100.0/24",
            "scanme.example.com",
            "nmap, curl",
            "recon, scan",
            "yes",
        )
    )
    assert raw is not None
    assert raw["name"] == "acme"
    assert raw["daily_windows"] == [
        {"start": "09:00", "end": "17:00"},
        {"start": "20:00", "end": "22:00"},
    ]
    assert raw["target_networks"] == ["192.0.2.0/24", "198.51.100.0/24"]
    assert raw["allowed_tools"] == ["nmap", "curl"]
    assert raw["autonomous"] is True
    EngagementConfig.model_validate(raw)  # the shaped dict validates


def test_collect_scope_blank_timezone_seeds_utc() -> None:
    raw = collect_scope(
        _answers(
            "acme",
            "",
            "2026-01-01T00:00:00+00:00",
            "2026-12-31T00:00:00+00:00",
            "",
            "",
            "",
            "",
            "",
            "",
        )
    )
    assert raw is not None
    assert raw["timezone"] == "UTC"


def test_collect_scope_aborts_when_ask_returns_none() -> None:
    assert collect_scope(_answers("acme", None)) is None


def test_collect_scope_edit_keeps_existing_on_blank() -> None:
    raw = collect_scope(
        _answers("", "", "", "", "", "", "", "", "", ""), existing=_VALID
    )
    assert raw is not None
    assert raw["name"] == "x"  # blank kept the existing value


def test_run_wizard_applies_and_reports_loaded() -> None:
    notes: list[str] = []
    eng = run_wizard(
        _answers("a", "b", "c", "d", "e", "f", "g", "h", "i", "j"),
        lambda _raw: _VALID,
        notes.append,
    )
    assert eng is _VALID
    assert any("loaded" in n for n in notes)


def test_run_wizard_retries_on_rejection() -> None:
    calls = {"n": 0}

    def apply(_raw: dict[str, object]) -> EngagementConfig:
        calls["n"] += 1
        if calls["n"] == 1:
            msg = "bad scope"
            raise ConfigError(msg)
        return _VALID

    notes: list[str] = []
    ask = _answers(*(["x"] * 20))  # two full passes
    eng = run_wizard(ask, apply, notes.append)
    assert eng is _VALID
    assert calls["n"] == 2
    assert any("rejected" in n for n in notes)


def test_run_wizard_cancelled_on_abort() -> None:
    notes: list[str] = []
    eng = run_wizard(_answers("a", None), lambda _raw: _VALID, notes.append)
    assert eng is None
    assert any("cancelled" in n for n in notes)
