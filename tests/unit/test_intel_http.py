"""L1: the shared default HTTP fetch (UA, retry/backoff, blocked-vs-empty)."""

from __future__ import annotations

import time
from types import SimpleNamespace

import httpx
import pytest

from skuggi.intel.http import HttpRequest, default_fetch


def test_default_fetch_sends_a_user_agent_and_returns_the_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_request(_method: str, _url: str, **kwargs: object) -> SimpleNamespace:
        captured["headers"] = kwargs.get("headers")
        return SimpleNamespace(status_code=200, text="body")

    monkeypatch.setattr(httpx, "request", fake_request)
    assert default_fetch(HttpRequest(url="http://x")) == "body"
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert "skuggi-intel" in headers["User-Agent"]


def test_default_fetch_returns_none_on_a_blocked_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        httpx, "request", lambda *_a, **_k: SimpleNamespace(status_code=403, text="no")
    )
    assert default_fetch(HttpRequest(url="http://x")) is None


def test_default_fetch_retries_a_transient_failure_then_gives_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def fake(*_a: object, **_k: object) -> SimpleNamespace:
        calls.append(1)
        return SimpleNamespace(status_code=503, text="")

    monkeypatch.setattr(httpx, "request", fake)
    monkeypatch.setattr(time, "sleep", lambda *_a: None)
    assert default_fetch(HttpRequest(url="http://x")) is None
    assert len(calls) == 3  # initial attempt + 2 retries


def test_default_fetch_returns_none_on_a_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: object, **_k: object) -> SimpleNamespace:
        msg = "down"
        raise httpx.ConnectError(msg)

    monkeypatch.setattr(httpx, "request", boom)
    monkeypatch.setattr(time, "sleep", lambda *_a: None)
    assert default_fetch(HttpRequest(url="http://x")) is None
