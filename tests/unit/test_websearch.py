"""L1: first-party PyPI lookups for install research (fetch injected, no network)."""

from __future__ import annotations

import httpx
import pytest

from skuggi.tooling import websearch
from skuggi.tooling.websearch import Fetch, pypi_candidates


def _fetch_from(known: dict[str, dict[str, object]]) -> Fetch:
    """A fake fetch: returns canned JSON for a known URL, else None (a 404)."""

    def fetch(url: str) -> dict[str, object] | None:
        return known.get(url)

    return fetch


def test_an_existing_package_becomes_a_pip_hit() -> None:
    url = "https://pypi.org/pypi/enum4linux-ng/json"
    fetch = _fetch_from(
        {url: {"info": {"name": "enum4linux-ng", "summary": "AD enum"}}}
    )
    hits = pypi_candidates("enum4linux-ng", fetch=fetch)
    assert len(hits) == 1
    assert hits[0].installer == "pip"
    assert hits[0].name == "enum4linux-ng"
    assert hits[0].summary == "AD enum"


def test_the_underscore_variant_is_tried() -> None:
    url = "https://pypi.org/pypi/enum4linux_ng/json"
    fetch = _fetch_from({url: {"info": {"name": "enum4linux_ng"}}})
    hits = pypi_candidates("enum4linux-ng", fetch=fetch)
    assert [h.name for h in hits] == ["enum4linux_ng"]


def test_a_missing_package_yields_no_hits() -> None:
    hits = pypi_candidates("definitely-not-real", fetch=_fetch_from({}))
    assert hits == []


def test_a_network_failure_degrades_to_no_hits() -> None:
    def boom(_url: str) -> dict[str, object] | None:
        return None  # _default_fetch returns None on any error; emulate that

    assert pypi_candidates("requests", fetch=boom) == []


def test_an_unsafe_query_is_never_looked_up() -> None:
    called: list[str] = []

    def record(url: str) -> dict[str, object] | None:
        called.append(url)
        return None

    for bad in ("-x", "a b", "; rm", "$(id)", ""):
        assert pypi_candidates(bad, fetch=record) == []
    assert called == []


def test_the_same_canonical_name_is_not_duplicated() -> None:
    # Both the hyphen and underscore spellings resolve to the same canonical name;
    # it must appear once.
    data: dict[str, object] = {"info": {"name": "enum4linux-ng"}}
    fetch = _fetch_from(
        {
            "https://pypi.org/pypi/enum4linux-ng/json": data,
            "https://pypi.org/pypi/enum4linux_ng/json": data,
        }
    )
    assert len(pypi_candidates("enum4linux-ng", fetch=fetch)) == 1


# --- _default_fetch: the real httpx path, with httpx.get monkeypatched ---------


class _Resp:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> object:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def test_default_fetch_returns_json_on_200(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "get", lambda *_a, **_k: _Resp(200, {"info": {}}))
    assert websearch._default_fetch("https://pypi.org/pypi/x/json") == {"info": {}}


def test_default_fetch_returns_none_on_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "get", lambda *_a, **_k: _Resp(404, None))
    assert websearch._default_fetch("https://pypi.org/pypi/x/json") is None


def test_default_fetch_returns_none_on_a_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: object, **_k: object) -> object:
        msg = "down"
        raise httpx.ConnectError(msg)

    monkeypatch.setattr(httpx, "get", boom)
    assert websearch._default_fetch("https://pypi.org/pypi/x/json") is None


def test_default_fetch_returns_none_on_non_dict_or_bad_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        httpx, "get", lambda *_a, **_k: _Resp(200, ["not", "a", "dict"])
    )
    assert websearch._default_fetch("https://pypi.org/pypi/x/json") is None
    monkeypatch.setattr(httpx, "get", lambda *_a, **_k: _Resp(200, ValueError("bad")))
    assert websearch._default_fetch("https://pypi.org/pypi/x/json") is None
