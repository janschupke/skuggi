"""L1: first-party PyPI lookups for install research (fetch injected, no network)."""

from __future__ import annotations

import json

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


# --- _default_fetch: the JSON-parse adaptation over the shared intel fetcher ---


def _patch_fetch(monkeypatch: pytest.MonkeyPatch, body: str | None) -> None:
    # websearch now routes through intel.http.default_fetch (text body / None);
    # patch that seam rather than httpx directly.
    monkeypatch.setattr(websearch, "default_fetch", lambda _req: body)


def test_default_fetch_parses_a_json_body(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(monkeypatch, json.dumps({"info": {}}))
    assert websearch._default_fetch("https://pypi.org/pypi/x/json") == {"info": {}}


def test_default_fetch_returns_none_when_the_fetch_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A network error / 404 surfaces from the shared fetcher as None.
    _patch_fetch(monkeypatch, None)
    assert websearch._default_fetch("https://pypi.org/pypi/x/json") is None


def test_default_fetch_returns_none_on_non_dict_or_bad_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_fetch(monkeypatch, json.dumps(["not", "a", "dict"]))
    assert websearch._default_fetch("https://pypi.org/pypi/x/json") is None
    _patch_fetch(monkeypatch, "not json{")
    assert websearch._default_fetch("https://pypi.org/pypi/x/json") is None
