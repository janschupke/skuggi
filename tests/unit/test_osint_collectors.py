"""L1: the OSINT HTTP collectors -- parsing + availability, all offline.

Every collector takes an injected ``fetch`` (no network, like test_websearch), so
these pin the parse of each source's real response shape and the never-raise
degradation to an empty result, plus the websearch backend selection + key gating.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from skuggi.intel.collectors.base import CollectContext, HttpRequest
from skuggi.intel.collectors.github import GitHubCollector
from skuggi.intel.collectors.websearch import WebSearchCollector
from skuggi.osint.collectors import collector_for, default_collectors
from skuggi.osint.collectors.crtsh import CrtShCollector
from skuggi.osint.collectors.dns import DnsCollector
from skuggi.osint.schema import OsintTask

Responder = Callable[[HttpRequest], str | None]


def _ctx(responder: Responder, **kw: object) -> CollectContext:
    base: dict[str, object] = {"fetch": responder, "clean": lambda s: s}
    base.update(kw)
    return CollectContext(**base)  # type: ignore[arg-type]


def _task(
    source: str, subject: str = "acme.com", objective: str = "footprint"
) -> OsintTask:
    return OsintTask(id="t1", source=source, subject=subject, objective=objective)  # type: ignore[arg-type]


# --- crt.sh ----------------------------------------------------------------


def test_crtsh_parses_and_dedupes_subdomains() -> None:
    body = json.dumps(
        [
            {"name_value": "mail.acme.com\n*.acme.com", "issuer_name": "LE"},
            {"name_value": "mail.acme.com", "issuer_name": "LE"},  # dup
            {"name_value": "evil.com", "issuer_name": "X"},  # out of subject
        ]
    )
    result = CrtShCollector().collect(_task("crtsh"), _ctx(lambda _r: body))
    values = {i.value for i in result.items}
    assert values == {"mail.acme.com", "acme.com"}  # '*.' stripped, evil.com dropped


def test_crtsh_empty_on_no_data() -> None:
    result = CrtShCollector().collect(_task("crtsh"), _ctx(lambda _r: None))
    assert result.items == ()
    assert "no data" in result.note


def test_crtsh_empty_on_bad_json() -> None:
    result = CrtShCollector().collect(_task("crtsh"), _ctx(lambda _r: "not json"))
    assert result.items == ()


# --- dns -------------------------------------------------------------------


def test_dns_collects_answers_per_type() -> None:
    def responder(req: HttpRequest) -> str | None:
        rtype = req.params["type"]
        if rtype == "A":
            return json.dumps({"Answer": [{"data": "192.0.2.1"}]})
        if rtype == "MX":
            return json.dumps({"Answer": [{"data": "10 mail.acme.com."}]})
        return json.dumps({})  # no Answer for the rest

    result = DnsCollector().collect(_task("dns"), _ctx(responder))
    kinds = {i.kind for i in result.items}
    assert "dns:A" in kinds
    assert "dns:MX" in kinds
    assert any(i.value == "192.0.2.1" for i in result.items)


# --- github ----------------------------------------------------------------


def test_github_lists_org_repos() -> None:
    body = json.dumps(
        [
            {
                "full_name": "acme/site",
                "language": "Go",
                "stargazers_count": 3,
                "description": "the site",
            }
        ]
    )
    result = GitHubCollector().collect(
        _task("github", subject="acme"), _ctx(lambda _r: body)
    )
    assert result.items[0].value == "acme/site"
    assert result.items[0].attributes["language"] == "Go"


def test_github_falls_back_from_org_to_user() -> None:
    calls: list[str] = []

    def responder(req: HttpRequest) -> str | None:
        calls.append(req.url)
        if "/orgs/" in req.url:
            return None  # not an org
        return json.dumps([{"full_name": "acme/dotfiles"}])

    result = GitHubCollector().collect(_task("github", subject="acme"), _ctx(responder))
    assert any("/orgs/" in u for u in calls)
    assert any("/users/" in u for u in calls)
    assert result.items[0].value == "acme/dotfiles"


# --- websearch -------------------------------------------------------------


def test_websearch_duckduckgo_parses_html() -> None:
    html = (
        '<a class="result__a" href="https://acme.com/about">About <b>Acme</b></a>'
        '<a class="result__a" href="https://jobs.acme.com">Careers</a>'
    )
    result = WebSearchCollector().collect(_task("websearch"), _ctx(lambda _r: html))
    urls = [i.value for i in result.items]
    assert urls == ["https://acme.com/about", "https://jobs.acme.com"]
    assert result.items[0].attributes["title"] == "About Acme"


def test_websearch_brave_needs_a_key() -> None:
    cfg = {"websearch": {"backend": "brave"}}
    collector = WebSearchCollector()
    assert collector.available(_ctx(lambda _r: None, source_config=cfg)) is False
    ctx = _ctx(
        lambda _r: None, source_config=cfg, secrets={"osint_search_api_key": "k"}
    )
    assert collector.available(ctx) is True


def test_websearch_brave_parses_json() -> None:
    body = json.dumps(
        {"web": {"results": [{"title": "Acme", "url": "https://acme.com"}]}}
    )
    cfg = {"websearch": {"backend": "brave"}}
    ctx = _ctx(
        lambda _r: body, source_config=cfg, secrets={"osint_search_api_key": "k"}
    )
    result = WebSearchCollector().collect(_task("websearch"), ctx)
    assert result.items[0].value == "https://acme.com"


def test_websearch_duckduckgo_available_without_key() -> None:
    assert WebSearchCollector().available(_ctx(lambda _r: None)) is True


# --- registry --------------------------------------------------------------


def test_default_collectors_cover_the_http_sources() -> None:
    sources = {c.source for c in default_collectors()}
    assert {"crtsh", "dns", "github", "websearch"} <= sources


def test_collector_for_finds_and_misses() -> None:
    collectors = default_collectors()
    assert collector_for("crtsh", collectors) is not None
    assert collector_for("crtsh", ()) is None  # empty registry -> miss
