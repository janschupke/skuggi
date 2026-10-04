"""L1: the active OSINT collectors + shodan -- Apify and driver paths, offline.

The browser/scraper sources are exercised with a fake Apify runner (canned dataset
rows) and a fake Driver (canned HTML); playwright/apify-client are never imported.
Covers the backend dispatch, the availability gating, and the parse of each path.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

from skuggi.osint.collectors import apify as apify_mod
from skuggi.osint.collectors import browser as browser_mod
from skuggi.osint.collectors import collector_for, default_collectors
from skuggi.osint.collectors.ats import ATSCollector
from skuggi.osint.collectors.base import CollectContext, Driver
from skuggi.osint.collectors.linkedin import LinkedInCollector
from skuggi.osint.collectors.shodan import ShodanCollector
from skuggi.osint.collectors.social import SocialCollector
from skuggi.osint.schema import OsintTask


class _FakeDriver:
    """A Driver that returns canned HTML (no browser)."""

    def __init__(self, html: str) -> None:
        self._html = html
        self.closed = False

    def fetch_html(self, url: str) -> str:
        return self._html

    def close(self) -> None:
        self.closed = True


def _ctx(**kw: object) -> CollectContext:
    base: dict[str, object] = {"fetch": lambda _r: None, "clean": lambda s: s}
    base.update(kw)
    return CollectContext(**base)  # type: ignore[arg-type]


def _driver_ctx(html: str, **kw: object) -> CollectContext:
    return _ctx(driver_factory=lambda: _FakeDriver(html), **kw)


def _apify_ctx(
    rows: list[dict[str, object]], source: str, actor: str = "a/x", **kw: object
) -> CollectContext:
    def run(_actor: str, _inp: Mapping[str, object]) -> list[dict[str, object]]:
        return rows

    cfg = {source: {"apify_actor": actor}}
    return _ctx(apify_run=run, source_config=cfg, **kw)


def _task(source: str, subject: str = "acme.com") -> OsintTask:
    return OsintTask(id="t", source=source, subject=subject, objective="o")  # type: ignore[arg-type]


# --- availability ----------------------------------------------------------


def test_active_unavailable_without_driver_or_apify() -> None:
    assert LinkedInCollector().available(_ctx()) is False


def test_active_available_with_a_driver() -> None:
    assert LinkedInCollector().available(_driver_ctx("<html></html>")) is True


def test_active_available_with_apify() -> None:
    assert ATSCollector().available(_apify_ctx([], "ats")) is True


# --- linkedin --------------------------------------------------------------


def test_linkedin_apify_yields_roles_and_tech() -> None:
    rows: list[dict[str, object]] = [
        {"title": "Senior Python Engineer", "description": "django, aws, kubernetes"}
    ]
    result = LinkedInCollector().collect(
        _task("linkedin"), _apify_ctx(rows, "linkedin")
    )
    kinds = {i.kind for i in result.items}
    assert "role" in kinds
    techs = {i.value for i in result.items if i.kind == "tech"}
    assert {"python", "django", "aws", "kubernetes"} <= techs


def test_linkedin_driver_extracts_tech_from_html() -> None:
    html = "<div>We use Go, React and PostgreSQL</div>"
    result = LinkedInCollector().collect(_task("linkedin"), _driver_ctx(html))
    techs = {i.value for i in result.items if i.kind == "tech"}
    assert {"go", "react", "postgresql"} <= techs


def test_linkedin_empty_when_no_backend() -> None:
    result = LinkedInCollector().collect(_task("linkedin"), _ctx())
    assert result.items == ()
    assert "unavailable" in result.note


# --- ats -------------------------------------------------------------------


def test_ats_driver_parses_job_links() -> None:
    html = '<a href="https://acme.com/jobs/42">Backend Engineer</a>'
    result = ATSCollector().collect(_task("ats"), _driver_ctx(html))
    assert result.items[0].kind == "role"
    assert result.items[0].value == "Backend Engineer"
    assert result.items[0].attributes["url"] == "https://acme.com/jobs/42"


def test_ats_apify_yields_roles() -> None:
    rows: list[dict[str, object]] = [{"title": "SRE"}, {"title": "Data Scientist"}]
    result = ATSCollector().collect(_task("ats"), _apify_ctx(rows, "ats"))
    assert {i.value for i in result.items} == {"SRE", "Data Scientist"}


# --- social ----------------------------------------------------------------


def test_social_driver_extracts_known_hosts() -> None:
    html = (
        '<a href="https://twitter.com/acme">x</a><a href="https://example.com/x">y</a>'
    )
    result = SocialCollector().collect(_task("social"), _driver_ctx(html))
    values = {i.value for i in result.items}
    assert "https://twitter.com/acme" in values
    assert "https://example.com/x" not in values  # not a known social host


# --- shodan ----------------------------------------------------------------


def test_shodan_needs_a_key() -> None:
    assert ShodanCollector().available(_ctx()) is False
    assert ShodanCollector().available(_ctx(secrets={"shodan_api_key": "k"})) is True


def test_shodan_parses_matches() -> None:
    body = json.dumps(
        {
            "matches": [
                {
                    "ip_str": "192.0.2.5",
                    "port": 443,
                    "product": "nginx",
                    "vulns": {"CVE-2021-1": {}},
                }
            ]
        }
    )
    ctx = _ctx(fetch=lambda _r: body, secrets={"shodan_api_key": "k"})
    result = ShodanCollector().collect(_task("shodan"), ctx)
    assert result.items[0].value == "192.0.2.5"
    assert result.items[0].attributes["product"] == "nginx"
    assert "CVE-2021-1" in result.items[0].attributes["cves"]


# --- optional-dep gating + registry ----------------------------------------


def test_playwright_factory_is_none_without_the_extra() -> None:
    # The extra is not installed in the test env, so the factory is None.
    if not browser_mod.playwright_available():
        assert browser_mod.default_driver_factory() is None


def test_make_apify_run_is_none_without_a_token() -> None:
    assert apify_mod.make_apify_run("") is None


def test_registry_covers_every_source() -> None:
    sources = {c.source for c in default_collectors()}
    assert sources == {
        "crtsh",
        "dns",
        "github",
        "websearch",
        "shodan",
        "linkedin",
        "ats",
        "social",
    }
    assert collector_for("linkedin", default_collectors()) is not None


def test_driver_is_a_protocol_instance() -> None:
    assert isinstance(_FakeDriver("x"), Driver)
