"""L1: the research collectors -- parsing, availability, degradation, all offline.

The HTTP collectors (cve/exploitdb/versions) take an injected ``fetch``; the local-
tool collectors (searchsploit/metasploit) take an injected runner / cache loader and
a presence flag, so none of these touch the network, a subprocess, or the real
filesystem. They pin each source's real response shape and the never-raise
degradation to an empty result.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest

from skuggi.intel.collectors.base import CollectContext, HttpRequest
from skuggi.intel.schema import IntelItem, IntelResult
from skuggi.research.collectors.cve import CveCollector
from skuggi.research.collectors.exploitdb import ExploitDbCollector
from skuggi.research.collectors.metasploit import MetasploitCollector
from skuggi.research.collectors.searchsploit import SearchsploitCollector
from skuggi.research.collectors.versions import VersionsCollector
from skuggi.research.schema import ResearchTask

Responder = Callable[[HttpRequest], "str | None"]


def _ctx(responder: Responder, **kw: object) -> CollectContext:
    base: dict[str, object] = {"fetch": responder, "clean": lambda s: s}
    base.update(kw)
    return CollectContext(**base)  # type: ignore[arg-type]


def _task(source: str, subject: str = "wordpress") -> ResearchTask:
    return ResearchTask(id="t1", source=source, subject=subject, objective="vulns")  # type: ignore[arg-type]


# ----- CVE (NVD) ---------------------------------------------------------------

_NVD_BODY = json.dumps(
    {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "descriptions": [
                        {"lang": "es", "value": "ignorar"},
                        {"lang": "en", "value": "an auth bypass"},
                    ],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]
                    },
                }
            },
            {"cve": {"id": "", "descriptions": []}},  # dropped: no id
            "not-a-dict",  # dropped
        ]
    }
)


def test_cve_parses_nvd_and_builds_detail_urls() -> None:
    res = CveCollector().collect(_task("cve"), _ctx(lambda _r: _NVD_BODY))
    assert res.source == "cve"
    assert len(res.items) == 1
    item = res.items[0]
    assert item.value == "CVE-2024-0001"
    assert item.attributes["severity"] == "HIGH"
    assert item.attributes["description"] == "an auth bypass"
    assert item.attributes["url"].endswith("CVE-2024-0001")


def test_cve_sends_api_key_header_when_present() -> None:
    seen: dict[str, str] = {}

    def fetch(req: HttpRequest) -> str:
        seen.update(req.headers)
        return _NVD_BODY

    CveCollector().collect(_task("cve"), _ctx(fetch, secrets={"nvd_api_key": "k"}))
    assert seen.get("apiKey") == "k"


def test_cve_is_always_available() -> None:
    assert CveCollector().available(_ctx(lambda _r: None)) is True


@pytest.mark.parametrize(
    "body",
    [None, "not json", json.dumps({"no": "vulns"}), json.dumps({"vulnerabilities": 1})],
)
def test_cve_degrades_to_empty(body: str | None) -> None:
    res = CveCollector().collect(_task("cve"), _ctx(lambda _r: body))
    assert res.items == ()
    assert res.note


def test_cve_severity_falls_back_through_metric_versions() -> None:
    body = json.dumps(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-9",
                        "descriptions": [],
                        "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]},
                    }
                }
            ]
        }
    )
    res = CveCollector().collect(_task("cve"), _ctx(lambda _r: body))
    assert res.items[0].attributes["severity"] == "7.5"


# ----- Exploit-DB --------------------------------------------------------------

_EDB_BODY = json.dumps(
    {
        "data": [
            {"id": "123", "description": "WP RCE", "type_id": "remote"},
            {"id": "", "description": ""},  # dropped
            7,  # dropped
        ]
    }
)


def test_exploitdb_parses_entries_and_sends_xhr_header() -> None:
    seen: dict[str, str] = {}

    def fetch(req: HttpRequest) -> str:
        seen.update(req.headers)
        return _EDB_BODY

    res = ExploitDbCollector().collect(_task("exploitdb"), _ctx(fetch))
    assert seen.get("X-Requested-With") == "XMLHttpRequest"
    assert len(res.items) == 1
    assert res.items[0].value == "EDB-123"
    assert res.items[0].attributes["url"].endswith("/123")


@pytest.mark.parametrize(
    "body", [None, "nope", json.dumps({}), json.dumps({"data": "x"})]
)
def test_exploitdb_degrades_to_empty(body: str | None) -> None:
    res = ExploitDbCollector().collect(_task("exploitdb"), _ctx(lambda _r: body))
    assert res.items == ()


def test_exploitdb_always_available() -> None:
    assert ExploitDbCollector().available(_ctx(lambda _r: None)) is True


# ----- versions (endoflife.date) -----------------------------------------------

_EOL_BODY = json.dumps(
    [
        {"cycle": "6.4", "latest": "6.4.3", "eol": False, "releaseDate": "2023-11-07"},
        {"cycle": "4.0", "latest": "4.0.38", "eol": "2000-01-01"},
        "junk",
    ]
)


def test_versions_parses_cycles_and_supported_flag() -> None:
    res = VersionsCollector().collect(_task("versions"), _ctx(lambda _r: _EOL_BODY))
    assert {i.value for i in res.items} == {"6.4", "4.0"}
    by_cycle = {i.value: i for i in res.items}
    assert by_cycle["6.4"].attributes["supported"] == "True"
    assert by_cycle["4.0"].attributes["supported"] == "False"


def test_versions_uses_alias_map_for_product_slug() -> None:
    seen: dict[str, str] = {}

    def fetch(req: HttpRequest) -> str:
        seen["url"] = req.url
        return _EOL_BODY

    ctx = _ctx(fetch, source_config={"versions": {"wordpress 6.x": "wordpress"}})
    VersionsCollector().collect(_task("versions", "WordPress 6.x"), ctx)
    assert seen["url"].endswith("/wordpress.json")


def test_versions_slugs_first_word_without_alias() -> None:
    seen: dict[str, str] = {}

    def fetch(req: HttpRequest) -> str:
        seen["url"] = req.url
        return _EOL_BODY

    VersionsCollector().collect(_task("versions", "Apache HTTPD"), _ctx(fetch))
    assert seen["url"].endswith("/apache.json")


@pytest.mark.parametrize("body", [None, "nope", json.dumps({"not": "a list"})])
def test_versions_degrades_to_empty(body: str | None) -> None:
    res = VersionsCollector().collect(_task("versions"), _ctx(lambda _r: body))
    assert res.items == ()


# ----- searchsploit (local tool) -----------------------------------------------

_SS_BODY = json.dumps(
    {
        "RESULTS_EXPLOIT": [
            {"Title": "WP Plugin RCE", "EDB-ID": "456", "Path": "/x/456.rb"},
            {"Title": "", "EDB-ID": ""},  # dropped
            9,  # dropped
        ]
    }
)


def test_searchsploit_unavailable_when_binary_absent() -> None:
    col = SearchsploitCollector(run=lambda _a: None, have_tool=False)
    assert col.available(_ctx(lambda _r: None)) is False


def test_searchsploit_parses_local_json_when_installed() -> None:
    calls: list[list[str]] = []

    def run(argv: list[str]) -> str:
        calls.append(argv)
        return _SS_BODY

    col = SearchsploitCollector(run=run, have_tool=True)
    assert col.available(_ctx(lambda _r: None)) is True
    res = col.collect(_task("searchsploit"), _ctx(lambda _r: None))
    assert calls == [["searchsploit", "--json", "wordpress"]]
    assert len(res.items) == 1
    assert res.items[0].value == "EDB-456"


@pytest.mark.parametrize("body", [None, "nope", json.dumps({"x": 1})])
def test_searchsploit_degrades_to_empty(body: str | None) -> None:
    col = SearchsploitCollector(run=lambda _a: body, have_tool=True)
    res = col.collect(_task("searchsploit"), _ctx(lambda _r: None))
    assert res.items == ()


def test_searchsploit_rejects_a_flag_injection_subject_without_running() -> None:
    """A subject starting with '-' is argument injection; it must not be spawned."""
    calls: list[list[str]] = []

    def run(argv: list[str]) -> str | None:
        calls.append(argv)
        return None

    col = SearchsploitCollector(run=run, have_tool=True)
    res = col.collect(_task("searchsploit", subject="-m 12345"), _ctx(lambda _r: None))
    assert res.items == ()
    assert calls == []  # the guard rejected it before the subprocess seam


# ----- metasploit (local module cache) -----------------------------------------

_MSF_CACHE = {
    "exploit/unix/webapp/wp_admin": {
        "name": "WordPress Admin Shell",
        "type": "exploit",
        "references": [["CVE", "2024-9999"], ["URL", "http://x"]],
    },
    "exploit/windows/smb/ms08_067": {"name": "MS08-067", "type": "exploit"},
    "bad": "not-a-dict",
}


def test_metasploit_unavailable_without_cache() -> None:
    col = MetasploitCollector(load_cache=lambda: None)
    assert col.available(_ctx(lambda _r: None)) is False


def test_metasploit_filters_cache_by_subject_and_extracts_cves() -> None:
    col = MetasploitCollector(load_cache=lambda: dict(_MSF_CACHE))
    assert col.available(_ctx(lambda _r: None)) is True
    res = col.collect(_task("metasploit"), _ctx(lambda _r: None))
    assert len(res.items) == 1
    item = res.items[0]
    assert item.value == "exploit/unix/webapp/wp_admin"
    assert item.attributes["cves"] == "2024-9999"


def test_metasploit_empty_result_when_cache_vanishes_between_calls() -> None:
    # available() saw a cache, but collect() re-loads and gets nothing.
    state = {"n": 0}

    def load() -> dict[str, object] | None:
        state["n"] += 1
        return dict(_MSF_CACHE) if state["n"] == 1 else None

    col = MetasploitCollector(load_cache=load)
    assert col.available(_ctx(lambda _r: None)) is True
    res = col.collect(_task("metasploit"), _ctx(lambda _r: None))
    assert res.items == ()


# ----- E16: version-aware CVE query + CVE join --------------------------------


def test_cve_uses_cpe_virtual_match_when_a_version_is_upstream() -> None:
    """A resolved upstream version switches NVD from keyword to a version-scoped CPE."""
    seen: dict[str, str] = {}

    def fetch(req: HttpRequest) -> str:
        seen.update(req.params)
        return _NVD_BODY

    upstream = (
        IntelResult(
            task_id="v",
            source="versions",
            subject="wordpress",
            items=(IntelItem(kind="version", value="6.4"),),
        ),
    )
    res = CveCollector().collect(_task("cve"), _ctx(fetch, upstream=upstream))
    assert "virtualMatchString" in seen
    assert "cpe:2.3:a:*:wordpress:6.4:" in seen["virtualMatchString"]
    assert "keywordSearch" not in seen
    assert "CPE" in res.note


def test_cve_falls_back_to_keyword_without_an_upstream_version() -> None:
    seen: dict[str, str] = {}

    def fetch(req: HttpRequest) -> str:
        seen.update(req.params)
        return _NVD_BODY

    CveCollector().collect(_task("cve"), _ctx(fetch))
    assert seen.get("keywordSearch") == "wordpress"
    assert "virtualMatchString" not in seen
