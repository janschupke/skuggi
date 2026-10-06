"""L1: the Burp bridge client -- reburp payload parsing + error mapping, offline.

The adapter takes an injected transport (no network), so these pin the parse of
reburp's record shapes into the backend-agnostic models, the feature probe's
edition detection, and the never-lie error mapping (403 -> feature-unavailable,
other non-200 -> error, transport blow-up -> unreachable).
"""

from __future__ import annotations

from collections.abc import Mapping

import httpx
import pytest

from skuggi.burp.client import (
    BurpError,
    BurpFeatureUnavailableError,
    BurpResponse,
    BurpUnreachableError,
    ReburpClient,
    Transport,
    feature_for,
    make_burp_client,
    make_reburp_client,
)
from skuggi.burp.models import HttpExchange, ScopeRules

Call = tuple[str, str, "dict[str, object] | None"]


def _transport(
    table: dict[str, BurpResponse], *, record: list[Call] | None = None
) -> Transport:
    """A fake transport dispatching on path prefix to a canned response."""

    def _send(
        method: str, path: str, body: Mapping[str, object] | None
    ) -> BurpResponse:
        if record is not None:
            record.append((method, path, dict(body) if body else None))
        for prefix, resp in table.items():
            if path.startswith(prefix):
                return resp
        return BurpResponse(status_code=404, body=None)

    return _send


def test_feature_probe_detects_professional() -> None:
    client = ReburpClient(
        _transport(
            {
                "/api/status": BurpResponse(
                    200,
                    {
                        "edition": "Professional",
                        "version": "2026.5",
                        "scanner": True,
                        "intruder": True,
                    },
                )
            }
        )
    )
    features = client.feature_probe()
    assert features.reachable
    assert features.edition == "professional"
    assert features.scanner
    assert features.intruder
    assert features.supports("active_scan")


def test_feature_probe_community_has_no_scanner() -> None:
    client = ReburpClient(
        _transport({"/api/status": BurpResponse(200, {"edition": "Community"})})
    )
    features = client.feature_probe()
    assert features.edition == "community"
    assert not features.scanner
    assert not features.supports("active_scan")
    assert not features.supports("intruder")
    assert features.supports("proxy_history")  # reads always work when reachable


def test_feature_probe_unreachable_is_not_an_exception() -> None:
    def _boom(
        method: str, path: str, body: Mapping[str, object] | None
    ) -> BurpResponse:
        msg = "connection refused"
        raise OSError(msg)

    features = ReburpClient(_boom).feature_probe()
    assert not features.reachable
    assert features.detail  # the wrapped transport failure is reported


def test_scan_issues_parses_records() -> None:
    client = ReburpClient(
        _transport(
            {
                "/api/scanner/issues": BurpResponse(
                    200,
                    {
                        "issues": [
                            {
                                "type": "sqli",
                                "name": "SQL injection",
                                "severity": "High",
                                "confidence": "Firm",
                                "host": "10.0.0.5",
                                "port": 443,
                                "protocol": "https",
                                "path": "/login",
                                "parameter": "user",
                                "issueDetail": "boom",
                                "cwe": ["CWE-89"],
                                "evidence": [
                                    {
                                        "request": "GET /login",
                                        "response": "HTTP/1.1 500",
                                    }
                                ],
                            }
                        ]
                    },
                )
            }
        )
    )
    issues = client.scan_issues()
    assert len(issues) == 1
    issue = issues[0]
    assert issue.severity == "high"
    assert issue.confidence == "firm"
    assert issue.url == "https://10.0.0.5/login"
    assert issue.cwe == ("CWE-89",)
    assert issue.evidence[0].request == "GET /login"


def test_scan_issues_tolerates_unknown_severity_and_bare_list() -> None:
    client = ReburpClient(
        _transport(
            {
                "/api/scanner/issues": BurpResponse(
                    200, [{"name": "odd", "severity": "bogus", "confidence": "?"}]
                )
            }
        )
    )
    issue = client.scan_issues()[0]
    assert issue.severity == "info"
    assert issue.confidence == "tentative"


def test_forbidden_maps_to_feature_unavailable() -> None:
    client = ReburpClient(_transport({"/api/scanner/issues": BurpResponse(403, None)}))
    with pytest.raises(BurpFeatureUnavailableError):
        client.scan_issues()


def test_non_200_maps_to_error() -> None:
    client = ReburpClient(_transport({"/api/scanner/issues": BurpResponse(500, None)}))
    with pytest.raises(BurpError):
        client.scan_issues()


def test_transport_failure_maps_to_unreachable() -> None:
    def _boom(
        method: str, path: str, body: Mapping[str, object] | None
    ) -> BurpResponse:
        msg = "down"
        raise ConnectionError(msg)

    with pytest.raises(BurpUnreachableError):
        ReburpClient(_boom).scan_issues()


def test_send_request_posts_exchange_and_parses_response() -> None:
    calls: list[Call] = []
    client = ReburpClient(
        _transport(
            {
                "/api/repeater/send": BurpResponse(
                    200, {"response": "HTTP/1.1 200", "time_ms": 42}
                )
            },
            record=calls,
        )
    )
    exchange = HttpExchange(
        host="10.0.0.5",
        port=443,
        secure=True,
        method="GET",
        path="/",
        request="GET / HTTP/1.1",
    )
    result = client.send_request(exchange)
    assert result.round_trip_ms == 42
    assert result.exchange.response == "HTTP/1.1 200"
    method, _path, body = calls[0]
    assert method == "POST"
    assert body is not None
    assert body["request"] == "GET / HTTP/1.1"


def test_start_scan_returns_handle() -> None:
    client = ReburpClient(
        _transport({"/api/scanner/scan": BurpResponse(200, {"id": "scan-7"})})
    )
    assert client.start_scan("https://10.0.0.5/") == "scan-7"


def test_start_scan_without_handle_raises() -> None:
    client = ReburpClient(_transport({"/api/scanner/scan": BurpResponse(200, {})}))
    with pytest.raises(BurpError):
        client.start_scan("https://10.0.0.5/")


def test_task_status_normalises_state() -> None:
    client = ReburpClient(
        _transport(
            {
                "/api/scanner/status": BurpResponse(
                    200, {"state": "running", "percent": 40}
                )
            }
        )
    )
    status = client.task_status("scan-7")
    assert status.state == "running"
    assert not status.finished
    assert status.percent == 40


def test_intruder_roundtrip() -> None:
    calls: list[Call] = []
    client = ReburpClient(
        _transport(
            {
                "/api/intruder/attack": BurpResponse(200, {"id": "atk-1"}),
                "/api/intruder/results": BurpResponse(
                    200,
                    {
                        "results": [
                            {"payload": "' OR 1=1", "length": 10, "flagged": True}
                        ]
                    },
                ),
            },
            record=calls,
        )
    )
    exchange = HttpExchange(
        host="10.0.0.5", method="POST", path="/login", request="POST /login"
    )
    handle = client.start_intruder(exchange, ("' OR 1=1",), marker="§")
    assert handle == "atk-1"
    rows = client.attack_results(handle)
    assert rows[0].flagged
    assert rows[0].payload == "' OR 1=1"


def test_set_scope_posts_rules() -> None:
    calls: list[Call] = []
    client = ReburpClient(
        _transport({"/api/scope": BurpResponse(200, {})}, record=calls)
    )
    client.set_scope(ScopeRules(include=("10.0.0.0/24",), exclude=("10.0.0.9",)))
    _method, _path, body = calls[0]
    assert body is not None
    assert body["include"] == ["10.0.0.0/24"]


def test_make_burp_client_dispatches_reburp() -> None:
    client = make_burp_client("reburp", "http://127.0.0.1:9090")
    assert isinstance(client, ReburpClient)


def test_make_burp_client_rejects_unimplemented_backend() -> None:
    with pytest.raises(NotImplementedError):
        make_burp_client("mcp", "http://127.0.0.1:9876")


def test_proxy_history_parses_entries() -> None:
    client = ReburpClient(
        _transport(
            {
                "/api/proxy/history": BurpResponse(
                    200,
                    {
                        "history": [
                            {
                                "host": "10.0.0.5",
                                "method": "GET",
                                "path": "/",
                                "notes": "n",
                            }
                        ]
                    },
                )
            }
        )
    )
    entries = client.proxy_history(host_filter="10.0.0.5")
    assert entries[0].exchange.host == "10.0.0.5"
    assert entries[0].notes == "n"


def test_add_match_replace_posts() -> None:
    calls: list[Call] = []
    client = ReburpClient(
        _transport({"/api/proxy/match-replace": BurpResponse(200, {})}, record=calls)
    )
    client.add_match_replace("foo", "bar")
    _method, _path, body = calls[0]
    assert body is not None
    assert body["match"] == "foo"


def test_feature_for_probes_support() -> None:
    client = ReburpClient(
        _transport({"/api/status": BurpResponse(200, {"edition": "Professional"})})
    )
    assert feature_for(client, "repeater")


def test_make_reburp_client_httpx_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def _fake_request(method: str, url: str, **kw: object) -> httpx.Response:
        seen["method"] = method
        seen["url"] = url
        seen["headers"] = kw.get("headers")
        return httpx.Response(200, json={"edition": "Community"})

    monkeypatch.setattr(httpx, "request", _fake_request)
    client = make_reburp_client("http://127.0.0.1:9090/", api_key="k")
    features = client.feature_probe()
    assert features.edition == "community"
    assert seen["url"] == "http://127.0.0.1:9090/api/status"
    assert seen["headers"] == {"Authorization": "Bearer k"}


def test_make_reburp_client_handles_non_json(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_request(method: str, url: str, **kw: object) -> httpx.Response:
        return httpx.Response(500, text="nope")

    monkeypatch.setattr(httpx, "request", _fake_request)
    features = make_reburp_client("http://127.0.0.1:9090").feature_probe()
    assert not features.reachable
