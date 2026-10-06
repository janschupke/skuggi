"""L1: Burp scanner issue -> FindingDraft mapping + models, offline.

Pins the severity/confidence translation, evidence-item extraction, CWE-ref
normalisation (invalid ones dropped), the dedup key, and the HttpExchange URL
reconstruction.
"""

from __future__ import annotations

from skuggi.burp.findings import (
    issue_dedup_key,
    issue_to_draft,
    meets_confidence,
)
from skuggi.burp.models import BurpFeatures, HttpExchange, ScanIssue


def _issue(**kw: object) -> ScanIssue:
    base: dict[str, object] = {
        "issue_type": "sqli",
        "name": "SQL injection",
        "severity": "high",
        "confidence": "certain",
        "host": "10.0.0.5",
        "port": 443,
        "protocol": "https",
        "path": "/login",
        "parameter": "user",
        "detail": "injectable",
    }
    base.update(kw)
    return ScanIssue(**base)  # type: ignore[arg-type]


def test_issue_to_draft_maps_severity_and_affected() -> None:
    draft = issue_to_draft(_issue())
    assert draft.title == "SQL injection"
    assert draft.severity == "high"
    assert draft.affected is not None
    assert draft.affected.host == "10.0.0.5"
    assert draft.affected.port == "443"
    assert draft.affected.url == "https://10.0.0.5/login"
    assert draft.affected.parameter == "user"
    assert "confidence: certain" in draft.description.lower()


def test_issue_to_draft_extracts_request_response_evidence() -> None:
    issue = _issue(
        evidence=(
            HttpExchange(request="GET /login", response="HTTP/1.1 500"),
            HttpExchange(request="GET /x"),  # response-less
        )
    )
    draft = issue_to_draft(issue)
    kinds = [item.kind for item in draft.evidence_items]
    assert kinds == ["request", "response", "request"]
    assert draft.evidence_items[0].content == "GET /login"


def test_cwe_refs_normalised_and_invalid_dropped() -> None:
    draft = issue_to_draft(_issue(cwe=("89", "CWE-79", "garbage")))
    ref_ids = sorted(ref.ref_id for ref in draft.refs)
    assert ref_ids == ["CWE-79", "CWE-89"]


def test_info_issue_without_port_omits_port() -> None:
    draft = issue_to_draft(_issue(severity="info", port=0, parameter=""))
    assert draft.severity == "info"
    assert draft.affected is not None
    assert draft.affected.port == ""


def test_dedup_key_is_stable_on_locus() -> None:
    assert issue_dedup_key(_issue()) == ("sqli", "10.0.0.5", "/login", "user")
    assert issue_dedup_key(_issue()) == issue_dedup_key(_issue(detail="reworded"))


def test_meets_confidence_floor() -> None:
    assert meets_confidence(_issue(confidence="certain"), "firm")
    assert meets_confidence(_issue(confidence="firm"), "firm")
    assert not meets_confidence(_issue(confidence="tentative"), "firm")


def test_http_exchange_url_reconstruction() -> None:
    assert HttpExchange(host="h", port=443, secure=True, path="/a").url == "https://h/a"
    assert HttpExchange(host="h", port=8080, path="/a").url == "http://h:8080/a"
    assert HttpExchange(path="/only").url == "/only"


def test_features_unreachable_supports_nothing() -> None:
    features = BurpFeatures.unreachable("no bridge")
    assert not features.supports("proxy_history")
    assert not features.supports("active_scan")
