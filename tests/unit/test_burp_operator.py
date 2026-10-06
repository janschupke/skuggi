"""L1: the operator read summaries for the Burp connector, offline.

Drives the pure summary functions with a fake client so the ``show burp`` content
is pinned without a front-end or a live Burp, including the Community/unreachable
degradation paths.
"""

from __future__ import annotations

from skuggi.burp import operator
from skuggi.burp.client import BurpClient, BurpError
from skuggi.burp.models import BurpFeatures, ScanIssue


class _FakeClient:
    """A BurpClient stub returning canned features/issues (or raising)."""

    def __init__(
        self,
        features: BurpFeatures,
        issues: tuple[ScanIssue, ...] = (),
        *,
        raise_on_issues: bool = False,
    ) -> None:
        self._features = features
        self._issues = issues
        self._raise = raise_on_issues

    def feature_probe(self) -> BurpFeatures:
        return self._features

    def scan_issues(self, *, host_filter: str = "") -> tuple[ScanIssue, ...]:
        if self._raise:
            msg = "boom"
            raise BurpError(msg)
        return self._issues


def _issue(**kw: object) -> ScanIssue:
    base: dict[str, object] = {
        "issue_type": "xss",
        "name": "Reflected XSS",
        "severity": "medium",
        "confidence": "firm",
        "host": "10.0.0.5",
        "protocol": "https",
        "path": "/q",
        "parameter": "term",
    }
    base.update(kw)
    return ScanIssue(**base)  # type: ignore[arg-type]


def _as_client(obj: _FakeClient) -> BurpClient:
    return obj  # type: ignore[return-value]


def test_status_lines_connected() -> None:
    features = BurpFeatures(
        reachable=True,
        edition="professional",
        version="2026.5",
        scanner=True,
        intruder=True,
        backend="reburp",
    )
    lines = operator.status_lines(features)
    assert "connected via reburp" in lines[0]
    assert "scanner on" in lines[1]


def test_status_lines_unreachable() -> None:
    lines = operator.status_lines(BurpFeatures.unreachable("refused"))
    assert lines == ["burp: not reachable (refused)"]


def test_issue_lines_render_each() -> None:
    lines = operator.issue_lines((_issue(), _issue(name="SQLi", severity="high")))
    assert lines[0] == "[medium] Reflected XSS -- https://10.0.0.5/q [term] (firm)"
    assert lines[1].startswith("[high] SQLi")


def test_issue_lines_empty() -> None:
    assert operator.issue_lines(()) == ["burp: no scanner issues"]


def test_fetch_issue_lines_community_degrades() -> None:
    client = _as_client(_FakeClient(BurpFeatures(reachable=True, edition="community")))
    lines = operator.fetch_issue_lines(client)
    assert "scanner unavailable on community" in lines[0]


def test_fetch_issue_lines_unreachable_degrades() -> None:
    client = _as_client(_FakeClient(BurpFeatures.unreachable("no bridge")))
    assert operator.fetch_issue_lines(client) == ["burp: not reachable (no bridge)"]


def test_fetch_issue_lines_read_error_degrades() -> None:
    features = BurpFeatures(reachable=True, edition="professional", scanner=True)
    client = _as_client(_FakeClient(features, raise_on_issues=True))
    lines = operator.fetch_issue_lines(client)
    assert "could not read issues" in lines[0]


def test_fetch_issue_lines_success() -> None:
    features = BurpFeatures(reachable=True, edition="professional", scanner=True)
    client = _as_client(_FakeClient(features, issues=(_issue(),)))
    lines = operator.fetch_issue_lines(client)
    assert lines[0].startswith("[medium] Reflected XSS")


def test_probe_status_delegates() -> None:
    features = BurpFeatures(reachable=True, edition="professional", backend="reburp")
    client = _as_client(_FakeClient(features))
    assert "connected via reburp" in operator.probe_status(client)[0]
