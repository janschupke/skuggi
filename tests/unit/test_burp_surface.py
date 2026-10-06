"""L1: the ``show burp`` operator surface -- presenter + control action, offline.

The control action is driven with a stub core whose ``burp_client`` returns a fake
client, so the status/issues branches render without a front-end or a live Burp.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from skuggi.agent.core import AgentCore
from skuggi.burp.client import BurpClient
from skuggi.burp.models import BurpFeatures, ScanIssue
from skuggi.frontend import control, presenters


class _FakeClient:
    def __init__(
        self, features: BurpFeatures, issues: tuple[ScanIssue, ...] = ()
    ) -> None:
        self._features = features
        self._issues = issues

    def feature_probe(self) -> BurpFeatures:
        return self._features

    def scan_issues(self, *, host_filter: str = "") -> tuple[ScanIssue, ...]:
        return self._issues


class _StubCore:
    def __init__(self, client: BurpClient) -> None:
        self._client = client

    def burp_client(self) -> BurpClient:
        return self._client


def _core(client: _FakeClient) -> AgentCore:
    return cast("AgentCore", _StubCore(cast("BurpClient", client)))


def _issue() -> ScanIssue:
    return ScanIssue(
        issue_type="xss",
        name="Reflected XSS",
        severity="medium",
        confidence="firm",
        host="10.0.0.5",
        protocol="https",
        path="/q",
        parameter="term",
    )


def test_present_burp_heading_and_lines() -> None:
    styled = presenters.present_burp(["a", "b"], heading="h:")
    texts = [line.text for line in styled]
    assert texts == ["h:", "a", "b"]


def test_present_burp_no_heading() -> None:
    assert [line.text for line in presenters.present_burp(["only"])] == ["only"]


def test_show_burp_status_branch() -> None:
    features = BurpFeatures(reachable=True, edition="professional", backend="reburp")
    styled = control.show_burp(_core(_FakeClient(features)), "", "repl")
    assert any("connected via reburp" in line.text for line in styled)


def test_show_burp_issues_branch() -> None:
    features = BurpFeatures(reachable=True, edition="professional", scanner=True)
    styled = control.show_burp(
        _core(_FakeClient(features, (_issue(),))), "issues", "repl"
    )
    assert styled[0].text == "burp scanner issues:"
    assert any("Reflected XSS" in line.text for line in styled)


def test_show_burp_issues_community_degrades() -> None:
    features = BurpFeatures(reachable=True, edition="community")
    styled = control.show_burp(_core(_FakeClient(features)), "issues", "repl")
    assert any("scanner unavailable" in line.text for line in styled)


class _OpsCore:
    """A core stub for control.burp_command's dispatch + disabled branches."""

    def __init__(self, engagement: object, ledger: object = None) -> None:
        self.engagement = engagement
        self.ledger = ledger
        self.session_id = "s1"
        self.thread_id = "t"

    def burp_client(self) -> BurpClient:
        return cast("BurpClient", _FakeClient(BurpFeatures(reachable=True)))


def test_burp_command_disabled_warns() -> None:
    core = cast("AgentCore", _OpsCore(engagement=None))
    styled = control.burp_command(core, "scans", "repl")
    assert any("not enabled" in line.text for line in styled)


def test_burp_command_usage_on_unknown_sub() -> None:

    eng = SimpleNamespace(burp=object(), autonomous=True)
    core = cast("AgentCore", _OpsCore(engagement=eng))
    styled = control.burp_command(core, "wat", "repl")
    assert any("usage: burp" in line.text for line in styled)
