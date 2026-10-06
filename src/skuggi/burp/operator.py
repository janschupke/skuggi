"""Presentation-agnostic summaries of Burp state for the operator read surface.

Pure functions from the backend-agnostic models to plain text lines, so the
``show burp`` surface in both front-ends renders the same content and the whole
thing is unit-testable with a fake :class:`~skuggi.burp.client.BurpClient` -- no
front-end, no live Burp. The front-end wraps these lines in its own styling.
"""

from __future__ import annotations

from skuggi.burp.client import BurpClient, BurpError
from skuggi.burp.models import BurpFeatures, ScanIssue


def status_lines(features: BurpFeatures) -> list[str]:
    """A short connection + edition + capability summary."""
    if not features.reachable:
        return [f"burp: not reachable ({features.detail or 'no bridge'})"]
    version = f" {features.version}" if features.version else ""
    caps = [
        f"scanner {'on' if features.scanner else 'off'}",
        f"intruder {'on' if features.intruder else 'off'}",
    ]
    return [
        f"burp: connected via {features.backend} -- {features.edition}{version}",
        "  " + ", ".join(caps),
    ]


def issue_line(issue: ScanIssue) -> str:
    """One scanner issue as a single severity-prefixed line."""
    locus = issue.url or issue.host or "?"
    param = f" [{issue.parameter}]" if issue.parameter else ""
    return f"[{issue.severity}] {issue.name} -- {locus}{param} ({issue.confidence})"


def issue_lines(issues: tuple[ScanIssue, ...]) -> list[str]:
    """A list of scanner issues, or a single "none" line when empty."""
    if not issues:
        return ["burp: no scanner issues"]
    return [issue_line(issue) for issue in issues]


def probe_status(client: BurpClient) -> list[str]:
    """Probe the bridge and summarise it (never raises -- the probe swallows)."""
    return status_lines(client.feature_probe())


def fetch_issue_lines(client: BurpClient, *, host_filter: str = "") -> list[str]:
    """Read current scanner issues and summarise them, degrading on failure.

    A Community edition (no scanner) or an unreachable bridge yields a single
    explanatory line rather than an exception, mirroring how an absent OSINT
    source degrades to a coverage note.
    """
    features = client.feature_probe()
    if not features.reachable:
        return [f"burp: not reachable ({features.detail or 'no bridge'})"]
    if not features.scanner:
        return [f"burp: scanner unavailable on {features.edition} edition"]
    try:
        issues = client.scan_issues(host_filter=host_filter)
    except BurpError as exc:
        return [f"burp: could not read issues ({exc})"]
    return issue_lines(issues)
