"""Operator/agent Burp operations: scan, pull issues into findings, list scans.

The thin orchestration behind the ``burp`` verb. Each op runs through the gated
runner (:func:`skuggi.burp.actions.run_burp_action`) so the scope guard, the
autonomous ceiling and the ``burp_actions`` ledger apply uniformly, then performs
the client call and -- for a pull -- maps scanner issues onto findings through the
same ``record_finding_drafts`` sink the worker and the OSINT verifier use.

Functions take explicit dependencies (client / engagement / ledger / ids) rather
than an ``AgentCore`` so they are unit-testable with fakes; the front-end control
action passes the core's fields. They return plain text lines; the surface styles
them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from skuggi.agent.executor import record_finding_drafts
from skuggi.burp.actions import run_burp_action
from skuggi.burp.findings import issue_dedup_key, issue_to_draft
from skuggi.burp.models import ScanIssue

if TYPE_CHECKING:
    from skuggi.burp.client import BurpClient
    from skuggi.engagement.scope import EngagementConfig
    from skuggi.persistence.ledger import Ledger


def _host_of(url: str) -> str:
    """The hostname of a URL (or the raw string when it has no scheme)."""
    parsed = urlparse(url if "//" in url else f"//{url}")
    return parsed.hostname or url


def scan(  # noqa: PLR0913 -- explicit deps for offline testability
    client: BurpClient,
    engagement: EngagementConfig,
    ledger: Ledger,
    *,
    session_id: str,
    thread_id: str,
    autonomous: bool,
    url: str,
) -> list[str]:
    """Launch an active scan against ``url`` (gated); report the outcome."""

    def _execute() -> tuple[str, str]:
        handle = client.start_scan(url)
        return (f"active scan started against {url}", handle)

    outcome = run_burp_action(
        engagement=engagement,
        ledger=ledger,
        session_id=session_id,
        thread_id=thread_id,
        action="active_scan",
        target_host=_host_of(url),
        params=f"active_scan {url}",
        autonomous=autonomous,
        execute=_execute,
    )
    line = outcome.summary
    if outcome.ran and outcome.handle:
        line = f"{outcome.summary} (handle {outcome.handle}; poll with `burp scans`)"
    return [f"burp: {line}"]


def _existing_keys(ledger: Ledger, session_id: str) -> set[tuple[str, str, str, str]]:
    """The (title, host, url, param) loci already recorded, for dedup on pull."""
    return {
        (f.title, f.affected_host, f.affected_url, f.affected_param)
        for f in ledger.findings_for(session_id)
    }


def _new_issues(
    issues: tuple[ScanIssue, ...], existing: set[tuple[str, str, str, str]]
) -> list[ScanIssue]:
    """The issues not already recorded as a finding (dedup across re-scans)."""
    out: list[ScanIssue] = []
    seen: set[tuple[str, str, str, str]] = set()
    for issue in issues:
        key = issue_dedup_key(issue)
        locus = (issue.name, issue.host, issue.url, issue.parameter)
        if locus in existing or key in seen:
            continue
        seen.add(key)
        out.append(issue)
    return out


def pull(  # noqa: PLR0913 -- explicit deps for offline testability
    client: BurpClient,
    engagement: EngagementConfig,
    ledger: Ledger,
    *,
    session_id: str,
    thread_id: str,
    autonomous: bool,
    host: str = "",
) -> list[str]:
    """Read the scanner's issues (gated) and record new ones as findings."""
    recorded: list[int] = []

    def _execute() -> tuple[str, str]:
        issues = client.scan_issues(host_filter=host)
        fresh = _new_issues(issues, _existing_keys(ledger, session_id))
        record_finding_drafts(
            ledger,
            [issue_to_draft(i) for i in fresh],
            session_id=session_id,
            engagement=engagement,
            command_id=None,
        )
        recorded.append(len(fresh))
        return (f"pulled {len(issues)} issues, recorded {len(fresh)} new findings", "")

    outcome = run_burp_action(
        engagement=engagement,
        ledger=ledger,
        session_id=session_id,
        thread_id=thread_id,
        action="scan_issues",
        target_host=host,
        params=f"scan_issues {host}".strip(),
        autonomous=autonomous,
        execute=_execute,
    )
    return [f"burp: {outcome.summary}"]


def scans(ledger: Ledger, *, session_id: str) -> list[str]:
    """List the Burp actions recorded this session (status + any task handle)."""
    rows = ledger.burp_actions_for(session_id)
    if not rows:
        return ["burp: no actions recorded this session"]
    out: list[str] = []
    for row in rows:
        handle = f" handle={row.handle}" if row.handle else ""
        out.append(f"[{row.status}] {row.action} {row.target}{handle} -- {row.params}")
    return out
