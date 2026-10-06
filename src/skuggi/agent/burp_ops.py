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
from skuggi.burp.client import BurpError
from skuggi.burp.findings import issue_dedup_key, issue_to_draft
from skuggi.burp.models import HttpExchange, ScanIssue, ScopeRules

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


def repeat(  # noqa: PLR0913 -- explicit deps for offline testability
    client: BurpClient,
    engagement: EngagementConfig,
    ledger: Ledger,
    *,
    session_id: str,
    thread_id: str,
    autonomous: bool,
    method: str,
    url: str,
) -> list[str]:
    """Send one request through Burp (Repeater-style, gated as a traffic action)."""
    parsed = urlparse(url if "//" in url else f"//{url}")
    host = parsed.hostname or url
    path = parsed.path or "/"
    verb = method.upper()

    def _execute() -> tuple[str, str]:
        exchange = HttpExchange(
            host=host,
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            secure=parsed.scheme == "https",
            method=verb,
            path=path,
            request=f"{verb} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n",
        )
        result = client.send_request(exchange)
        code = result.exchange.status_code
        return (f"{verb} {url} -> {code if code is not None else '?'}", "")

    outcome = run_burp_action(
        engagement=engagement,
        ledger=ledger,
        session_id=session_id,
        thread_id=thread_id,
        action="repeater",
        target_host=host,
        params=f"repeater {verb} {url}",
        autonomous=autonomous,
        execute=_execute,
    )
    return [f"burp: {outcome.summary}"]


def sync(  # noqa: PLR0913 -- explicit deps for offline testability
    client: BurpClient,
    engagement: EngagementConfig,
    ledger: Ledger,
    *,
    session_id: str,
    thread_id: str,
    autonomous: bool,
) -> list[str]:
    """Push the engagement's scope into Burp (defense-in-depth), gated + recorded.

    Burp will then refuse out-of-scope hosts itself, so a misconfigured spider or
    an operator click cannot wander outside the authorized networks. The RoE
    exclusions become Burp exclusions.
    """
    roe = engagement.rules_of_engagement
    include = tuple(str(n) for n in engagement.target_networks) + tuple(
        engagement.allowed_hosts
    )
    exclude: tuple[str, ...] = ()
    if roe is not None:
        exclude = tuple(str(n) for n in roe.excluded_networks) + tuple(
            roe.excluded_hosts
        )

    def _execute() -> tuple[str, str]:
        client.set_scope(ScopeRules(include=include, exclude=exclude))
        return (
            f"pushed scope: {len(include)} include / {len(exclude)} exclude rules",
            "",
        )

    outcome = run_burp_action(
        engagement=engagement,
        ledger=ledger,
        session_id=session_id,
        thread_id=thread_id,
        action="set_scope",
        target_host="",
        params="set_scope (engagement -> burp)",
        autonomous=autonomous,
        execute=_execute,
    )
    return [f"burp: {outcome.summary}"]


def recon(  # noqa: PLR0913 -- explicit deps for offline testability
    client: BurpClient,
    engagement: EngagementConfig,
    ledger: Ledger,
    *,
    session_id: str,
    thread_id: str,
    autonomous: bool,
    host: str = "",
) -> list[str]:
    """One bounded read-only recon sweep: observe proxy traffic, pull issues.

    The lightweight autonomous-recon pass -- a gated read of the proxy history
    (what has been observed) followed by the gated scanner-issue pull (findings),
    both deduped and recorded. Writes stay on the explicit scan/repeater verbs.
    """

    def _proxy_exec() -> tuple[str, str]:
        entries = client.proxy_history(host_filter=host)
        hosts = sorted({e.exchange.host for e in entries if e.exchange.host})
        return (
            f"proxy history: {len(entries)} exchanges across {len(hosts)} host(s)",
            "",
        )

    proxy = run_burp_action(
        engagement=engagement,
        ledger=ledger,
        session_id=session_id,
        thread_id=thread_id,
        action="proxy_history",
        target_host="",
        params=f"proxy_history {host}".strip(),
        autonomous=autonomous,
        execute=_proxy_exec,
    )
    lines = [f"burp: {proxy.summary}"]
    lines.extend(
        pull(
            client,
            engagement,
            ledger,
            session_id=session_id,
            thread_id=thread_id,
            autonomous=autonomous,
            host=host,
        )
    )
    return lines


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


_POLLABLE = frozenset({"active_scan", "intruder"})


def scans(  # noqa: PLR0913 -- explicit deps for offline testability
    client: BurpClient,
    engagement: EngagementConfig,
    ledger: Ledger,
    *,
    session_id: str,
    thread_id: str,
    autonomous: bool,
) -> list[str]:
    """List recorded Burp actions, polling live task status and reconciling scans.

    An in-flight scan/attack (an ``executed`` row with a Burp task ``handle``) is
    polled for its current state; a completed active scan is reconciled -- its new
    issues are pulled into findings through the gated :func:`pull` path (deduped,
    so repeated polling never double-records).
    """
    rows = ledger.burp_actions_for(session_id)
    if not rows:
        return ["burp: no actions recorded this session"]
    out: list[str] = []
    for row in rows:
        base = f"[{row.status}] {row.action} {row.target}"
        if not (row.handle and row.status == "executed" and row.action in _POLLABLE):
            out.append(f"{base} -- {row.params}")
            continue
        base = f"{base} handle={row.handle}"
        try:
            status = client.task_status(row.handle)
        except BurpError as exc:
            out.append(f"{base} -- poll failed ({exc})")
            continue
        percent = f" {status.percent}%" if status.percent is not None else ""
        out.append(f"{base} -- {status.state}{percent}")
        if status.finished and row.action == "active_scan":
            reconciled = pull(
                client,
                engagement,
                ledger,
                session_id=session_id,
                thread_id=thread_id,
                autonomous=autonomous,
                host=row.target,
            )
            out.extend(f"  reconcile {row.handle}: {line}" for line in reconciled)
    return out
