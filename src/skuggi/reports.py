"""Markdown engagement reports, rendered from the ledger.

A report is the human-facing output of a session: the engagement header and
scope, the chronological command log (with timestamps, status and exit codes),
and the findings grouped by severity, each citing the command it came from.
``write_report`` reads the whole session out of the ledger and writes a
timestamped ``.md`` under the (gitignored) reports directory -- the only file
the harness writes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from skuggi.engagement import EngagementConfig
from skuggi.ledger import CommandRow, FindingRow, Ledger, SessionRow

# Most-severe first; anything unrecognized sorts last under "other".
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _block(label: str, body: str) -> str:
    """A labelled section, or nothing when the body is empty (from graph.py)."""
    return f"## {label}\n\n{body}" if body.strip() else ""


def _command_log(commands: list[CommandRow]) -> str:
    if not commands:
        return "_No commands recorded._"
    lines = ["| # | when | status | exit | command |", "|---|---|---|---|---|"]
    for c in commands:
        exit_ = "-" if c.exit_code is None else str(c.exit_code)
        cmd = c.command.replace("|", "\\|")
        lines.append(f"| {c.id} | {c.started_at} | {c.status} | {exit_} | `{cmd}` |")
    return "\n".join(lines)


def _findings(findings: list[FindingRow]) -> str:
    if not findings:
        return "_No findings recorded._"
    by_sev: dict[str, list[FindingRow]] = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)
    ordered = [*_SEVERITY_ORDER, *sorted(set(by_sev) - set(_SEVERITY_ORDER))]
    out: list[str] = []
    for sev in ordered:
        group = by_sev.get(sev)
        if not group:
            continue
        out.append(f"### {sev.upper()} ({len(group)})")
        for f in group:
            src = f" _(from cmd:{f.command_id})_" if f.command_id is not None else ""
            out.append(f"\n**[{f.id}] {f.title}**{src}\n\n{f.description}")
            if f.evidence:
                out.append(f"\n```\n{f.evidence}\n```")
    return "\n".join(out)


def render_report(
    session: SessionRow,
    commands: list[CommandRow],
    findings: list[FindingRow],
    *,
    engagement: EngagementConfig | None = None,
) -> str:
    """Compose the full Markdown report for one session."""
    header = (
        f"# Engagement report: {session.engagement_name}\n\n"
        f"- Session: `{session.session_id}`\n"
        f"- Mode: {session.mode}\n"
        f"- Started: {session.started_at}\n"
        f"- Generated: {datetime.now(UTC).isoformat()}\n"
        f"- Commands: {len(commands)} · Findings: {len(findings)}"
    )
    scope = engagement.describe() if engagement is not None else ""
    return "\n\n".join(
        block
        for block in (
            header,
            _block("Scope", f"```\n{scope}\n```" if scope else ""),
            _block("Findings", _findings(findings)),
            _block("Command log", _command_log(commands)),
        )
        if block
    )


def _slug(text: str) -> str:
    """A filesystem-safe slug for the report filename."""
    return (
        "".join(c if c.isalnum() or c in "-_" else "-" for c in text).strip("-")
        or "engagement"
    )


def write_report(
    session_id: str,
    ledger: Ledger,
    reports_dir: Path,
    *,
    engagement: EngagementConfig | None = None,
) -> Path:
    """Render the session's report and write it as a timestamped Markdown file.

    Raises ``ValueError`` if the session was never started.
    """
    session = ledger.session(session_id)
    if session is None:
        msg = f"no session recorded for {session_id!r}"
        raise ValueError(msg)
    commands = ledger.commands_for(session_id)
    findings = ledger.findings_for(session_id)
    body = render_report(session, commands, findings, engagement=engagement)

    reports_dir = reports_dir.expanduser()
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = reports_dir / f"{_slug(session.engagement_name)}-{session_id[:8]}-{stamp}.md"
    path.write_text(body, encoding="utf-8")
    return path
