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

from skuggi import palette
from skuggi.engagement import EngagementConfig
from skuggi.ledger import CommandRow, FindingRow, Ledger, SessionRow
from skuggi.paths import ensure_dir
from skuggi.text import join_blocks, labeled

# Most-severe first; anything unrecognized sorts last under "other".
_SEVERITY_ORDER = palette.severities()


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
    return join_blocks(
        header,
        labeled("Scope", f"```\n{scope}\n```" if scope else "", heading=True),
        labeled("Findings", _findings(findings), heading=True),
        labeled("Command log", _command_log(commands), heading=True),
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
    pdf: bool = False,
) -> Path | tuple[Path, Path]:
    """Render the session's report and write it as a timestamped Markdown file.

    Markdown is always the canonical artifact. When ``pdf`` is set, the same
    rendered Markdown is also painted to a sibling ``.pdf`` (via
    :mod:`skuggi.pdf`, imported lazily so the core agent needs no PDF deps) and
    both paths are returned.

    Raises ``ValueError`` if the session was never started.
    """
    session = ledger.session(session_id)
    if session is None:
        msg = f"no session recorded for {session_id!r}"
        raise ValueError(msg)
    commands = ledger.commands_for(session_id)
    findings = ledger.findings_for(session_id)
    body = render_report(session, commands, findings, engagement=engagement)

    reports_dir = ensure_dir(reports_dir)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    base = reports_dir / f"{_slug(session.engagement_name)}-{session_id[:8]}-{stamp}"
    md_path = base.with_suffix(".md")
    md_path.write_text(body, encoding="utf-8")
    if not pdf:
        return md_path

    from skuggi import pdf as pdf_mod

    pdf_path = pdf_mod.markdown_to_pdf(
        body, base.with_suffix(".pdf"), title=session.engagement_name
    )
    return md_path, pdf_path


def report_written_lines(result: Path | tuple[Path, Path]) -> list[str]:
    """Describe what :func:`write_report` produced, for either front-end.

    Keeps the "report written / pdf written" wording identical across the REPL
    and the daemon instead of each formatting the ``Path | tuple`` return.
    """
    if isinstance(result, tuple):
        md_path, pdf_path = result
        return [f"report written: {md_path}", f"pdf written: {pdf_path}"]
    return [f"report written: {result}"]
