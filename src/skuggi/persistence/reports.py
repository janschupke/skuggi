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

from skuggi.common import palette
from skuggi.common.paths import ensure_dir
from skuggi.common.text import join_blocks, labeled
from skuggi.engagement.engagement import EngagementConfig
from skuggi.persistence.ledger import CommandRow, FindingRow, Ledger, SessionRow

# Most-severe first; anything unrecognized sorts last under "other".
_SEVERITY_ORDER = palette.severities()


def _local_stamp(iso: str, engagement: EngagementConfig | None) -> str:
    """A stored UTC timestamp rendered in the engagement timezone, labeled.

    The ledger writes timezone-aware UTC ISO strings; an external report shows
    them in the engagement's own timezone (``2026-07-01 14:30:00 EEST (+03:00)``)
    so the reader sees wall-clock time in the scope's zone. With no engagement
    (the fallback path, e.g. a report rendered without a scope) the value stays
    in UTC. A naive input string is treated as UTC defensively -- the ledger
    never writes one, but this keeps the display total.
    """
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    if engagement is not None:
        dt = dt.astimezone(engagement.tzinfo())
    raw = dt.strftime("%z")
    offset = f"{raw[:3]}:{raw[3:]}" if raw else ""
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S %Z')} ({offset})"


def _command_log(
    commands: list[CommandRow], engagement: EngagementConfig | None
) -> str:
    if not commands:
        return "_No commands recorded._"
    lines = ["| # | when | status | exit | command |", "|---|---|---|---|---|"]
    for c in commands:
        exit_ = "-" if c.exit_code is None else str(c.exit_code)
        cmd = c.command.replace("|", "\\|")
        when = _local_stamp(c.started_at, engagement)
        lines.append(f"| {c.id} | {when} | {c.status} | {exit_} | `{cmd}` |")
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
    generated_label: str | None = None,
) -> str:
    """Compose the full Markdown report for one session.

    All displayed times are rendered in the engagement timezone (see
    ``_local_stamp``); the stored ledger values stay UTC. ``generated_label`` is
    the single "generated at" stamp: ``write_report`` computes it once and passes
    the same value to the PDF footer so the two artifacts never disagree. When
    omitted it is computed here (standalone/direct callers).
    """
    if generated_label is None:
        generated_label = _local_stamp(datetime.now(UTC).isoformat(), engagement)
    zone = engagement.timezone if engagement is not None else "UTC"
    header = (
        f"# Engagement report: {session.engagement_name}\n\n"
        f"- Session: `{session.session_id}`\n"
        f"- Mode: {session.mode}\n"
        f"- Started: {_local_stamp(session.started_at, engagement)}\n"
        f"- Generated: {generated_label}\n"
        f"- Times shown in: {zone}\n"
        f"- Commands: {len(commands)} · Findings: {len(findings)}"
    )
    scope = engagement.describe() if engagement is not None else ""
    return join_blocks(
        header,
        labeled("Scope", f"```\n{scope}\n```" if scope else "", heading=True),
        labeled("Findings", _findings(findings), heading=True),
        labeled("Command log", _command_log(commands, engagement), heading=True),
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
    # One generated-at stamp, shared by the Markdown body and the PDF footer, so a
    # later PDF re-render cannot disagree with the document it renders.
    generated_label = _local_stamp(datetime.now(UTC).isoformat(), engagement)
    body = render_report(
        session,
        commands,
        findings,
        engagement=engagement,
        generated_label=generated_label,
    )

    reports_dir = ensure_dir(reports_dir)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    base = reports_dir / f"{_slug(session.engagement_name)}-{session_id[:8]}-{stamp}"
    md_path = base.with_suffix(".md")
    md_path.write_text(body, encoding="utf-8")
    if not pdf:
        return md_path

    from skuggi.persistence import pdf as pdf_mod

    pdf_path = pdf_mod.markdown_to_pdf(
        body,
        base.with_suffix(".pdf"),
        title=session.engagement_name,
        generated_label=f"Generated {generated_label}",
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
