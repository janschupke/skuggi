"""Markdown engagement reports, rendered from the ledger.

A report is the human-facing output of a session: the engagement header and
scope, the chronological command log (with timestamps, status and exit codes),
and the findings grouped by severity, each citing the command it came from.
``write_report`` reads the whole session out of the ledger and writes a
timestamped ``.md`` under the (gitignored) reports directory -- the only file
the harness writes.
"""

from __future__ import annotations

import base64
import difflib
import mimetypes
from datetime import UTC, datetime
from pathlib import Path

from skuggi.common import palette
from skuggi.common.clock import file_stamp, now_iso
from skuggi.common.paths import confine_under, ensure_dir
from skuggi.common.text import join_blocks, labeled, slug
from skuggi.engagement.engagement import EngagementConfig
from skuggi.persistence.ledger import (
    CommandRow,
    FindingEvidenceRow,
    FindingRefRow,
    FindingRow,
    Ledger,
    SessionRow,
)

_Refs = dict[int, list[FindingRefRow]]
_Evidence = dict[int, list[FindingEvidenceRow]]

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


def _cvss_line(f: FindingRow) -> str:
    """The CVSS score line for a finding, or empty when it carries no vector."""
    if f.cvss_score is None or not f.cvss_vector:
        return ""
    band = (f.cvss_severity or "").upper()
    return f"\n\nCVSS {f.cvss_version} {f.cvss_score} ({band}) — `{f.cvss_vector}`"


def _refs_line(refs: list[FindingRefRow]) -> str:
    """A finding's framework classifications as Markdown links, primary first."""
    if not refs:
        return ""
    parts = []
    for r in refs:
        label = f"{r.ref_id}*" if r.is_primary else r.ref_id
        parts.append(f"[{label}]({r.url})" if r.url else label)
    return "\n\nClassified: " + ", ".join(parts)


def _affected(f: FindingRow) -> str:
    """The affected locus of a finding, as a readable one-liner (or "")."""
    loc: list[str] = []
    if f.affected_url:
        loc.append(f.affected_url)
    if f.affected_host:
        host = f.affected_host + (f":{f.affected_port}" if f.affected_port else "")
        loc.append(host)
    elif f.affected_port:
        loc.append(f"port {f.affected_port}")
    if f.affected_param:
        loc.append(f"parameter `{f.affected_param}`")
    return " — ".join(loc)


def _severity_summary(findings: list[FindingRow]) -> str:
    """A severity-count table over the approved findings (the report's at-a-glance)."""
    if not findings:
        return "No approved findings."
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    ordered = [s for s in _SEVERITY_ORDER if s in counts]
    ordered += sorted(set(counts) - set(_SEVERITY_ORDER))
    rows = "\n".join(f"| {s.upper()} | {counts[s]} |" for s in ordered)
    return f"| Severity | Count |\n| --- | --- |\n{rows}\n\n**Total: {len(findings)}**"


_LIMITATIONS = (
    "This report covers only the hosts, networks and methods authorized in the "
    "scope below; anything outside it was not tested. Testing was time-boxed to "
    "the engagement window, so an absence of findings in an area is not a proof "
    "of its absence of vulnerabilities. Findings reflect the state of the targets "
    "at the time of testing."
)


def _fenced(text: str) -> str:
    """Wrap `text` in a code fence longer than any backtick run it contains.

    Evidence is target-derived; a bare ```` ``` ```` fence would let a line of
    backticks in the evidence break out of the block and inject Markdown into the
    report. The fence is sized to one backtick longer than the longest run inside
    (minimum three), which CommonMark guarantees cannot be closed early (audit B4).
    """
    longest = 0
    run = 0
    for char in text:
        run = run + 1 if char == "`" else 0
        longest = max(longest, run)
    fence = "`" * max(3, longest + 1)
    return f"\n{fence}\n{text}\n{fence}"


def _image_data_uri(media_path: str, media_root: Path | None) -> str:
    """A ``data:`` URI for a workspace-confined image, or "" when unusable (E4/B4).

    The path is confined under ``media_root`` (a traversal/symlink escape yields ""),
    must be an existing image file, and is inlined as base64 so the PDF renders it
    with no network fetch (the report's fetcher serves only ``data:``).
    """
    if media_root is None or not media_path:
        return ""
    try:
        path = confine_under(media_root, media_path)
    except ValueError:
        return ""
    if not path.is_file():
        return ""
    mime = mimetypes.guess_type(str(path))[0] or ""
    if not mime.startswith("image/"):
        return ""
    data = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime};base64,{data}"


def _evidence_items_block(
    items: list[FindingEvidenceRow], media_root: Path | None
) -> str:
    """Render a finding's structured evidence: fenced text, embedded images (E4)."""
    out: list[str] = []
    for item in items:
        label = item.kind.capitalize()
        if item.kind in ("screenshot", "image"):
            uri = _image_data_uri(item.media_path, media_root)
            if uri:
                out.append(f"\n_{label}:_\n\n![{item.media_path}]({uri})")
            else:
                out.append(f"\n_{label}:_ `{item.media_path}` (not embedded)")
        elif item.content:
            out.append(f"\n_{label}:_{_fenced(item.content)}")
    return "\n".join(out)


def _findings(
    findings: list[FindingRow],
    refs: _Refs | None = None,
    evidence: _Evidence | None = None,
    media_root: Path | None = None,
) -> str:
    if not findings:
        return "_No findings recorded._"
    refs = refs or {}
    evidence = evidence or {}
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
            affected = _affected(f)
            if affected:
                out.append(f"\n_Affected:_ {affected}")
            out.append(_cvss_line(f))
            out.append(_refs_line(refs.get(f.id, [])))
            if f.impact:
                out.append(f"\n**Impact:** {f.impact}")
            if f.remediation:
                out.append(f"\n**Remediation:** {f.remediation}")
            if f.evidence:
                out.append(_fenced(f.evidence))
            out.append(_evidence_items_block(evidence.get(f.id, []), media_root))
    return "\n".join(p for p in out if p)


def render_report(  # noqa: PLR0913 -- a report is composed from its ledger parts
    session: SessionRow,
    commands: list[CommandRow],
    findings: list[FindingRow],
    *,
    engagement: EngagementConfig | None = None,
    generated_label: str | None = None,
    refs: _Refs | None = None,
    evidence: _Evidence | None = None,
    media_root: Path | None = None,
    revision: int = 1,
    previous: str | None = None,
    excluded: int = 0,
    changelog: bool = False,
) -> str:
    """Compose the full Markdown report for one session.

    All displayed times are rendered in the engagement timezone (see
    ``_local_stamp``); the stored ledger values stay UTC. ``generated_label`` is
    the single "generated at" stamp: ``write_report`` computes it once and passes
    the same value to the PDF footer so the two artifacts never disagree. When
    omitted it is computed here (standalone/direct callers). ``revision`` /
    ``previous`` / ``excluded`` / ``changelog`` drive the revision header;
    ``findings`` here are already the approved ones (``excluded`` counts the rest).
    """
    if generated_label is None:
        generated_label = _local_stamp(now_iso(), engagement)
    zone = engagement.timezone if engagement is not None else "UTC"
    prior = f"; previous: `{previous}`" if previous else ""
    dropped = f" ({excluded} draft/rejected excluded)" if excluded else ""
    changes = "\n- Changelog: `CHANGELOG.md`" if changelog else ""
    header = (
        f"# Engagement report: {session.engagement_name}\n\n"
        f"- Session: `{session.session_id}`\n"
        f"- Mode: {session.mode}\n"
        f"- Started: {_local_stamp(session.started_at, engagement)}\n"
        f"- Generated: {generated_label}\n"
        f"- Revision: {revision}{prior}\n"
        f"- Times shown in: {zone}\n"
        f"- Commands: {len(commands)} · Approved findings: {len(findings)}{dropped}"
        f"{changes}"
    )
    scope = engagement.describe() if engagement is not None else ""
    return join_blocks(
        header,
        labeled("Summary", _severity_summary(findings), heading=True),
        labeled("Scope", f"```\n{scope}\n```" if scope else "", heading=True),
        labeled("Methodology & limitations", _LIMITATIONS, heading=True),
        labeled(
            "Findings",
            _findings(findings, refs, evidence, media_root),
            heading=True,
        ),
        labeled("Command log", _command_log(commands, engagement), heading=True),
    )


def _affected_table(findings: list[FindingRow]) -> str:
    """A finding-to-affected-asset table for the engagement report (audit E5)."""
    rows = [(f, _affected(f)) for f in findings]
    rows = [(f, a) for f, a in rows if a]
    if not rows:
        return ""
    lines = ["| ID | Severity | Finding | Affected |", "| --- | --- | --- | --- |"]
    lines += [f"| {f.id} | {f.severity.upper()} | {f.title} | {a} |" for f, a in rows]
    return "\n".join(lines)


def render_engagement_report(  # noqa: PLR0913 -- a report is composed from its ledger parts
    engagement_name: str,
    findings: list[FindingRow],
    *,
    engagement: EngagementConfig | None = None,
    generated_label: str | None = None,
    refs: _Refs | None = None,
    evidence: _Evidence | None = None,
    media_root: Path | None = None,
    session_count: int = 0,
) -> str:
    """Compose the cross-session, deduplicated engagement report (audit E5).

    Unlike the per-session report, this aggregates every session's approved findings
    (already deduped by the caller) into one client deliverable: an executive
    severity summary, the authorized scope and limitations, an affected-asset table,
    and the full per-finding detail. There is no single command log (the report
    spans sessions), so it is omitted.
    """
    if generated_label is None:
        generated_label = _local_stamp(now_iso(), engagement)
    zone = engagement.timezone if engagement is not None else "UTC"
    header = (
        f"# Engagement report: {engagement_name}\n\n"
        f"- Scope: all sessions ({session_count})\n"
        f"- Generated: {generated_label}\n"
        f"- Times shown in: {zone}\n"
        f"- Approved findings (deduped): {len(findings)}"
    )
    scope = engagement.describe() if engagement is not None else ""
    return join_blocks(
        header,
        labeled("Executive summary", _severity_summary(findings), heading=True),
        labeled("Scope", f"```\n{scope}\n```" if scope else "", heading=True),
        labeled("Methodology & limitations", _LIMITATIONS, heading=True),
        labeled("Affected assets", _affected_table(findings), heading=True),
        labeled(
            "Findings", _findings(findings, refs, evidence, media_root), heading=True
        ),
    )


def write_report(  # noqa: PLR0913 -- a report write is composed from its ledger parts
    session_id: str,
    ledger: Ledger,
    reports_dir: Path,
    *,
    engagement: EngagementConfig | None = None,
    media_root: Path | None = None,
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
    # A report contains only approved findings; the rest are counted, not shown.
    findings = ledger.approved_findings_for(session_id)
    excluded = len(ledger.findings_for(session_id)) - len(findings)
    refs = {f.id: ledger.finding_refs_for(f.id) for f in findings}
    evidence = {f.id: ledger.finding_evidence_for(f.id) for f in findings}

    reports_dir = ensure_dir(reports_dir)
    prefix = f"{slug(session.engagement_name)}-{session_id[:8]}-"
    # Sort by write time, not name, so the ordering is robust to stamp collisions.
    prior = sorted(reports_dir.glob(f"{prefix}*.md"), key=lambda p: p.stat().st_mtime)
    changelog_path = reports_dir / "CHANGELOG.md"

    # One generated-at stamp, shared by the Markdown body and the PDF footer, so a
    # later PDF re-render cannot disagree with the document it renders.
    generated_label = _local_stamp(now_iso(), engagement)
    body = render_report(
        session,
        commands,
        findings,
        engagement=engagement,
        generated_label=generated_label,
        refs=refs,
        evidence=evidence,
        media_root=media_root,
        revision=len(prior) + 1,
        previous=prior[-1].name if prior else None,
        excluded=excluded,
        changelog=changelog_path.exists(),
    )

    base = reports_dir / f"{prefix}{file_stamp()}"
    md_path = base.with_suffix(".md")
    if md_path.exists():  # a second report in the same clock second -- keep both
        base = reports_dir / f"{prefix}{file_stamp()}-r{len(prior) + 1}"
        md_path = base.with_suffix(".md")
    md_path.write_text(body, encoding="utf-8")
    # A unified diff against the previous revision -- the report's revision notes.
    if prior:
        _write_diff(prior[-1], md_path, body)
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


def write_engagement_report(  # noqa: PLR0913 -- a report write is composed from its ledger parts
    engagement_name: str,
    ledger: Ledger,
    reports_dir: Path,
    *,
    engagement: EngagementConfig | None = None,
    media_root: Path | None = None,
    pdf: bool = False,
) -> Path | tuple[Path, Path]:
    """Write the cross-session, deduplicated engagement report (audit E5).

    Aggregates every session's approved findings for ``engagement_name``, deduped by
    the ledger, into one client deliverable under ``reports_dir``. Markdown is the
    canonical artifact; ``pdf=True`` also paints a sibling PDF and returns both.
    """
    findings = ledger.approved_findings_for_engagement(engagement_name)
    refs = {f.id: ledger.finding_refs_for(f.id) for f in findings}
    evidence = {f.id: ledger.finding_evidence_for(f.id) for f in findings}
    session_count = sum(
        1 for s in ledger.sessions() if s.engagement_name == engagement_name
    )
    reports_dir = ensure_dir(reports_dir)
    generated_label = _local_stamp(now_iso(), engagement)
    body = render_engagement_report(
        engagement_name,
        findings,
        engagement=engagement,
        generated_label=generated_label,
        refs=refs,
        evidence=evidence,
        media_root=media_root,
        session_count=session_count,
    )
    base = reports_dir / f"{slug(engagement_name)}-engagement-{file_stamp()}"
    md_path = base.with_suffix(".md")
    if md_path.exists():  # a second report in the same clock second -- keep both
        base = reports_dir / f"{slug(engagement_name)}-engagement-{file_stamp()}-b"
        md_path = base.with_suffix(".md")
    md_path.write_text(body, encoding="utf-8")
    if not pdf:
        return md_path
    from skuggi.persistence import pdf as pdf_mod

    pdf_path = pdf_mod.markdown_to_pdf(
        body,
        base.with_suffix(".pdf"),
        title=engagement_name,
        generated_label=f"Generated {generated_label}",
    )
    return md_path, pdf_path


def _write_diff(previous: Path, new_md: Path, new_body: str) -> Path:
    """Write a unified diff of the previous report vs the new one (revision notes)."""
    old_body = previous.read_text(encoding="utf-8")
    diff = difflib.unified_diff(
        old_body.splitlines(keepends=True),
        new_body.splitlines(keepends=True),
        fromfile=previous.name,
        tofile=new_md.name,
    )
    diff_path = new_md.with_suffix(".diff")
    diff_path.write_text("".join(diff), encoding="utf-8")
    return diff_path


def append_changelog(reports_dir: Path, note: str) -> Path:
    """Append a timestamped operator note to the engagement's report changelog."""
    reports_dir = ensure_dir(reports_dir)
    path = reports_dir / "CHANGELOG.md"
    header = "" if path.exists() else "# Report changelog\n\n"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"{header}- {now_iso()} — {note.strip()}\n")
    return path


def report_written_lines(result: Path | tuple[Path, Path]) -> list[str]:
    """Describe what :func:`write_report` produced, for either front-end.

    Keeps the "report written / pdf written" wording identical across the REPL
    and the daemon instead of each formatting the ``Path | tuple`` return. A sibling
    ``.diff`` (the revision notes vs the previous report) is reported when present.
    """
    md_path = result[0] if isinstance(result, tuple) else result
    lines = [f"report written: {md_path}"]
    if isinstance(result, tuple):
        lines.append(f"pdf written: {result[1]}")
    diff_path = md_path.with_suffix(".diff")
    if diff_path.exists():
        lines.append(f"revision diff: {diff_path}")
    return lines
