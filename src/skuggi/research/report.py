"""Render a research run's structured profile into a Markdown report.

The research loop's own output writer -- distinct from
``skuggi.persistence.reports`` (which renders ledger findings for a pentest
engagement). This takes the verifier's :class:`ResearchProfile` plus the raw
collected corpus and writes a timestamped Markdown briefing under the resolved
output root (the engagement's ``research_dir`` or a cwd fallback). The body is run
through the session redactor before it touches disk, and the path is confined with
``common.paths.confine_under``.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from skuggi.common.clock import file_stamp, now_iso
from skuggi.common.paths import confine_under, ensure_parent
from skuggi.common.text import slug
from skuggi.intel.schema import IntelResult
from skuggi.research.schema import ResearchProfile


def render_report(
    request: str, profile: ResearchProfile | None, results: list[IntelResult]
) -> str:
    """Compose the Markdown research briefing from the profile and the corpus."""
    subject = profile.subject if profile else request
    blocks = [
        f"# Research: {subject}",
        f"_generated {now_iso()}_",
        f"**Request:** {request}",
    ]
    if profile:
        blocks.append(_profile_block(profile))
    blocks.append(_sources_block(results))
    return "\n\n".join(b for b in blocks if b) + "\n"


def _profile_block(p: ResearchProfile) -> str:
    lines = ["## Summary"]
    if p.latest_version:
        lines.append(f"- **Latest version:** {p.latest_version}")
    if p.commonly_deployed_versions:
        lines.append(
            f"- **Commonly deployed:** {', '.join(p.commonly_deployed_versions)}"
        )
    if p.built_on:
        lines.append(f"- **Built on / subsystems:** {', '.join(p.built_on)}")
    if p.notes:
        lines.append(f"\n{p.notes}")
    if p.known_vulnerabilities:
        lines.append("\n## Known vulnerabilities\n")
        lines.append("| ID | Severity | Title | Link | Source |")
        lines.append("| --- | --- | --- | --- | --- |")
        for v in p.known_vulnerabilities:
            link = f"[{v.url}]({v.url})" if v.url else ""
            lines.append(f"| {v.id} | {v.severity} | {v.title} | {link} | {v.source} |")
    return "\n".join(lines)


def _sources_block(results: list[IntelResult]) -> str:
    if not results:
        return ""
    header = "## Collected sources\n"
    rows = [
        f"- **{r.source}** ({r.subject}): {len(r.items)} items — {r.note}"
        for r in results
    ]
    return "\n".join([header, *rows])


def write_research_report(
    output_root: Path,
    request: str,
    profile: ResearchProfile | None,
    results: list[IntelResult],
    *,
    clean: Callable[[str], str],
) -> Path:
    """Render and write the research report; return the artifact path.

    The filename is ``<subject-slug>-<stamp>.md`` under ``output_root`` (confined).
    ``clean`` is the session redactor, applied to the whole body before writing.
    """
    subject = profile.subject if profile else request
    path = confine_under(output_root, f"{slug(subject)}-{file_stamp()}.md")
    body = render_report(request, profile, results)
    ensure_parent(path)
    path.write_text(clean(body), encoding="utf-8")
    return path
