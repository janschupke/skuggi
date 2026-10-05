"""LinkedIn company collector (active: Apify actor or browser render).

Pulls a company's public footprint -- a summary, open jobs (as role items), and an
inferred tech stack from the role text. Prefers an Apify actor when configured
(structured job rows), else a Playwright render of the public company page. Active
tier, so a passive-only engagement holds it back (see osint_guard).
"""

from __future__ import annotations

import re

from skuggi.engagement.scope import OsintSource
from skuggi.intel.collectors.base import CollectContext, empty_result
from skuggi.osint.collectors import scrape
from skuggi.osint.schema import OsintItem, OsintResult, OsintTask

# A compact, high-signal tech vocabulary scanned out of role text -- enough to
# sketch a stack without pretending to be exhaustive. Lower-cased word matches.
_TECH = (
    "python",
    "java",
    "javascript",
    "typescript",
    "go",
    "golang",
    "rust",
    "ruby",
    "php",
    "c++",
    "kotlin",
    "swift",
    "scala",
    "react",
    "angular",
    "vue",
    "node",
    "django",
    "rails",
    "spring",
    "kubernetes",
    "docker",
    "terraform",
    "aws",
    "gcp",
    "azure",
    "postgres",
    "postgresql",
    "mysql",
    "mongodb",
    "redis",
    "kafka",
    "graphql",
    "elasticsearch",
)
_TAG = re.compile(r"<[^>]+>")


class LinkedInCollector:
    """Company summary, open roles, and an inferred tech stack."""

    source: OsintSource = "linkedin"
    # Driver-capable (Apify when configured, else a Playwright render): the
    # collect step runs it serially so a parallel superstep never pools browsers.
    uses_driver = True

    def available(self, ctx: CollectContext) -> bool:
        """Usable when Apify is configured for linkedin or a browser driver exists."""
        return scrape.active_available(ctx, "linkedin")

    def collect(self, task: OsintTask, ctx: CollectContext) -> OsintResult:
        """Collect roles + tech, from an Apify actor or a rendered company page."""
        rows = scrape.run_actor(ctx, "linkedin", {"company": task.subject})
        if rows is not None:
            return _from_rows(task, rows)
        url = f"https://www.linkedin.com/company/{task.subject}/"
        html = scrape.rendered_html(ctx, url)
        if html is None:
            return empty_result(task, "linkedin unavailable (no apify actor or driver)")
        return _from_html(task, html)


def _tech_items(text: str) -> list[OsintItem]:
    words = set(re.findall(r"[a-z+]+", text.lower()))
    return [OsintItem(kind="tech", value=t) for t in _TECH if t in words]


def _from_rows(task: OsintTask, rows: list[dict[str, object]]) -> OsintResult:
    roles = scrape.items_from_dataset(rows, kind="role", main_field="title")
    text = " ".join(str(v) for row in rows for v in row.values())
    items = (*roles, *_tech_items(text))
    return OsintResult(
        task_id=task.id,
        source="linkedin",
        subject=task.subject,
        items=items,
        note=f"{len(roles)} open roles via apify",
    )


def _from_html(task: OsintTask, html: str) -> OsintResult:
    text = _TAG.sub(" ", html)
    items = tuple(_tech_items(text))
    return OsintResult(
        task_id=task.id,
        source="linkedin",
        subject=task.subject,
        items=items,
        note=f"rendered company page; {len(items)} tech signals",
    )
