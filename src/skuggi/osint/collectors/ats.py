"""ATS / careers-listing collector (active: Apify actor or browser render).

Reads a company's open-position listings -- from an Apify actor when configured,
else a Playwright render of the careers URL (``source_config["ats"]["careers_url"]``,
or a conventional ``https://<subject>/careers``). Each posting becomes a ``role``
item. Active tier.
"""

from __future__ import annotations

import re

from skuggi.engagement.scope import OsintSource
from skuggi.intel.collectors.base import CollectContext, empty_result
from skuggi.osint.collectors import scrape
from skuggi.osint.schema import OsintItem, OsintResult, OsintTask

# Careers-page anchors that look like a job posting link (href + visible title).
_JOB_LINK = re.compile(
    r'<a[^>]+href="([^"]*(?:job|career|position|opening)[^"]*)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_TAG = re.compile(r"<[^>]+>")


class ATSCollector:
    """Open positions from an applicant-tracking / careers page."""

    source: OsintSource = "ats"

    def available(self, ctx: CollectContext) -> bool:
        """Usable when Apify is configured for ats or a browser driver exists."""
        return scrape.active_available(ctx, "ats")

    def collect(self, task: OsintTask, ctx: CollectContext) -> OsintResult:
        """Collect open roles from an Apify actor or a rendered careers page."""
        rows = scrape.run_actor(ctx, "ats", {"company": task.subject})
        if rows is not None:
            roles = scrape.items_from_dataset(rows, kind="role", main_field="title")
            return OsintResult(
                task_id=task.id,
                source="ats",
                subject=task.subject,
                items=roles,
                note=f"{len(roles)} open roles via apify",
            )
        url = (
            ctx.config_for("ats").get("careers_url")
            or f"https://{task.subject}/careers"
        )
        html = scrape.rendered_html(ctx, url)
        if html is None:
            return empty_result(task, "ats unavailable (no apify actor or driver)")
        return _from_html(task, html)


def _from_html(task: OsintTask, html: str) -> OsintResult:
    seen: dict[str, str] = {}
    for href, raw_title in _JOB_LINK.findall(html):
        title = _TAG.sub("", raw_title).strip()
        if title:
            seen.setdefault(title, href)
    items = tuple(
        OsintItem(kind="role", value=title, attributes={"url": href})
        for title, href in seen.items()
    )
    return OsintResult(
        task_id=task.id,
        source="ats",
        subject=task.subject,
        items=items,
        note=f"{len(items)} roles from the careers page",
    )
