"""Social-presence collector (active: Apify actor or browser render).

Discovers a subject's public social profiles. Prefers an Apify actor when
configured, else a Playwright render of a search/results page whose profile links
are extracted. Active tier. Best-effort: nothing found is an empty result.
"""

from __future__ import annotations

import re

from skuggi.engagement.scope import OsintSource
from skuggi.intel.collectors.base import CollectContext, empty_result
from skuggi.osint.collectors import scrape
from skuggi.osint.schema import OsintItem, OsintResult, OsintTask

# Well-known social hosts whose profile links are worth surfacing.
_SOCIAL_HOSTS = (
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "mastodon.social",
    "youtube.com",
    "github.com",
    "linkedin.com",
)
_LINK = re.compile(r'href="(https?://[^"]+)"', re.IGNORECASE)


class SocialCollector:
    """Public social-profile discovery for a subject."""

    source: OsintSource = "social"

    def available(self, ctx: CollectContext) -> bool:
        """Usable when Apify is configured for social or a browser driver exists."""
        return scrape.active_available(ctx, "social")

    def collect(self, task: OsintTask, ctx: CollectContext) -> OsintResult:
        """Collect social-profile links from an Apify actor or a rendered page."""
        rows = scrape.run_actor(ctx, "social", {"query": task.subject})
        if rows is not None:
            profiles = scrape.items_from_dataset(rows, kind="profile", main_field="url")
            return OsintResult(
                task_id=task.id,
                source="social",
                subject=task.subject,
                items=profiles,
                note=f"{len(profiles)} profiles via apify",
            )
        url = f"https://duckduckgo.com/html/?q={task.subject}+social+profile"
        html = scrape.rendered_html(ctx, url)
        if html is None:
            return empty_result(task, "social unavailable (no apify actor or driver)")
        return _from_html(task, html)


def _from_html(task: OsintTask, html: str) -> OsintResult:
    found = {
        link
        for link in _LINK.findall(html)
        if any(host in link.lower() for host in _SOCIAL_HOSTS)
    }
    items = tuple(OsintItem(kind="profile", value=link) for link in sorted(found))
    return OsintResult(
        task_id=task.id,
        source="social",
        subject=task.subject,
        items=items,
        note=f"{len(items)} social profiles",
    )
