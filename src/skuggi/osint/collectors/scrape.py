"""Shared backend dispatch for the active (browser/scraper) OSINT sources.

LinkedIn, ATS and social collection differ only in what they parse; how they
*fetch* -- an Apify actor when configured, else a local Playwright render -- is the
same decision, so it lives here. ``active_available`` is the shared ``available``
check; ``scrape`` picks the backend; ``items_from_dataset`` maps generic Apify rows
to items. All best-effort: a dead backend yields ``None``/empty, never an exception.
"""

from __future__ import annotations

from skuggi.common.logs import get_logger
from skuggi.engagement.scope import OsintSource
from skuggi.intel.collectors.base import CollectContext
from skuggi.osint.schema import OsintItem

log = get_logger(__name__)


def actor_for(ctx: CollectContext, source: OsintSource) -> str | None:
    """The configured Apify actor id for ``source`` (None when unset)."""
    return ctx.config_for(source).get("apify_actor") or None


def active_available(ctx: CollectContext, source: OsintSource) -> bool:
    """An active source is usable when Apify is configured OR a driver exists."""
    has_apify = ctx.apify_run is not None and actor_for(ctx, source) is not None
    return has_apify or ctx.driver_factory is not None


def rendered_html(ctx: CollectContext, url: str) -> str | None:
    """Render ``url`` through the injected driver, or None when none/err."""
    if ctx.driver_factory is None:
        return None
    driver = ctx.driver_factory()
    try:
        return driver.fetch_html(url)
    except Exception:
        log.warning("driver render of %s failed", url, exc_info=True)
        return None
    finally:
        driver.close()


def run_actor(
    ctx: CollectContext, source: OsintSource, run_input: dict[str, object]
) -> list[dict[str, object]] | None:
    """Run the source's configured Apify actor, or None when unavailable."""
    actor = actor_for(ctx, source)
    if ctx.apify_run is None or actor is None:
        return None
    return ctx.apify_run(actor, run_input)


def items_from_dataset(
    rows: list[dict[str, object]], *, kind: str, main_field: str
) -> tuple[OsintItem, ...]:
    """Map Apify dataset rows to items: ``main_field`` is the value, rest attributes."""
    items: list[OsintItem] = []
    for row in rows:
        value = str(row.get(main_field, "")).strip()
        if not value:
            continue
        attributes = {
            k: str(v) for k, v in row.items() if k != main_field and v is not None
        }
        items.append(OsintItem(kind=kind, value=value, attributes=attributes))
    return tuple(items)
