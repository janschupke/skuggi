"""The OSINT collector registry: one handler per source, looked up by name.

``default_collectors`` is the built-in set. The OSINT graph filters it at dispatch
by *authorized* (the source is in the engagement's ``enabled_sources`` and the task
passes ``check_osint_task``) AND *available* (the collector's deps/credentials are
present). A source authorized but whose collector is unavailable becomes a recorded
coverage gap, never an exception.

The source-agnostic handlers (web search, GitHub) are shared and imported from
``skuggi.intel.collectors``; the subject-centric ones (certificate transparency,
DNS, Shodan, and the browser/Apify scrapers) are OSINT-specific and live here.
"""

from __future__ import annotations

from skuggi.engagement.scope import OsintSource
from skuggi.intel.collectors import (
    CollectContext,
    Collector,
    Driver,
    Fetch,
    GitHubCollector,
    HttpRequest,
    WebSearchCollector,
    default_fetch,
    empty_result,
)
from skuggi.osint.collectors.ats import ATSCollector
from skuggi.osint.collectors.crtsh import CrtShCollector
from skuggi.osint.collectors.dns import DnsCollector
from skuggi.osint.collectors.linkedin import LinkedInCollector
from skuggi.osint.collectors.shodan import ShodanCollector
from skuggi.osint.collectors.social import SocialCollector
from skuggi.osint.schema import OsintTask

__all__ = [
    "CollectContext",
    "Collector",
    "Driver",
    "Fetch",
    "HttpRequest",
    "collector_for",
    "default_collectors",
    "default_fetch",
    "empty_result",
]


def default_collectors() -> tuple[Collector[OsintTask], ...]:
    """The built-in collector set (one per supported source)."""
    return (
        CrtShCollector(),
        DnsCollector(),
        GitHubCollector(),
        WebSearchCollector(),
        ShodanCollector(),
        LinkedInCollector(),
        ATSCollector(),
        SocialCollector(),
    )


def collector_for(
    source: OsintSource, collectors: tuple[Collector[OsintTask], ...]
) -> Collector[OsintTask] | None:
    """The collector handling ``source``, or None when none is registered."""
    return next((c for c in collectors if c.source == source), None)
