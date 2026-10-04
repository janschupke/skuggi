"""The OSINT collector registry: one handler per source, looked up by name.

``default_collectors`` is the built-in set (the tool-registry analogue). The OSINT
graph filters it at dispatch by *authorized* (the source is in the engagement's
``enabled_sources`` and the task passes ``check_osint_task``) AND *available* (the
collector's deps/credentials are present). A source authorized but whose collector
is unavailable becomes a recorded coverage gap, never an exception.

Browser-driven (LinkedIn/ATS) and Apify collectors register here too but gate
themselves behind ``available()`` so the HTTP-only install still runs the loop.
"""

from __future__ import annotations

from skuggi.engagement.scope import OsintSource
from skuggi.osint.collectors.ats import ATSCollector
from skuggi.osint.collectors.base import (
    CollectContext,
    Collector,
    Driver,
    Fetch,
    HttpRequest,
    default_fetch,
    empty_result,
)
from skuggi.osint.collectors.crtsh import CrtShCollector
from skuggi.osint.collectors.dns import DnsCollector
from skuggi.osint.collectors.github import GitHubCollector
from skuggi.osint.collectors.linkedin import LinkedInCollector
from skuggi.osint.collectors.shodan import ShodanCollector
from skuggi.osint.collectors.social import SocialCollector
from skuggi.osint.collectors.websearch import WebSearchCollector

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


def default_collectors() -> tuple[Collector, ...]:
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
    source: OsintSource, collectors: tuple[Collector, ...]
) -> Collector | None:
    """The collector handling ``source``, or None when none is registered."""
    return next((c for c in collectors if c.source == source), None)
