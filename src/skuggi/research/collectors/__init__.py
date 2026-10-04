"""The research collector registry: one handler per public source.

``default_research_collectors`` is the built-in set. The research graph filters it
at dispatch by *known-source* (``research.scope.check_research_source``) AND
*available* (the collector's deps/credentials/local tools are present). A source
whose collector is unavailable -- e.g. ``searchsploit`` not installed -- becomes a
recorded coverage gap, never an exception.

The source-agnostic HTTP handlers (web search, GitHub) are shared and imported
from ``skuggi.intel.collectors``; the research-specific ones (versions, CVE,
Exploit-DB, and the optional local searchsploit/metasploit) live here.
"""

from __future__ import annotations

from skuggi.intel.collectors import (
    Collector,
    GitHubCollector,
    WebSearchCollector,
)
from skuggi.research.collectors.cve import CveCollector
from skuggi.research.collectors.exploitdb import ExploitDbCollector
from skuggi.research.collectors.metasploit import MetasploitCollector
from skuggi.research.collectors.searchsploit import SearchsploitCollector
from skuggi.research.collectors.versions import VersionsCollector
from skuggi.research.schema import ResearchSource, ResearchTask

__all__ = ["collector_for", "default_research_collectors"]


def default_research_collectors() -> tuple[Collector[ResearchTask], ...]:
    """The built-in research collector set (one per supported source)."""
    return (
        WebSearchCollector(),
        GitHubCollector(),
        VersionsCollector(),
        CveCollector(),
        ExploitDbCollector(),
        SearchsploitCollector(),
        MetasploitCollector(),
    )


def collector_for(
    source: ResearchSource, collectors: tuple[Collector[ResearchTask], ...]
) -> Collector[ResearchTask] | None:
    """The collector handling ``source``, or None when none is registered."""
    return next((c for c in collectors if c.source == source), None)
