"""Shared collector surface: the protocol, the HTTP seam, and the shared handlers.

Re-exports the collector author's import surface from
:mod:`skuggi.intel.collectors.base`
plus the two source handlers both loops share (web search and GitHub). Subsystem-
specific collectors live in their own package (``skuggi.osint.collectors`` /
``skuggi.research.collectors``) and import this module for the base.
"""

from __future__ import annotations

from skuggi.intel.collectors.base import (
    ApifyRun,
    CollectContext,
    Collector,
    CollectTask,
    Driver,
    Fetch,
    HttpRequest,
    IntelItem,
    IntelResult,
    collector_for,
    default_fetch,
    empty_result,
)
from skuggi.intel.collectors.github import GitHubCollector
from skuggi.intel.collectors.websearch import WebSearchCollector

__all__ = [
    "ApifyRun",
    "CollectContext",
    "CollectTask",
    "Collector",
    "Driver",
    "Fetch",
    "GitHubCollector",
    "HttpRequest",
    "IntelItem",
    "IntelResult",
    "WebSearchCollector",
    "collector_for",
    "default_fetch",
    "empty_result",
]
