"""OSINT scheduling: the shared DAG walk plus the OSINT coverage floor.

The dependency-aware task selection (``remaining``/``select_ready``/``is_blocked``)
is subsystem-agnostic and lives in :mod:`skuggi.intel.scheduler`; it is re-exported
here so the OSINT nodes keep importing it from one place. ``coverage_gaps`` is the
OSINT-specific backstop -- it maps the generic source-coverage floor onto the OSINT
scope's enabled sources.
"""

from __future__ import annotations

from skuggi.engagement.scope import OsintScope, OsintSource
from skuggi.intel.scheduler import coverage_gaps as _intel_coverage_gaps
from skuggi.intel.scheduler import is_blocked, remaining, select_ready
from skuggi.osint.schema import OsintResult

__all__ = ["coverage_gaps", "is_blocked", "remaining", "select_ready"]


def coverage_gaps(results: list[OsintResult], osint: OsintScope) -> list[OsintSource]:
    """Enabled OSINT sources that produced no data yet (deterministic floor).

    A thin OSINT wrapper over ``intel.scheduler.coverage_gaps``: it passes the
    scope's ``enabled_sources`` and narrows the generic source names back to
    ``OsintSource`` for the verifier request block.
    """
    enabled = {str(s): s for s in osint.enabled_sources}
    gaps = _intel_coverage_gaps(list(results), list(enabled))
    return [enabled[name] for name in gaps]
