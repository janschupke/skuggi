"""The research boundary: public-sources-only, no offensive scanning, ever.

Research is engagement-independent, so there is no subject scope to check -- a
research subject is a free public identifier ("wordpress 6.x"), not an authorized
asset. What this guard DOES enforce is the one hard invariant: every research
source is a passive, public-data ``recon``-tier query. A task naming anything that
is not a known :data:`skuggi.research.schema.RESEARCH_SOURCES` member is denied, so
there is no code path from the research loop to an active/offensive source.

Mirrors ``engagement.osint_guard`` in shape (a deny-by-default ``GuardVerdict``)
but is far simpler: the source allow-list IS the boundary.
"""

from __future__ import annotations

from skuggi.engagement.guard import GuardVerdict
from skuggi.research.schema import RESEARCH_SOURCES
from skuggi.tooling.registry import RiskTier

# Every research source is recon-tier by construction (public, passive). Kept as a
# table so the invariant is explicit and a test can assert no source exceeds it.
RESEARCH_SOURCE_TIER = dict.fromkeys(RESEARCH_SOURCES, RiskTier.recon)


def check_research_source(source: str) -> GuardVerdict:
    """Is ``source`` a known, public, recon-tier research source?

    The whole research boundary: an unknown source is denied (deny-by-default), so
    the loop can never dispatch to anything outside the passive public-data set.
    """
    if source not in RESEARCH_SOURCE_TIER:
        return GuardVerdict(False, f"unknown research source {source!r}")
    return GuardVerdict(True, "public source")
