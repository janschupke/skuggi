"""The OSINT boundary: the one guard that authorizes a reconnaissance task.

The command guard (``skuggi.engagement.guard``) answers *is this shell command in
the network/host scope*; this answers *is this OSINT task in the OSINT scope*. It
is a separate module because OSINT acts on *subjects* (organizations, apex domains,
people, GitHub orgs) and draws on third-party *sources*, not IPs and tools -- a
different correctness centrepiece that changes for a different reason.

Same discipline as the command guard: an ordered, deny-by-default ``GuardVerdict``
chain, the first failing gate wins, and anything it cannot prove in scope is
denied. No LLM is in this path. The source's risk tier is a static fact
(:data:`SOURCE_TIER`) -- passive HTTP sources are ``recon``, browser/scraper
sources are ``active`` -- mirroring ``risk._METHOD_TIER`` for commands.

The guard takes the task's primitives (``source``/``subject``) rather than an
``OsintTask`` object so this stays in the ``engagement`` layer with no edge up into
the ``osint`` package; the OSINT collector node unpacks a task when it calls here.
"""

from __future__ import annotations

from skuggi.engagement.guard import GuardVerdict
from skuggi.engagement.scope import OsintScope, OsintSource
from skuggi.tooling.registry import RiskTier

# Each OSINT source's intrinsic risk tier. Passive sources query a third party
# *about* the subject and never touch it (``recon``); the browser/scraper sources
# drive a real session against the subject's surface (``active``). Shodan is a
# passive database lookup, so it is ``recon`` despite needing a key. A source
# missing here is treated as ``active`` by ``_source_tier`` (deny-by-default risk).
SOURCE_TIER: dict[OsintSource, RiskTier] = {
    "crtsh": RiskTier.recon,
    "dns": RiskTier.recon,
    "github": RiskTier.recon,
    "websearch": RiskTier.recon,
    "shodan": RiskTier.recon,
    "linkedin": RiskTier.active,
    "ats": RiskTier.active,
    "social": RiskTier.active,
}


def source_tier(source: OsintSource) -> RiskTier:
    """The risk tier of an OSINT source (unknown -> ``active``, deny-by-default)."""
    return SOURCE_TIER.get(source, RiskTier.active)


def check_osint_task(
    source: OsintSource, subject: str, osint: OsintScope
) -> GuardVerdict:
    """Is this OSINT task inside the engagement's OSINT *scope*?

    The deny-chain, cheapest first: the source must be enabled, the subject must
    be in scope, and a passive-only engagement forbids an active source. Passing
    every gate is in scope. These are HARD_BLOCK boundaries -- a denial here is
    not operator-overridable without editing the scope.

    The autonomous *ceiling* is deliberately NOT a gate here. Like the command
    path (``agent.executor``), the ceiling is a separate ESCALATION decision made
    by the caller after scope passes: an in-scope source above the ceiling is held
    and surfaced to the operator, not denied. Keeping the two apart lets both
    autonomous paths classify refusals the same way (``security.boundaries``).
    """
    if source not in osint.enabled_sources:
        return GuardVerdict(False, f"OSINT source {source!r} is not enabled")
    if not osint.subject_in_scope(subject):
        return GuardVerdict(
            False, f"subject {subject!r} is outside the authorized OSINT scope"
        )
    if osint.passive_only and source_tier(source) != RiskTier.recon:
        return GuardVerdict(
            False, f"source {source!r} is active; this engagement is passive-only"
        )
    return GuardVerdict(True, "in scope")
