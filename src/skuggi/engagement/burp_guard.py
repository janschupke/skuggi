"""The Burp boundary: the guard that authorizes one agent-driven Burp action.

The command guard (:mod:`skuggi.engagement.guard`) answers *is this shell command
in scope*; the OSINT guard answers *is this subject/source in the OSINT scope*;
this answers *may the agent drive this Burp action*. Burp differs from both: a
write action (repeater/active-scan/intruder) sends real attack traffic to a host,
so it must clear the command guard's network/host boundary -- NOT the OSINT-style
subject check. It reuses that boundary via
:func:`skuggi.engagement.guard.host_in_scope`.

Same discipline as the other guards: an ordered, deny-by-default ``GuardVerdict``
chain, first failing gate wins, no LLM in the path. The autonomous *ceiling* is
deliberately NOT a gate here -- like the command and OSINT paths, an in-scope
action above the ceiling is an ESCALATION the caller holds as ``proposed``, not a
denial. The guard takes primitives (``action``/``target_host``) rather than a
Burp object so it stays in the ``engagement`` layer with no edge up into
``skuggi.burp`` beyond the leaf model vocabulary.
"""

from __future__ import annotations

from skuggi.burp.models import BurpAction
from skuggi.engagement.guard import GuardVerdict, host_in_scope
from skuggi.engagement.scope import EngagementConfig
from skuggi.tooling.registry import RiskTier

# The actions that send real traffic to the target host and so must clear the
# network/host scope boundary (everything else reads Burp's own state or edits
# Burp's config).
TRAFFIC_ACTIONS: frozenset[BurpAction] = frozenset(
    {"repeater", "active_scan", "intruder"}
)

# Each action's intrinsic risk tier (mirrors osint_guard.SOURCE_TIER and
# risk._METHOD_TIER). Reads + scope push are recon; match/replace + repeater +
# active scan are active; an intruder fuzzing run is intrusive. An unknown action
# is intrusive (deny-by-default risk).
ACTION_TIER: dict[BurpAction, RiskTier] = {
    "proxy_history": RiskTier.recon,
    "scan_issues": RiskTier.recon,
    "scan_status": RiskTier.recon,
    "set_scope": RiskTier.recon,
    "match_replace": RiskTier.active,
    "repeater": RiskTier.active,
    "active_scan": RiskTier.active,
    "intruder": RiskTier.intrusive,
}


def action_tier(action: BurpAction) -> RiskTier:
    """The risk tier of a Burp action (unknown -> ``intrusive``, deny-by-default)."""
    return ACTION_TIER.get(action, RiskTier.intrusive)


def check_burp_action(
    action: BurpAction, target_host: str, engagement: EngagementConfig
) -> GuardVerdict:
    """Is this Burp action inside the engagement's Burp *scope*?

    The deny-chain, cheapest first: the connector must be enabled, the action must
    be on the scope's allow-list, a traffic-sending action must clear the
    network/host boundary, and a passive-only scope forbids any active-tier action.
    Passing every gate is in scope. These are HARD_BLOCK boundaries. The ceiling is
    the caller's separate ESCALATION decision (see :mod:`skuggi.security.boundaries`).
    """
    burp = engagement.burp
    if burp is None:
        return GuardVerdict(
            False, "the Burp connector is not enabled for this engagement"
        )
    if action not in burp.allowed_actions:
        return GuardVerdict(False, f"burp action {action!r} is not permitted by scope")
    if action in TRAFFIC_ACTIONS:
        verdict = host_in_scope(target_host, engagement)
        if not verdict.allowed:
            return verdict
    if burp.passive_only and action_tier(action) is not RiskTier.recon:
        return GuardVerdict(
            False, f"action {action!r} is active; this Burp scope is passive-only"
        )
    return GuardVerdict(True, "in scope")
