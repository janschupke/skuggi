"""Scope-promotion candidates discovered by the OSINT loop (audit E17).

OSINT resolves hosts (a subdomain's A record, an infrastructure IP) that fall
inside an authorized network but are not yet in the engagement's ``allowed_hosts``,
so the command guard still blocks them -- the recon -> scan loop never closes. This
module computes those candidates as a pure function over the collected corpus; the
verifier surfaces them as a *proposal* the operator applies through the gated,
non-grantable ``set engagement scope`` flow (never auto-applied, so an
authorization change is always a deliberate, confirmed act -- audit C4).
"""

from __future__ import annotations

from collections.abc import Sequence

from skuggi.common.netscope import in_cidr, is_ip
from skuggi.engagement.scope import EngagementConfig
from skuggi.intel.schema import IntelResult


def _candidate_ips(results: Sequence[IntelResult]) -> list[str]:
    """Every IP literal in the corpus (an item value, or an ``ip`` attribute)."""
    found: list[str] = []
    for result in results:
        for item in result.items:
            for raw in (item.value, item.attributes.get("ip", "")):
                token = raw.strip()
                if token and is_ip(token):
                    found.append(token)
    return found


def promotable_hosts(
    results: Sequence[IntelResult], engagement: EngagementConfig | None
) -> list[str]:
    """Discovered IPs inside an authorized network but not yet in ``allowed_hosts``.

    Deterministic and sorted-unique. An engagement with no ``target_networks`` has
    no authorization boundary to promote within, so nothing is promotable. A host
    already in ``allowed_hosts`` is omitted (the guard already reaches it).
    """
    if engagement is None or not engagement.target_networks:
        return []
    allowed = engagement.allowed_hosts
    promotable: set[str] = set()
    for ip in _candidate_ips(results):
        if ip in allowed:
            continue
        if any(in_cidr(ip, net) for net in engagement.target_networks):
            promotable.add(ip)
    return sorted(promotable)
