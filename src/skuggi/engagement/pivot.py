"""Runtime reachability over footholds: route a target directly or through a host.

Scope (:class:`skuggi.engagement.scope.EngagementConfig`) stays the authorization
boundary -- what the operator is *allowed* to touch. A foothold layers reachability
on top: a compromised/jump host that names the networks and hosts it can *reach*.
``route_for`` decides, for a command's target, whether skuggi can hit it locally or
must run through a foothold -- the first foothold whose declared reach covers the
target wins (deterministic, registration order). It never changes authorization: a
target still has to pass the guard's scope check; this only picks the path.

The transport-wrapping that turns "run X" into "run X *through* the foothold" lives
alongside, consumed at the single execution choke point (see the executor).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass

from skuggi.persistence.ledger_schema import FootholdRow


@dataclass(frozen=True, slots=True)
class Route:
    """How to reach a target: directly (``foothold is None``) or via a foothold."""

    foothold: FootholdRow | None


def _split(csv: str) -> list[str]:
    return [part.strip() for part in csv.split(",") if part.strip()]


def _reaches(foothold: FootholdRow, target: str) -> bool:
    """Whether `foothold` declares it can reach `target` (exact host or in a CIDR)."""
    if target in _split(foothold.reachable_hosts):
        return True
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        return False  # a hostname not listed exactly is not reached by a CIDR
    for cidr in _split(foothold.reachable_networks):
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def route_for(target: str, footholds: Sequence[FootholdRow]) -> Route:
    """Pick the route to `target`: the first foothold that reaches it, else direct.

    An empty target or no footholds means a direct (local) route. The target is
    matched by exact hostname or by membership in a foothold's reachable network.
    """
    if target:
        for foothold in footholds:
            if _reaches(foothold, target):
                return Route(foothold=foothold)
    return Route(foothold=None)
