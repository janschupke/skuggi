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

from collections.abc import Sequence
from dataclasses import dataclass

from skuggi.common.netscope import in_cidr, is_ip
from skuggi.common.text import split_csv
from skuggi.persistence.ledger_schema import FootholdRow


@dataclass(frozen=True, slots=True)
class Route:
    """How to reach a target: directly (``foothold is None``) or via a foothold."""

    foothold: FootholdRow | None


def _reaches(foothold: FootholdRow, target: str) -> bool:
    """Whether `foothold` declares it can reach `target` (exact host or in a CIDR)."""
    if target in split_csv(foothold.reachable_hosts):
        return True
    if not is_ip(target):
        return False  # a hostname not listed exactly is not reached by a CIDR
    return any(in_cidr(target, cidr) for cidr in split_csv(foothold.reachable_networks))


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


def select_route(targets: Sequence[str], footholds: Sequence[FootholdRow]) -> Route:
    """Route a command by its first target that must go through a foothold, else direct.

    A command may name several targets; the command is pivoted as soon as any one of
    them is only reachable via a foothold (the deeper target drives the path).
    """
    for target in targets:
        route = route_for(target, footholds)
        if route.foothold is not None:
            return route
    return Route(foothold=None)


def wrap_command(foothold: FootholdRow, inner_command: str) -> str:
    """Wrap `inner_command` so it runs through `foothold` (template substitution).

    The operator-supplied ``template`` places the inner command via a ``{cmd}``
    marker (``ssh root@host -- {cmd}``, a webshell curl, ``proxychains4 -q {cmd}``);
    a template with no marker is treated as a prefix wrapper. An empty template
    leaves the command unchanged. The result is still in placeholder form -- any
    ``«KIND:id»`` secret (the foothold's own, or one in the inner command) is
    rehydrated by the caller just before exec, exactly like a direct command.
    """
    template = foothold.template.strip()
    if not template:
        return inner_command
    if "{cmd}" in template:
        return template.replace("{cmd}", inner_command)
    return f"{template} {inner_command}"
