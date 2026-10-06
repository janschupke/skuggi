"""Shared IP / CIDR scope primitives.

The scope guard, the pivot router, the OSINT host-promotion check and the egress
gate all answer the same two questions about a token -- is it a literal IP, and
does an address fall inside a CIDR -- and had each hand-rolled the ``ipaddress``
try/except with subtly different error handling (``_is_ipv4`` that also accepted
IPv6, a ``TypeError`` guard for a cross-version ``in`` that never raises). These
are the most correctness-sensitive predicates in the harness, so they live once
here and fail identically everywhere: any parse error denies (returns ``False``),
never raises.
"""

from __future__ import annotations

import ipaddress

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def is_ip(token: str) -> bool:
    """Whether `token` is a literal IPv4 or IPv6 address (not a hostname)."""
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def in_cidr(addr: str | IpAddress, cidr: str | IpNetwork) -> bool:
    """Whether `addr` falls inside `cidr`; any malformed input is ``False``.

    Both arguments may be a string (parsed here, ``cidr`` non-strict so host bits
    are allowed) or an already-parsed object. A version mismatch between the two
    is simply ``False`` -- ``ip in net`` never raises on it -- and a parse failure
    denies rather than raising, so a caller cannot accidentally let a bad token
    through by forgetting a guard.
    """
    try:
        ip = ipaddress.ip_address(addr) if isinstance(addr, str) else addr
        net = (
            ipaddress.ip_network(cidr, strict=False) if isinstance(cidr, str) else cidr
        )
    except ValueError:
        return False
    return ip in net
