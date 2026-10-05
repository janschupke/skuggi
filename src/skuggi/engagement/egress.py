"""The network-egress boundary: which hosts a fetch/tool may actually reach.

The engagement guard (:mod:`skuggi.engagement.guard`) answers *is this command
in scope* by parsing its argv; this answers the orthogonal *may this network
connection leave the box, and to where*. The two are different boundaries: a URL
chosen by the model (or planted in a scraped page a collector then follows) never
passes through ``check_command`` at all, so without this gate an OSINT/research
collector is an open SSRF primitive -- it would happily fetch
``http://169.254.169.254/`` (cloud metadata) or an internal ``10.x`` service.

Two postures:

* **public-recon** (``EgressPolicy.public_recon``) -- the OSINT and research
  loops. Their boundary is the *public* internet: everything is allowed EXCEPT
  SSRF-sensitive address space (loopback, link-local incl. the metadata IP,
  RFC-1918/ULA private, multicast, reserved). A public hostname that *resolves*
  into that space is denied, closing the DNS-indirection hole.
* **scope-bound** (``EgressPolicy.from_engagement``) -- reachability tied to the
  authorized scope: only the engagement's target networks / allowed hosts, minus
  the RoE exclusions. A private in-scope lab target IS reachable here (unlike
  public-recon), because it is explicitly authorized.

Deny-by-default throughout: anything the policy cannot positively clear -- an
unresolvable host, a mixed answer with one sensitive IP, an empty host -- is
refused. Resolution is a point-in-time check (a later connection could re-resolve
elsewhere -- classic TOCTOU/DNS-rebinding); pinning the resolved IP into the
connection is a follow-up, but resolving-and-checking already stops the common
literal-IP and resolves-to-metadata cases.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from skuggi.common.logs import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterable

    from skuggi.engagement.scope import EngagementConfig

log = get_logger(__name__)

_IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True, slots=True)
class EgressDecision:
    """Whether a host/URL may be reached, and why not when refused."""

    allowed: bool
    reason: str


def _is_sensitive(ip: _IpAddress) -> bool:
    """Whether `ip` is SSRF-sensitive address space that public recon must avoid.

    Covers loopback, link-local (incl. ``169.254.169.254`` cloud metadata),
    private (RFC-1918 / IPv6 ULA), multicast, reserved and the unspecified
    address. An IPv4-mapped IPv6 address is unwrapped and re-checked so
    ``::ffff:127.0.0.1`` cannot slip past.
    """
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return _is_sensitive(mapped)
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve(host: str) -> tuple[_IpAddress, ...] | None:
    """Every IP `host` resolves to (the host itself if it is a literal), or None.

    A literal IP is returned directly (no DNS). A name is resolved via
    ``getaddrinfo`` across both families; resolution failure yields ``None`` so
    the caller denies (a host it cannot resolve is one it cannot prove safe).
    """
    try:
        return (ipaddress.ip_address(host),)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return None
    out: list[_IpAddress] = []
    for info in infos:
        sockaddr = info[4]
        try:
            out.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    return tuple(out) or None


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    """What network destinations a fetch/tool is allowed to reach."""

    # When True, allow any public host and deny only SSRF-sensitive space
    # (the public-recon posture). When False, allow only the scope sets below.
    public_only: bool
    allowed_networks: tuple[_IpNetwork, ...] = ()
    allowed_hosts: frozenset[str] = frozenset()
    excluded_networks: tuple[_IpNetwork, ...] = ()
    excluded_hosts: frozenset[str] = frozenset()

    @classmethod
    def public_recon(cls) -> EgressPolicy:
        """The OSINT/research posture: public internet minus sensitive space."""
        return cls(public_only=True)

    @classmethod
    def from_engagement(cls, engagement: EngagementConfig) -> EgressPolicy:
        """A scope-bound policy: only authorized targets, minus RoE exclusions."""
        roe = engagement.rules_of_engagement
        return cls(
            public_only=False,
            allowed_networks=tuple(engagement.target_networks),
            allowed_hosts=frozenset(engagement.allowed_hosts),
            excluded_networks=tuple(roe.excluded_networks) if roe else (),
            excluded_hosts=frozenset(roe.excluded_hosts) if roe else frozenset(),
        )

    def _excluded(self, host: str, ips: Iterable[_IpAddress]) -> bool:
        if host in self.excluded_hosts:
            return True
        for ip in ips:
            if str(ip) in self.excluded_hosts:
                return True
            if any(ip in net for net in self.excluded_networks):
                return True
        return False

    def _in_scope(self, host: str, ips: Iterable[_IpAddress]) -> bool:
        if host in self.allowed_hosts:
            return True
        return any(ip in net for ip in ips for net in self.allowed_networks)

    def _public_verdict(self, host: str, ips: tuple[_IpAddress, ...]) -> EgressDecision:
        sensitive = [ip for ip in ips if _is_sensitive(ip)]
        if sensitive:
            return EgressDecision(
                False,
                f"host {host!r} resolves into non-public space "
                f"({sensitive[0]}); recon egress is public-only",
            )
        return EgressDecision(True, "public host")

    def check_host(self, host: str) -> EgressDecision:
        """Whether a connection to `host` is allowed under this policy."""
        if not host:
            return EgressDecision(False, "empty host")
        ips = _resolve(host)
        if ips is None:
            return EgressDecision(False, f"host {host!r} did not resolve")
        if self._excluded(host, ips):
            return EgressDecision(False, f"host {host!r} is on the egress deny-list")
        if self.public_only:
            return self._public_verdict(host, ips)
        if self._in_scope(host, ips):
            return EgressDecision(True, "in authorized scope")
        return EgressDecision(False, f"host {host!r} is outside the authorized scope")

    def check_url(self, url: str) -> EgressDecision:
        """Whether a request to `url`'s host is allowed (the fetch entry point)."""
        host = urlsplit(url).hostname or ""
        return self.check_host(host)

    def allows_url(self, url: str) -> bool:
        """Boolean form for the fetch guard; logs the reason on a deny."""
        decision = self.check_url(url)
        if not decision.allowed:
            log.warning("egress denied: %s (%s)", url, decision.reason)
        return decision.allowed
