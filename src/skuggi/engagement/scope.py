"""The engagement scope model: the authorized boundary, loaded from JSON.

The pydantic data definitions for one engagement -- what is in scope (networks,
hosts, tools, methods, time windows), the posture/framework awareness that is
advisory to the agent, and the CVSS environmental threat model. Split out of
``engagement.py`` from the parse+guard engine (:mod:`skuggi.engagement.guard`),
which reads these models but changes for a different reason. No I/O, no command
parsing -- just the shape of an engagement and the small queries over it.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, time
from typing import Literal, get_args
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    BaseModel,
    ConfigDict,
    IPvAnyNetwork,
    field_validator,
    model_validator,
)

from skuggi.agent.protocol import Methodology, Stance, Taxonomy
from skuggi.burp.models import BurpAction
from skuggi.tooling.registry import RiskTier, RiskTierField

# The OSINT reconnaissance sources the agentic OSINT loop can draw on. Each maps
# to a collector (see skuggi.osint.collectors); authorizing one here is what the
# OSINT guard checks (a source absent from ``enabled_sources`` is denied). Passive
# HTTP sources (crt.sh/dns/github/websearch) tier ``recon``; the browser/scraper
# sources (linkedin/ats/social) tier ``active``. See skuggi.engagement.osint_guard.
OsintSource = Literal[
    "crtsh", "dns", "github", "linkedin", "ats", "shodan", "websearch", "social"
]
OSINT_SOURCES: tuple[OsintSource, ...] = get_args(OsintSource)
# The Burp connector actions the agent can be authorized to drive (the scope
# allow-list vocabulary), derived from the one BurpAction definition.
BURP_ACTIONS: tuple[BurpAction, ...] = get_args(BurpAction)


class TimeWindow(BaseModel):
    """A daily allowed clock range, interpreted in the engagement timezone."""

    model_config = ConfigDict(frozen=True)

    start: time
    end: time

    def contains(self, moment: time) -> bool:
        """Whether `moment` falls in this window, including midnight-spanning."""
        if self.start <= self.end:
            return self.start <= moment <= self.end
        return moment >= self.start or moment <= self.end


class ThreatModel(BaseModel):
    """Per-engagement CVSS Environmental inputs -- the asset's security requirements.

    Present on a scope means environmental scoring is in play; its three
    requirements map to CVSS CR/IR/AR (``medium`` is the neutral default, so a
    threat model with all-medium is harmless but still switches environmental on).
    """

    model_config = ConfigDict(frozen=True)

    confidentiality_requirement: Literal["low", "medium", "high"] = "medium"
    integrity_requirement: Literal["low", "medium", "high"] = "medium"
    availability_requirement: Literal["low", "medium", "high"] = "medium"

    def cvss_environmental_metrics(self) -> dict[str, str]:
        """The CR/IR/AR CVSS metrics for this threat model (non-neutral levels only)."""
        level = {"low": "L", "medium": "M", "high": "H"}
        pairs = {
            "CR": level[self.confidentiality_requirement],
            "IR": level[self.integrity_requirement],
            "AR": level[self.availability_requirement],
        }
        # "M" is CVSS "Medium" == the neutral 1.0 weight; omit it to keep vectors lean.
        return {code: value for code, value in pairs.items() if value != "M"}


class OsintScope(BaseModel):
    """The authorized boundary for the agentic OSINT reconnaissance loop.

    A distinct scope dimension from the network/host boundary: OSINT acts on
    *subjects* (organizations, apex domains, people/usernames, GitHub orgs), not
    IPs, and queries third-party services *about* them. Present on an engagement
    means OSINT is enabled; absent (``EngagementConfig.osint is None``) means the
    ``osint`` loop refuses to run. The guard (``skuggi.engagement.osint_guard``)
    denies any task whose subject is outside this scope or whose source is not in
    ``enabled_sources`` -- deny-by-default, exactly like the command guard.
    """

    model_config = ConfigDict(frozen=True)

    organizations: frozenset[str] = frozenset()
    domains: frozenset[str] = frozenset()  # authorized apex domains
    people: frozenset[str] = frozenset()  # names / usernames
    github_orgs: frozenset[str] = frozenset()
    enabled_sources: frozenset[OsintSource] = frozenset()
    # When True, only passive (``recon``-tier) sources may run; a source whose
    # collector touches the subject (browser scraping) is held back. Independent
    # of ``autonomous_ceiling`` -- this is the passive/active boundary, the ceiling
    # is the auto-run-vs-propose line, and both must pass.
    passive_only: bool = True
    # The highest risk tier the OSINT loop runs without asking (mirrors
    # EngagementConfig.autonomous_ceiling for OSINT). Conservative by default:
    # passive HTTP recon auto-runs, browser/scraper sources escalate.
    autonomous_ceiling: RiskTierField = RiskTier.recon

    def subject_in_scope(self, subject: str) -> bool:
        """Whether ``subject`` is an authorized OSINT subject.

        A domain matches an authorized apex exactly or as a subdomain of it
        (``mail.acme.com`` under ``acme.com``); an org/person/github handle must
        be a listed member. Matching is case-insensitive. This is the OSINT
        analogue of the command guard's ``_target_in_scope`` -- a false allow
        here is a real authorization bug, so it is kept small and total.
        """
        needle = subject.strip().lower()
        if not needle:
            return False
        members = {
            m.lower() for m in (*self.organizations, *self.people, *self.github_orgs)
        }
        if needle in members:
            return True
        return any(
            needle == apex or needle.endswith(f".{apex}")
            for apex in (d.lower() for d in self.domains)
        )


class BurpScope(BaseModel):
    """The authorized boundary for the Burp Suite connector's agent-driven actions.

    Present on an engagement means the connector is enabled; absent
    (``EngagementConfig.burp is None``) means the ``burp`` loop/verb refuses to
    run. ``allowed_actions`` is a deny-by-default allow-list of what the agent may
    drive (reads like ``scan_issues`` and writes like ``repeater``); traffic-sending
    actions additionally clear the network/host scope (the command guard's boundary,
    via ``skuggi.engagement.burp_guard``). ``passive_only`` forbids active-traffic
    actions regardless of the ceiling; ``autonomous_ceiling`` is the auto-run-vs-
    propose line (both must pass), mirroring :class:`OsintScope`.
    """

    model_config = ConfigDict(frozen=True)

    allowed_actions: frozenset[BurpAction] = frozenset()
    passive_only: bool = True
    autonomous_ceiling: RiskTierField = RiskTier.active


class RulesOfEngagement(BaseModel):
    """Authorization metadata and operational controls for an engagement (E13/E14).

    Authorization is the paper trail a professional engagement must carry (who
    authorized it, the point of contact, the signed-auth reference, explicitly
    prohibited actions); the operational block records testing constraints (an
    out-of-scope exclusion deny-list, a scan-rate / concurrency / stealth posture,
    and the attack-source identity). Exclusions are the one part the guard ENFORCES
    (an excluded host is denied even if it also matches scope); the rest is advisory
    metadata rendered in the report header and surfaced to the operator.
    """

    model_config = ConfigDict(frozen=True)

    authorized_by: str = ""
    point_of_contact: str = ""
    authorization_reference: str = ""
    prohibited_actions: tuple[str, ...] = ()
    # Out-of-scope exclusions, checked BEFORE the allow-list (deny wins).
    excluded_networks: tuple[IPvAnyNetwork, ...] = ()
    excluded_hosts: frozenset[str] = frozenset()
    # Operational posture (advisory metadata unless a tool flag maps cleanly).
    max_scan_rate: str = ""
    max_concurrency: int | None = None
    attack_source: str = ""
    stealth: bool = False

    def is_empty(self) -> bool:
        """Whether nothing was recorded (so the report omits the RoE header)."""
        return not (
            self.authorized_by
            or self.point_of_contact
            or self.authorization_reference
            or self.prohibited_actions
            or self.excluded_networks
            or self.excluded_hosts
            or self.max_scan_rate
            or self.max_concurrency
            or self.attack_source
            or self.stealth
        )


class EngagementConfig(BaseModel):
    """The authorized boundary for one engagement, loaded from JSON."""

    model_config = ConfigDict(frozen=True)

    name: str
    timezone: str
    # Optional time bounds. ``None`` leaves that edge unbounded: both ``None``
    # means the engagement has no authorized-time window at all (the guard skips
    # the date/time check). A set bound must be timezone-aware (see ``_aware``).
    authorized_start: datetime | None = None
    authorized_end: datetime | None = None
    daily_windows: tuple[TimeWindow, ...] = ()
    target_networks: tuple[IPvAnyNetwork, ...] = ()
    allowed_hosts: frozenset[str] = frozenset()
    allowed_tools: frozenset[str] = frozenset()
    allowed_methods: frozenset[str] = frozenset()
    # The authorized TCP/UDP ports. Empty = unset = every port allowed (the
    # backward-compatible default); when non-empty the guard denies a command
    # naming a port outside the set (via a tool's ``port_flags``). A command that
    # names no port is unaffected -- it uses the tool's own defaults.
    allowed_ports: frozenset[int] = frozenset()
    autonomous: bool = False
    # The highest risk tier autonomous mode runs without asking. A command above
    # it is recorded ``proposed`` for the operator to run by hand, even when
    # autonomous is armed -- the deterministic "manual escalation" gate (see
    # skuggi.engagement.risk and executor._run_or_propose). Conservative by default:
    # recon/scans auto-run, but brute-force/crack/exploit escalate. Unlike the
    # scope allow-lists this never *widens* authority -- it only holds back.
    autonomous_ceiling: RiskTierField = RiskTier.active
    # The engagement posture. Advisory only: it calibrates what the agent
    # proposes (see skuggi.prompts), never what the guard allows.
    stance: Stance = "cautious"
    # Framework awareness. ``methodology`` is the driving framework (prescriptive);
    # ``taxonomies`` are the per-finding classification schemes enabled for this
    # engagement (descriptive, never forced); ``threat_model`` enables CVSS
    # Environmental scoring. All advisory to the agent -- none affect the guard.
    methodology: Methodology = "phases"
    taxonomies: frozenset[Taxonomy] = frozenset()
    threat_model: ThreatModel | None = None
    # The OSINT reconnaissance boundary. Advisory-absent, like ``threat_model``:
    # ``None`` means the agentic OSINT loop is disabled for this engagement. Never
    # affects the command guard -- it is its own dimension (see OsintScope).
    osint: OsintScope | None = None
    # The Burp connector boundary. Advisory-absent like ``osint``: ``None`` disables
    # the connector for this engagement. Its own dimension; the command guard is
    # unaffected (see BurpScope / skuggi.engagement.burp_guard).
    burp: BurpScope | None = None
    # Rules of engagement: authorization metadata + operational controls
    # (E13/E14). Only the exclusion deny-list is enforced by the guard; the rest
    # is advisory metadata for the report header. None means none recorded.
    rules_of_engagement: RulesOfEngagement | None = None

    @field_validator("timezone")
    @classmethod
    def _known_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            msg = f"unknown timezone: {value!r}"
            raise ValueError(msg) from exc
        return value

    @field_validator("authorized_start", "authorized_end")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            msg = "authorized_start/authorized_end must be timezone-aware"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _window_ordered(self) -> EngagementConfig:
        """Reject an end before the start when both bounds are set."""
        start, end = self.authorized_start, self.authorized_end
        if start is not None and end is not None and end < start:
            msg = "authorized_end is before authorized_start"
            raise ValueError(msg)
        return self

    def tzinfo(self) -> ZoneInfo:
        """The engagement's timezone as a ``ZoneInfo``."""
        return ZoneInfo(self.timezone)

    def resolve_target(self) -> str | None:
        """The scope-derived default for the runtime ``target`` var, or None.

        The *first* scoped target: the lexicographically-first allowed host,
        else the first target network, else None (an empty scope). This is only
        the default -- a manually-set ``target`` in the engagement env overrides
        it (see skuggi.engagement.runtime_env and ``core.effective_target``).
        ``sorted`` makes "first" deterministic over the unordered host set.
        """
        if self.allowed_hosts:
            return min(self.allowed_hosts)
        if self.target_networks:
            return str(self.target_networks[0])
        return None

    def describe(self, *, method_paint: Callable[[str], str] | None = None) -> str:
        """A one-block human summary for the REPL.

        ``method_paint`` styles each method name (the REPL passes the palette);
        without it the summary is plain, for the daemon and the report. Colour
        is applied to the structured method list here, so no front-end has to
        re-parse this rendered text.
        """
        paint = method_paint or (lambda m: m)
        nets = ", ".join(str(n) for n in self.target_networks) or "(none)"
        daily = ", ".join(f"{w.start}-{w.end}" for w in self.daily_windows) or "any"
        hosts = ", ".join(sorted(self.allowed_hosts)) or "(none)"
        methods = ", ".join(paint(m) for m in sorted(self.allowed_methods))
        start = self.authorized_start.isoformat() if self.authorized_start else "open"
        end = self.authorized_end.isoformat() if self.authorized_end else "open"
        window = (
            "no time bound"
            if self.authorized_start is None and self.authorized_end is None
            else f"{start} -> {end}"
        )
        return (
            f"engagement: {self.name}\n"
            f"  window: {window} ({self.timezone})\n"
            f"  daily:  {daily}\n"
            f"  networks: {nets}\n"
            f"  hosts:  {hosts}\n"
            f"  tools:  {', '.join(sorted(self.allowed_tools))}\n"
            f"  methods: {methods}\n"
            f"  stance: {self.stance}\n"
            f"  autonomous: {self.autonomous}"
        )
