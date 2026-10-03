"""The engagement boundary: what is in scope, and the one guard that enforces it.

This is the pentest analogue of ``tools.py``'s ``_resolve_within`` and its
input clamps. A command string is a model-supplied argument, so before it can
be *suggested* or *run* it passes through ``check_command`` exactly once, and
every failure is a clean ``GuardVerdict`` with a reason rather than an
exception. The rule of the module is conservative: anything it cannot prove is
in scope is denied.

``parse_command`` turns a raw command into an argv, a binary, the engagement
method it belongs to (looked up in the registry), and the target hosts it acts
on. Target extraction is the correctness centrepiece: it classifies each argv
token as an IP / CIDR / URL-host / hostname, and the registry's ``target_flags``
let a flag force its value to be treated as a target even when it would not
classify on its own (``-t localhost``).
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, time
from pathlib import Path
from typing import Literal, NamedTuple
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, IPvAnyNetwork, field_validator

from skuggi.agent.protocol import Methodology, Stance, Taxonomy
from skuggi.common.logs import get_logger
from skuggi.tooling.registry import ToolRegistry

log = get_logger(__name__)

# A dotted name with an alphabetic TLD. Deliberately strict: a bare word with
# no dot ("localhost", "80") is not a target unless a target_flag forces it.
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_](-?[A-Za-z0-9_])*\.)+[A-Za-z]{2,}$")

# An IPv4 address with a final-octet range, e.g. ``10.0.0.1-254`` (nmap). The
# base three octets plus a ``lo-hi`` span that this module expands and checks
# host-by-host.
_FINAL_OCTET_RANGE = re.compile(
    r"^(?P<base>\d{1,3}(?:\.\d{1,3}){2})\.(?P<lo>\d{1,3})-(?P<hi>\d{1,3})$"
)
_MAX_OCTET = 255


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


class EngagementConfig(BaseModel):
    """The authorized boundary for one engagement, loaded from JSON."""

    model_config = ConfigDict(frozen=True)

    name: str
    timezone: str
    authorized_start: datetime
    authorized_end: datetime
    daily_windows: tuple[TimeWindow, ...] = ()
    target_networks: tuple[IPvAnyNetwork, ...] = ()
    allowed_hosts: frozenset[str] = frozenset()
    allowed_tools: frozenset[str] = frozenset()
    allowed_methods: frozenset[str] = frozenset()
    autonomous: bool = False
    # The engagement posture. Advisory only: it calibrates what the agent
    # proposes (see skuggi.prompts), never what the guard allows.
    stance: Stance = "cautious"
    # The host the cheatsheet's ``${target}`` defaults to, exported into the
    # wrapped shell. Optional: when blank it is derived from a sole allowed host
    # or sole target network (see ``primary_target``).
    primary_target: str | None = None
    # Framework awareness. ``methodology`` is the driving framework (prescriptive);
    # ``taxonomies`` are the per-finding classification schemes enabled for this
    # engagement (descriptive, never forced); ``threat_model`` enables CVSS
    # Environmental scoring. All advisory to the agent -- none affect the guard.
    methodology: Methodology = "phases"
    taxonomies: frozenset[Taxonomy] = frozenset()
    threat_model: ThreatModel | None = None

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
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            msg = "authorized_start/authorized_end must be timezone-aware"
            raise ValueError(msg)
        return value

    def tzinfo(self) -> ZoneInfo:
        """The engagement's timezone as a ``ZoneInfo``."""
        return ZoneInfo(self.timezone)

    def resolve_target(self) -> str | None:
        """The ``${target}`` default for this engagement, or None if ambiguous.

        Precedence: the explicit ``primary_target`` field, else the sole allowed
        host, else the sole target network. With several hosts/networks (or none)
        there is no safe default and the operator sets ``target`` themselves.
        """
        if self.primary_target:
            return self.primary_target
        if len(self.allowed_hosts) == 1:
            return next(iter(self.allowed_hosts))
        if len(self.target_networks) == 1:
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
        return (
            f"engagement: {self.name}\n"
            f"  window: {self.authorized_start.isoformat()} "
            f"-> {self.authorized_end.isoformat()} ({self.timezone})\n"
            f"  daily:  {daily}\n"
            f"  networks: {nets}\n"
            f"  hosts:  {hosts}\n"
            f"  tools:  {', '.join(sorted(self.allowed_tools))}\n"
            f"  methods: {methods}\n"
            f"  stance: {self.stance}\n"
            f"  autonomous: {self.autonomous}"
        )


@dataclass(frozen=True, slots=True)
class ParsedCommand:
    """A raw command decomposed for the guard."""

    raw: str
    argv: tuple[str, ...]
    binary: str
    targets: tuple[str, ...]
    method: str | None
    requires_target: bool
    # A target expression (range/list) that could not be enumerated for scope
    # checking -- the guard denies it (a target it cannot enumerate is one it
    # cannot prove in scope).
    unresolved: bool = False
    # The command names a target-list *file* (nmap ``-iL`` …) whose contents
    # cannot be scope-checked statically -- the guard denies it.
    target_file: bool = False


class GuardVerdict(NamedTuple):
    """The outcome of checking one command against the engagement."""

    allowed: bool
    reason: str


def _as_target(token: str) -> str | None:
    """Interpret a token as a target host, or None if it is not one."""
    if "://" in token:
        return urlsplit(token).hostname
    try:
        ipaddress.ip_network(token, strict=False)
    except ValueError:
        return token if _HOSTNAME.match(token) else None
    return token


def _is_ipv4(host: str) -> bool:
    """Whether `host` is a literal IP address (not a hostname or garbage)."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _expand_comma_list(token: str) -> list[str] | None:
    """A comma list expanded iff *every* member classifies as a host/IP.

    ``10.0.0.1,10.0.0.2`` expands; nmap octet-shorthand (``10.0.0.1,2,3``) does
    not and yields ``None`` (deny), since the bare octets cannot be enumerated.
    """
    parts = [p for p in token.split(",") if p]
    hosts = [_as_target(p) for p in parts]
    if parts and all(h is not None for h in hosts):
        return [h for h in hosts if h is not None]
    return None


def _expand_octet_range(token: str) -> list[str] | None:
    """A final-octet range (``10.0.0.1-254``) expanded to each concrete IP.

    ``None`` for anything that is not a simple ``A.B.C.lo-hi`` with a valid
    ``0 <= lo <= hi <= 255`` span (a multi-octet range such as ``10.0-5.0.1``).
    """
    match = _FINAL_OCTET_RANGE.match(token)
    if match is None:
        return None
    lo, hi = int(match["lo"]), int(match["hi"])
    if not 0 <= lo <= hi <= _MAX_OCTET:
        return None
    hosts = [f"{match['base']}.{octet}" for octet in range(lo, hi + 1)]
    return hosts if all(_is_ipv4(host) for host in hosts) else None


def _expand_target_expr(token: str) -> list[str] | None:
    """Expand a multi-host target *expression* to its concrete hosts, or ``None``.

    Handles the two common shapes a scan tool accepts in place of one host: a
    final-octet range (``10.0.0.1-254``) and a comma list whose every member
    classifies (``10.0.0.1,10.0.0.2``); each expanded host is scope-checked
    individually by the guard.

    Returns ``None`` when the token *looks* like host material (dotted, with a
    ``-`` or ``,``) but cannot be expanded confidently. The guard treats
    ``None`` as unresolved and **denies** it: a target the harness cannot
    enumerate is a target it cannot prove in scope.
    """
    if "." not in token or not ("-" in token or "," in token):
        return None  # not a target expression; the normal classifier handles it
    if "," in token:
        return _expand_comma_list(token)
    return _expand_octet_range(token)


class _Targets(NamedTuple):
    """Targets pulled from an argv, plus whether any defied enumeration."""

    hosts: tuple[str, ...]
    unresolved: bool


def _extract_targets(argv: tuple[str, ...], target_flags: tuple[str, ...]) -> _Targets:
    """Pull target hosts out of the argument vector, order-preserving, unique.

    A token that is a host/IP/URL classifies directly; a multi-host *expression*
    (range/list) is expanded and every host added; a dotted ``-``/``,`` token
    that cannot be expanded sets ``unresolved`` so the guard denies the command
    rather than letting an un-checkable target ride along.
    """
    found: list[str] = []
    unresolved = False
    force_next = False
    for token in argv[1:]:
        if force_next:
            # A flag-forced value is still classified: a URL yields its host
            # (so `-u http://192.0.2.10/x` is checked as `192.0.2.10`, in scope,
            # not as the whole string). It falls back to the verbatim token only
            # when it does not classify, preserving `-t localhost` forcing.
            found.append(_as_target(token) or token)
            force_next = False
            continue
        if token in target_flags:
            force_next = True
            continue
        target = _as_target(token)
        if target is not None:
            found.append(target)
            continue
        expanded = _expand_target_expr(token)
        if expanded is not None:
            found.extend(expanded)
        elif "." in token and ("-" in token or "," in token):
            unresolved = True
    return _Targets(tuple(dict.fromkeys(found)), unresolved)


def parse_command(raw: str, registry: ToolRegistry) -> ParsedCommand:
    """Decompose `raw` into the fields the guard needs.

    A command that will not tokenize (an unbalanced quote) yields an empty
    argv, which the guard then denies -- never a raised exception.
    """
    try:
        argv = tuple(shlex.split(raw))
    except ValueError as exc:
        log.debug("command did not tokenize (%s); guard will deny: %r", exc, raw)
        argv = ()
    if not argv:
        return ParsedCommand(
            raw=raw, argv=(), binary="", targets=(), method=None, requires_target=True
        )
    binary = Path(argv[0]).name
    spec = registry.spec_for(binary)
    target_flags = spec.target_flags if spec else ()
    target_file_flags = spec.target_file_flags if spec else ()
    targets = _extract_targets(argv, target_flags)
    return ParsedCommand(
        raw=raw,
        argv=argv,
        binary=binary,
        targets=targets.hosts,
        method=spec.method if spec else None,
        requires_target=spec.requires_target if spec else True,
        unresolved=targets.unresolved,
        target_file=any(flag in argv for flag in target_file_flags),
    )


def _target_in_scope(target: str, engagement: EngagementConfig) -> bool:
    """Whether one target host is inside the authorized scope."""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return target in engagement.allowed_hosts
    for allowed in engagement.target_networks:
        try:
            if net.subnet_of(allowed):  # type: ignore[arg-type]
                return True
        except TypeError:
            continue  # v4 vs v6 mismatch
    return False


def check_command(  # noqa: PLR0911 -- a guard is a linear sequence of denials; each check is one return
    cmd: ParsedCommand, engagement: EngagementConfig, *, now: datetime
) -> GuardVerdict:
    """The single choke point: is this command inside the engagement boundary?

    Runs cheapest-to-costliest, returning the first failure's reason. `now`
    must be timezone-aware; it is converted into the engagement timezone for
    the daily-window check.
    """
    if not cmd.binary:
        return GuardVerdict(False, "empty or unparseable command")
    if cmd.method is None:
        return GuardVerdict(False, f"tool {cmd.binary!r} is not in the tool registry")
    if cmd.binary not in engagement.allowed_tools:
        return GuardVerdict(
            False, f"tool {cmd.binary!r} is not authorized for this engagement"
        )
    if cmd.method not in engagement.allowed_methods:
        return GuardVerdict(
            False, f"method {cmd.method!r} is not authorized for this engagement"
        )
    if not (engagement.authorized_start <= now <= engagement.authorized_end):
        return GuardVerdict(False, "outside the authorized date/time range")
    if engagement.daily_windows:
        local = now.astimezone(engagement.tzinfo()).timetz().replace(tzinfo=None)
        if not any(window.contains(local) for window in engagement.daily_windows):
            return GuardVerdict(False, "outside the allowed daily time window")
    if cmd.target_file:
        return GuardVerdict(
            False,
            "target-list files cannot be scope-checked; enumerate hosts explicitly",
        )
    if cmd.unresolved:
        return GuardVerdict(
            False, "target expression could not be resolved for scope checking"
        )
    if cmd.requires_target and not cmd.targets:
        return GuardVerdict(
            False, "no in-scope target could be identified in the command"
        )
    for target in cmd.targets:
        if not _target_in_scope(target, engagement):
            return GuardVerdict(
                False, f"target {target!r} is outside the authorized scope"
            )
    return GuardVerdict(True, "in scope")
