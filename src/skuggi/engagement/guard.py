"""Command parsing and the one guard that enforces the engagement boundary.

This is the pentest analogue of ``tools.py``'s ``_resolve_within`` and its input
clamps. A command string is a model-supplied argument, so before it can be
*suggested* or *run* it passes through ``check_command`` exactly once, and every
failure is a clean ``GuardVerdict`` with a reason rather than an exception. The
rule of the module is conservative: anything it cannot prove is in scope is denied.

``parse_command`` turns a raw command into an argv, a binary, the engagement method
it belongs to (looked up in the registry), and the target hosts it acts on. Target
extraction is the correctness centrepiece: it classifies each argv token as an IP /
CIDR / URL-host / hostname, and the registry's ``target_flags`` let a flag force its
value to be treated as a target even when it would not classify on its own
(``-t localhost``). The scope model it checks against lives in
:mod:`skuggi.engagement.scope`.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit

from skuggi.common import netscope
from skuggi.common.logs import get_logger
from skuggi.engagement.scope import EngagementConfig
from skuggi.engagement.workspace import Workspace
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

# The allow-all token in a scope's tool/method lists: an explicit operator choice
# to authorize every tool / method (a lab or a deliberately wide engagement).
_WILDCARD = "*"


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
    # Data-file paths the command passes to the tool (wordlist/user/cred lists,
    # from the spec's ``input_file_flags``). The guard confines each to the
    # engagement workspace, so the file reaches the tool while its contents stay
    # out of the model's context.
    input_files: tuple[str, ...] = ()
    # ``argv[0]`` carried a path (``/usr/bin/nmap``, ``./nmap``) rather than a
    # bare tool name. Authorization is keyed on the basename, so a pathed argv[0]
    # would run an arbitrary binary under a registered tool's authority -- denied.
    binary_is_path: bool = False
    # Ports the command names via the spec's ``port_flags``, expanded from the
    # spec string (``80,443,1-1000``). Checked against ``allowed_ports`` only when
    # the engagement sets it.
    ports: tuple[int, ...] = ()
    # A port spec that could not be parsed (an open-ended ``-`` range, a bad
    # number) -- the guard denies it when ports are scoped, like an unresolvable
    # target: a port it cannot enumerate is one it cannot prove in scope.
    ports_unresolved: bool = False
    # A transport/pivot tool (ssh/proxychains/…). Denied when invoked directly --
    # its payload is unconstrainable; pivoting goes through a foothold (see guard
    # ``_authorization_verdict`` and ``engagement.pivot``).
    transport: bool = False


class GuardVerdict(NamedTuple):
    """The outcome of one scope check -- the shared contract of every guard.

    All four scope guards return this: ``check_command`` (here),
    ``osint_guard.check_osint_task``, ``research.scope.check_research_source`` and
    ``forensics.scope.check_forensic_command``. They take DIFFERENT inputs by
    design -- a shell command's argv/targets/ports/time, an OSINT source+subject,
    a research source name, a forensic tool+argv+path -- because they guard
    genuinely different dimensions, so there is no common input type to unify
    them under, and forcing one would be speculative generality. What they DO
    share is this verdict and the invariant behind it: deny-by-default, the first
    failing gate wins, and anything not proven in scope is ``allowed=False``.
    """

    allowed: bool
    reason: str


# The largest value a bare decimal could be a port rather than an integer-encoded
# IPv4 address: at or below this a lone number is treated as a port (ignored, not
# a target); above it a number can only be an encoded host, so it is decoded and
# scope-checked. nmap and friends accept ``2130706433`` (= 127.0.0.1).
_MAX_PORT = 65535
_MAX_IPV4_INT = 0xFFFFFFFF


def _decode_int_ip(token: str) -> str | None:
    """Decode an integer/hex-encoded IPv4 (``2130706433``/``0x7f000001``), else None.

    A bare decimal is only decoded when it is too large to be a port, so a real
    port number (``80``) is never mistaken for a host. The decoded dotted-quad is
    then scope-checked like any other target -- closing the hole where an encoded
    out-of-scope IP rode alongside an in-scope one undetected.
    """
    lowered = token.lower()
    try:
        if lowered.startswith("0x"):
            value = int(token, 16)
        elif token.isdigit():
            value = int(token)
            if value <= _MAX_PORT:
                return None  # a plausible port, not an encoded IP
        else:
            return None
    except ValueError:
        return None
    if 0 <= value <= _MAX_IPV4_INT:
        return str(ipaddress.ip_address(value))
    return None


def _as_target(token: str) -> str | None:
    """Interpret a token as a target host, or None if it is not one."""
    if "://" in token:
        return urlsplit(token).hostname
    try:
        ipaddress.ip_network(token, strict=False)
    except ValueError:
        decoded = _decode_int_ip(token)
        if decoded is not None:
            return decoded
        return token if _HOSTNAME.match(token) else None
    return token


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
    return hosts if all(netscope.is_ip(host) for host in hosts) else None


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


def _flag_values(argv: tuple[str, ...], flags: tuple[str, ...]) -> tuple[str, ...]:
    """Each value immediately following one of `flags` in `argv`, in order.

    Handles both ``-w list.txt`` (separate token) and ``-w=list.txt`` (glued);
    a flag at the very end with no value contributes nothing.
    """
    if not flags:
        return ()
    found: list[str] = []
    expect = False
    for token in argv[1:]:
        if expect:
            found.append(token)
            expect = False
            continue
        if token in flags:
            expect = True
            continue
        for flag in flags:
            if token.startswith(f"{flag}="):
                found.append(token[len(flag) + 1 :])
                break
    return tuple(found)


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
    input_file_flags = spec.input_file_flags if spec else ()
    port_flags = spec.port_flags if spec else ()
    targets = _extract_targets(argv, target_flags)
    ports, ports_unresolved = _parse_ports(_flag_values(argv, port_flags))
    return ParsedCommand(
        raw=raw,
        argv=argv,
        binary=binary,
        targets=targets.hosts,
        method=spec.method if spec else None,
        requires_target=spec.requires_target if spec else True,
        unresolved=targets.unresolved,
        target_file=any(flag in argv for flag in target_file_flags),
        input_files=_flag_values(argv, input_file_flags),
        binary_is_path=Path(argv[0]).name != argv[0],
        transport=spec.transport if spec else False,
        ports=ports,
        ports_unresolved=ports_unresolved,
    )


def _parse_ports(values: tuple[str, ...]) -> tuple[tuple[int, ...], bool]:
    """Expand port-spec flag values (``80,443,1-1000``, nmap ``T:22,U:53``).

    Returns the concrete ports and whether any token defied parsing -- an
    open-ended range (``1-``), a non-numeric or out-of-range value -- which the
    guard treats as unresolved and denies when ports are scoped. A proto prefix
    (``T:``/``U:``) is stripped; the port itself is what scope cares about.
    """
    found: list[int] = []
    unresolved = False
    for value in values:
        for item in value.split(","):
            token = item.strip()
            if not token:
                continue
            if ":" in token:  # strip an nmap T:/U: protocol prefix
                token = token.split(":", 1)[1]
            lo, sep, hi = token.partition("-")
            if sep:
                expanded = _port_range(lo, hi)
                if expanded is None:
                    unresolved = True
                else:
                    found.extend(expanded)
            else:
                port = _as_port(token)
                if port is None:
                    unresolved = True
                else:
                    found.append(port)
    return tuple(dict.fromkeys(found)), unresolved


def _as_port(token: str) -> int | None:
    """A token as a valid TCP/UDP port (0-65535), or None."""
    if not token.isdigit():
        return None
    value = int(token)
    return value if 0 <= value <= _MAX_PORT else None


def _port_range(lo: str, hi: str) -> list[int] | None:
    """Expand ``lo-hi`` to each port, or None for an open/invalid/backwards range."""
    low, high = _as_port(lo), _as_port(hi)
    if low is None or high is None or low > high:
        return None
    return list(range(low, high + 1))


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


def _datafiles_in_scope(
    cmd: ParsedCommand,
    workspace: Workspace | None,
    cwd: Path | None,
    wordlist_roots: tuple[Path, ...],
) -> GuardVerdict | None:
    """Confine each data-file path to the workspace, or deny. None = all clear.

    A data-file flag (wordlist/credential list) is confined to the engagement
    workspace or a configured wordlist root. Confinement is only *enforced* when
    a workspace and cwd are supplied: the real execution path always has both (a
    loaded engagement implies a workspace), while the pure-scope compliance
    scorer passes neither and is not evaluating file paths.
    """
    if not cmd.input_files or workspace is None or cwd is None:
        return None
    for path in cmd.input_files:
        try:
            workspace.confine_datafile(path, cwd=cwd, extra_roots=wordlist_roots)
        except ValueError as exc:
            return GuardVerdict(False, str(exc))
    return None


def _authorization_verdict(  # noqa: PLR0911 -- one guard clause per denial reason
    cmd: ParsedCommand, engagement: EngagementConfig
) -> GuardVerdict | None:
    """Deny unless the command's tool and method are authorized (or ``*``)."""
    if not cmd.binary:
        return GuardVerdict(False, "empty or unparseable command")
    if cmd.binary_is_path:
        return GuardVerdict(
            False, f"command must be a bare tool name, not a path: {cmd.argv[0]!r}"
        )
    if cmd.method is None:
        return GuardVerdict(False, f"tool {cmd.binary!r} is not in the tool registry")
    if cmd.transport:
        return GuardVerdict(
            False,
            f"tool {cmd.binary!r} is a pivot/transport tool and cannot be run "
            "directly (its remote payload is not scope-checkable) -- register a "
            "foothold with `set foothold` and skuggi routes commands through it",
        )
    # ``*`` in the allow-list authorizes every tool / method; otherwise the
    # binary / method must be named.
    tools = engagement.allowed_tools
    if _WILDCARD not in tools and cmd.binary not in tools:
        return GuardVerdict(
            False, f"tool {cmd.binary!r} is not authorized for this engagement"
        )
    if (
        _WILDCARD not in engagement.allowed_methods
        and cmd.method not in engagement.allowed_methods
    ):
        return GuardVerdict(
            False, f"method {cmd.method!r} is not authorized for this engagement"
        )
    return None


def _time_window_verdict(
    engagement: EngagementConfig, now: datetime
) -> GuardVerdict | None:
    """Deny when `now` is outside the authorization window or the daily windows."""
    start, end = engagement.authorized_start, engagement.authorized_end
    if start is not None and now < start:
        return GuardVerdict(False, "before the authorized start time")
    if end is not None and now > end:
        return GuardVerdict(False, "after the authorized end time")
    if engagement.daily_windows:
        local = now.astimezone(engagement.tzinfo()).timetz().replace(tzinfo=None)
        if not any(window.contains(local) for window in engagement.daily_windows):
            return GuardVerdict(False, "outside the allowed daily time window")
    return None


def _target_verdict(
    cmd: ParsedCommand, engagement: EngagementConfig
) -> GuardVerdict | None:
    """Deny unless every target the command names resolves inside the scope."""
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
        if _target_excluded(target, engagement):
            return GuardVerdict(
                False, f"target {target!r} is on the out-of-scope exclusion list"
            )
        if not _target_in_scope(target, engagement):
            return GuardVerdict(
                False, f"target {target!r} is outside the authorized scope"
            )
    return None


def _target_excluded(target: str, engagement: EngagementConfig) -> bool:
    """Whether a target is on the RoE exclusion deny-list (checked before allow).

    Deny wins over allow: an excluded host is refused even when it also matches the
    scope allow-list (audit E13). Mirrors ``_target_in_scope``: an IP is excluded
    when it falls in an excluded network, a bare name when it is listed exactly.
    """
    roe = engagement.rules_of_engagement
    if roe is None:
        return False
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return target in roe.excluded_hosts
    for blocked in roe.excluded_networks:
        try:
            if net.subnet_of(blocked):  # type: ignore[arg-type]
                return True
        except TypeError:
            continue  # v4 vs v6 mismatch
    return str(net.network_address) in roe.excluded_hosts


def check_command(  # noqa: PLR0913 -- a guard reads over many engagement inputs
    cmd: ParsedCommand,
    engagement: EngagementConfig,
    *,
    now: datetime,
    workspace: Workspace | None = None,
    cwd: Path | None = None,
    wordlist_roots: tuple[Path, ...] = (),
) -> GuardVerdict:
    """The single choke point: is this command inside the engagement boundary?

    An ordered, cheapest-to-costliest deny-chain: the first gate to return a
    verdict wins, and passing every gate is in scope. `now` must be
    timezone-aware; it is converted into the engagement timezone for the
    daily-window check. `workspace`/`cwd`/`wordlist_roots` enable data-file
    confinement: a wordlist/credential-list path is allowed only when it stays
    inside the engagement workspace or a configured wordlist root.
    """
    return (
        _authorization_verdict(cmd, engagement)
        or _time_window_verdict(engagement, now)
        or _target_verdict(cmd, engagement)
        or _port_verdict(cmd, engagement)
        or _datafiles_in_scope(cmd, workspace, cwd, wordlist_roots)
        or GuardVerdict(True, "in scope")
    )


def _port_verdict(
    cmd: ParsedCommand, engagement: EngagementConfig
) -> GuardVerdict | None:
    """Deny when the command names a port outside the authorized port scope.

    Off unless the engagement sets ``allowed_ports`` (empty = every port). A port
    spec that could not be parsed is denied like an unresolvable target; a command
    that names no port passes (it uses the tool's own defaults).
    """
    if not engagement.allowed_ports:
        return None
    if cmd.ports_unresolved:
        return GuardVerdict(
            False, "port specification could not be resolved for scope checking"
        )
    out_of_scope = sorted(p for p in cmd.ports if p not in engagement.allowed_ports)
    if out_of_scope:
        return GuardVerdict(
            False, f"port(s) {out_of_scope} outside the authorized port scope"
        )
    return None
