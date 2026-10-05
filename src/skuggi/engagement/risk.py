"""Deterministic risk tiering for an allowed command.

The engagement guard (``check_command``) answers *allowed vs. denied*; this
answers *how risky* an allowed command is, so autonomous mode can auto-run the
low tiers and escalate the rest to the operator (``graph._run_or_propose``). No
LLM is in this path: the tier is a pure function of the tool's method (a port
scan is more active than passive recon; brute-forcing/cracking is intrusive;
exploitation is destructive), an optional explicit ``ToolSpec.risk`` override,
and a small set of high-signal argv heuristics that can only RAISE the tier --
privilege escalation, a SQLi OS-shell / file-write, or a data dump.

The enum itself lives in ``tooling.registry`` next to ``ToolSpec.risk`` (so the
registry stays importable without this module); the scoring is here, beside the
guard it serves.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from skuggi.tooling.registry import RiskTier

if TYPE_CHECKING:
    from collections.abc import Sequence

    from skuggi.tooling.registry import ToolSpec

_METHOD_TIER: dict[str, RiskTier] = {
    "recon": RiskTier.recon,
    "scan": RiskTier.active,
    "enumerate": RiskTier.active,
    "bruteforce": RiskTier.intrusive,
    "crack": RiskTier.intrusive,
    "exploit": RiskTier.destructive,
    # Read-only forensic examination (strings/file/exiftool over local evidence):
    # the lowest tier, like recon, because nothing touches a live target.
    "forensics": RiskTier.recon,
}

# argv flag-heads (``--flag=value`` compares on the head) that RAISE the tier.
_PRIVILEGE_TOKENS = frozenset({"sudo", "doas", "pkexec"})
_DESTRUCTIVE_FLAGS = frozenset(
    {"--os-shell", "--os-pwn", "--os-cmd", "--file-write", "--file-dest"}
)
_INTRUSIVE_FLAGS = frozenset({"--dump", "--dump-all"})

# Per-binary base tier, applied when the ToolSpec carries no explicit ``risk`` and
# the method bucket under-states the tool: sqlmap/nikto baseline runs are active
# scanning/injection a pro would not auto-run unattended, so they default to
# intrusive (held as a proposal rather than auto-executed at the default ceiling).
_BINARY_BASE: dict[str, RiskTier] = {
    "sqlmap": RiskTier.intrusive,
    "nikto": RiskTier.intrusive,
}

# nmap --script categories/names whose presence raises the tier: a vuln/brute scan
# is intrusive, an exploit/dos script is destructive. Plain -sC/--script=default is
# none of these and stays at the scan tier.
_NMAP_DESTRUCTIVE_SCRIPTS = ("exploit", "dos")
_NMAP_INTRUSIVE_SCRIPTS = ("vuln", "brute", "intrusive", "malware", "fuzzer")

# curl flags that make a request state-changing rather than passive recon.
_CURL_WRITE_FLAGS = frozenset({"-d", "--data", "-F", "--form", "-T", "--upload-file"})
_CURL_WRITE_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})


def _base_tier(spec: ToolSpec | None) -> RiskTier:
    """The tool's base tier: explicit ``risk`` override, else method, else high.

    An unknown binary never reaches here (the guard denies it first); if one
    somehow did, it is destructive -- deny-by-default extends to risk-by-default.
    """
    if spec is None:
        return RiskTier.destructive
    if spec.risk is not None:
        return spec.risk
    if spec.binary in _BINARY_BASE:
        return _BINARY_BASE[spec.binary]
    return _METHOD_TIER.get(spec.method, RiskTier.destructive)


def _flag_value(argv: Sequence[str], flag: str) -> str:
    """The value of ``flag`` in ``argv`` (``--flag v`` or ``--flag=v``), or ""."""
    want_next = False
    for token in argv:
        if want_next:
            return token
        if token == flag:
            want_next = True
        elif token.startswith(f"{flag}="):
            return token.split("=", 1)[1]
    return ""


def _nmap_script_tier(argv: Sequence[str]) -> RiskTier:
    """Raise for an nmap ``--script`` running vuln/brute (intrusive) or exploit/dos."""
    spec = _flag_value(argv, "--script").lower()
    if not spec:
        return RiskTier.recon
    if any(cat in spec for cat in _NMAP_DESTRUCTIVE_SCRIPTS):
        return RiskTier.destructive
    if any(cat in spec for cat in _NMAP_INTRUSIVE_SCRIPTS):
        return RiskTier.intrusive
    return RiskTier.recon


def _curl_write_tier(argv: Sequence[str]) -> RiskTier:
    """Raise a curl command to intrusive when it writes/uploads or uses a write verb."""
    heads = {token.split("=", 1)[0] for token in argv}
    if heads & _CURL_WRITE_FLAGS or any(token.startswith("--data") for token in argv):
        return RiskTier.intrusive
    method = _flag_value(argv, "-X") or _flag_value(argv, "--request")
    if method.upper() in _CURL_WRITE_METHODS:
        return RiskTier.intrusive
    return RiskTier.recon


def _argv_binary_tier(binary: str, argv: Sequence[str]) -> RiskTier:
    """Binary-specific argv escalation (nmap scripts, curl writes)."""
    if binary == "nmap":
        return _nmap_script_tier(argv)
    if binary == "curl":
        return _curl_write_tier(argv)
    return RiskTier.recon


def risk_tier(spec: ToolSpec | None, argv: Sequence[str]) -> RiskTier:
    """The risk tier of an allowed command: the base tier, raised by argv.

    Argv can only RAISE the tier: a privilege wrapper or SQLi os-shell/dump is
    destructive/intrusive regardless of the tool, and a per-tool escalation covers
    the tool-specific dangers the method bucket misses (an nmap vuln/exploit script,
    a state-changing curl). The tier never drops below the base.
    """
    tier = max(_base_tier(spec), _argv_binary_tier(spec.binary if spec else "", argv))
    for token in argv:
        head = token.split("=", 1)[0]
        if head in _PRIVILEGE_TOKENS or head in _DESTRUCTIVE_FLAGS:
            tier = max(tier, RiskTier.destructive)
        elif head in _INTRUSIVE_FLAGS:
            tier = max(tier, RiskTier.intrusive)
    return tier
