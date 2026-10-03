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
}

# argv flag-heads (``--flag=value`` compares on the head) that RAISE the tier.
_PRIVILEGE_TOKENS = frozenset({"sudo", "doas", "pkexec"})
_DESTRUCTIVE_FLAGS = frozenset(
    {"--os-shell", "--os-pwn", "--os-cmd", "--file-write", "--file-dest"}
)
_INTRUSIVE_FLAGS = frozenset({"--dump", "--dump-all"})


def _base_tier(spec: ToolSpec | None) -> RiskTier:
    """The tool's base tier: explicit ``risk`` override, else method, else high.

    An unknown binary never reaches here (the guard denies it first); if one
    somehow did, it is destructive -- deny-by-default extends to risk-by-default.
    """
    if spec is None:
        return RiskTier.destructive
    if spec.risk is not None:
        return spec.risk
    return _METHOD_TIER.get(spec.method, RiskTier.destructive)


def risk_tier(spec: ToolSpec | None, argv: Sequence[str]) -> RiskTier:
    """The risk tier of an allowed command: the base tier, raised by argv."""
    tier = _base_tier(spec)
    for token in argv:
        head = token.split("=", 1)[0]
        if head in _PRIVILEGE_TOKENS or head in _DESTRUCTIVE_FLAGS:
            tier = max(tier, RiskTier.destructive)
        elif head in _INTRUSIVE_FLAGS:
            tier = max(tier, RiskTier.intrusive)
    return tier
