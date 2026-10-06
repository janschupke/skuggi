"""The one registry of ``set engagement <param>`` sub-commands.

Engagement configuration is edited through a single hierarchy -- ``set engagement
<param> [value]`` -- rather than a scatter of top-level verbs. This module is the
*one* place that enumerates those params: their field key (the ``EngagementConfig``
/ ``EngagementEnv`` attribute), how they are edited (``kind``), the completion
value set for the enum ones, and how a raw operator string parses into the value
the config expects. Grammar (``verbs``), completion, help, dispatch and the
interactive flow all read this registry, so a new engagement param is wired in one
edit here plus the matching ``verbs`` noun option (drift-tested to agree).

``verbs`` cannot import this (it is a leaf), so the ``set engagement`` noun options
are hand-written there and ``tests/unit/test_verbs.py`` pins them to :func:`names`.

The ``kind`` decides the edit path:

- ``direct``  -- a plain config field; a value edits in place, no value opens the
  field's widget. Not gated.
- ``auth``    -- an authorization-bearing field (hosts/networks/ports/tools/
  methods/windows/dates/ceiling); always shown as a diff and confirmed before it
  is written, whether or not a value was given.
- ``composite`` -- ``osint`` / ``threat_model`` / ``rules_of_engagement``; always
  the guided multi-field widget.
- ``scope``   -- the natural-language authorization editor (LLM proposes edits).
- ``env``     -- a runtime var in ``env.json`` (target/wordlist); a value, no gate.
- ``listener`` -- the interface+port picker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from skuggi.agent import protocol
from skuggi.frontend import wizard
from skuggi.tooling.registry import RiskTier

Kind = Literal["direct", "auth", "composite", "scope", "env", "listener"]

# Arguments that open the full wizard rather than edit one param.
WIZARD_ARGS = wizard.WIZARD_ARGS


@dataclass(frozen=True, slots=True)
class EngagementParam:
    """One ``set engagement <name>`` sub-command."""

    name: str
    group: str
    kind: Kind
    usage: str = ""
    summary: str = ""


# Static value sets for the enum params, used by completion (no live core needed).
_ENUMS: dict[str, tuple[str, ...]] = {
    "methodology": protocol.METHODOLOGIES,
    "stance": protocol.STANCES,
    "taxonomies": protocol.TAXONOMIES,
    "autonomous": ("on", "off"),
    "autonomous_ceiling": tuple(t.name for t in RiskTier),
}

# Ordered; the group drives the help listing and the scaffold cheatsheet.
PARAMS: tuple[EngagementParam, ...] = (
    EngagementParam("name", "identity", "direct", "<name>", "engagement name"),
    EngagementParam("timezone", "identity", "direct", "<iana>", "IANA timezone"),
    EngagementParam(
        "authorized_start", "scope", "auth", "<iso8601>", "authorized window start"
    ),
    EngagementParam(
        "authorized_end", "scope", "auth", "<iso8601>", "authorized window end"
    ),
    EngagementParam(
        "daily_windows", "scope", "auth", "<HH:MM-HH:MM,…>", "daily clock windows"
    ),
    EngagementParam(
        "target_networks", "scope", "auth", "<cidr,…>", "in-scope networks"
    ),
    EngagementParam("allowed_hosts", "scope", "auth", "<host,…>", "in-scope hosts"),
    EngagementParam("allowed_ports", "scope", "auth", "<ports>", "in-scope ports"),
    EngagementParam("allowed_tools", "scope", "auth", "<tool,…>", "permitted tools"),
    EngagementParam(
        "allowed_methods", "scope", "auth", "<method,…>", "permitted methods"
    ),
    EngagementParam(
        "autonomous_ceiling",
        "scope",
        "auth",
        "<recon|active|intrusive|destructive>",
        "highest tier auto-run",
    ),
    EngagementParam(
        "scope", "scope", "scope", "<request>", "natural-language scope edit"
    ),
    EngagementParam(
        "methodology", "approach", "direct", "<phases|ptes|attack>", "driving framework"
    ),
    EngagementParam(
        "stance",
        "approach",
        "direct",
        "<passive|cautious|balanced|aggressive>",
        "how forward-leaning proposals are",
    ),
    EngagementParam(
        "taxonomies", "approach", "direct", "<wstg,attack>", "finding taxonomies"
    ),
    EngagementParam(
        "autonomous", "approach", "direct", "[on|off]", "arm autonomous execution"
    ),
    EngagementParam(
        "threat_model", "approach", "composite", "", "CVSS environmental requirements"
    ),
    EngagementParam("osint", "recon", "composite", "", "OSINT reconnaissance scope"),
    EngagementParam(
        "rules_of_engagement", "rules", "composite", "", "rules of engagement"
    ),
    EngagementParam("target", "env", "env", "<host>", "current ${target} host"),
    EngagementParam("wordlist", "env", "env", "<path>", "${wordlist} path"),
    EngagementParam("listener", "env", "listener", "", "listener lhost/lport"),
)

_BY_NAME: dict[str, EngagementParam] = {p.name: p for p in PARAMS}

# Group display order + titles for the help listing and scaffold cheatsheet.
GROUP_ORDER: tuple[str, ...] = (
    "identity",
    "scope",
    "approach",
    "recon",
    "rules",
    "env",
)
GROUP_TITLES: dict[str, str] = {
    "identity": "Identity",
    "scope": "Scope & authorization",
    "approach": "Approach",
    "recon": "Recon",
    "rules": "Rules of engagement",
    "env": "Runtime vars",
}


def names() -> tuple[str, ...]:
    """Every param name, in registry order (the drift anchor for ``verbs``)."""
    return tuple(p.name for p in PARAMS)


def get(name: str) -> EngagementParam | None:
    """The param called `name`, or ``None`` if it is not one."""
    return _BY_NAME.get(name)


def enum_values(name: str) -> tuple[str, ...] | None:
    """The completion value set for an enum param, else ``None``."""
    return _ENUMS.get(name)


def needs_prompt(name: str, *, has_value: bool) -> bool:
    """Whether editing `name` must round-trip an interactive prompt.

    ``composite`` / ``scope`` / ``listener`` and every ``auth`` field always
    prompt (the last for the gated diff+confirm); a ``direct`` field prompts only
    when no value is supplied (then its widget collects one); ``env`` is one-shot.
    """
    param = _BY_NAME.get(name)
    if param is None:
        return False
    if param.kind in ("composite", "scope", "listener", "auth"):
        return True
    if param.kind == "direct":
        return not has_value
    return False


def _toggle(raw: str) -> bool:
    """Parse an on/off word to a bool (for the ``autonomous`` param)."""
    value = raw.strip().lower()
    if value in ("on", "true", "yes", "1"):
        return True
    if value in ("off", "false", "no", "0"):
        return False
    msg = f"expected on/off, got {raw!r}"
    raise ValueError(msg)


def parse_value(name: str, raw: str) -> object:
    """Parse a raw operator string into the value `name`'s field expects.

    Reuses the wizard field's ``transform`` (CSV lists, port ranges, clock
    windows); ``autonomous`` becomes a bool; env params and anything else stay the
    raw string. Raises ``ValueError`` on a malformed value.
    """
    if name == "autonomous":
        return _toggle(raw)
    field = wizard.FIELDS_BY_KEY.get(name)
    if field is not None and field.transform is not None:
        return field.transform(raw)
    return raw


@dataclass(frozen=True, slots=True)
class Invocation:
    """A parsed ``set engagement <rest>`` request."""

    action: Literal["adopt", "wizard", "param"]
    target: str  # adopt: the path (possibly empty = cwd); wizard/param: the name
    value: str  # param: the remaining value text (possibly empty)


def classify(rest: str) -> Invocation:
    """Parse the text after ``set engagement`` into an :class:`Invocation`.

    An empty tail adopts the cwd; a ``setup``/``new``/``edit`` head opens the
    wizard; a known param head is a param edit (the rest is its value); anything
    else is treated as a path to adopt.
    """
    rest = rest.strip()
    if not rest:
        return Invocation("adopt", "", "")
    head, _, tail = rest.partition(" ")
    lowered = head.lower()
    if lowered in WIZARD_ARGS:
        return Invocation("wizard", lowered, "")
    if lowered in _BY_NAME:
        return Invocation("param", lowered, tail.strip())
    return Invocation("adopt", rest, "")


def cheatsheet() -> list[tuple[str, list[tuple[str, str]]]]:
    """Grouped ``(title, [(invocation, summary)])`` for the scaffold output.

    ``invocation`` is ``set engagement <name> <usage>`` (the caller adds the
    surface prefix via ``verbs.cmd``), so a freshly-scaffolded engagement prints
    exactly the commands that fill it in.
    """
    out: list[tuple[str, list[tuple[str, str]]]] = []
    for group in GROUP_ORDER:
        rows = [
            (
                f"set engagement {p.name}" + (f" {p.usage}" if p.usage else ""),
                p.summary,
            )
            for p in PARAMS
            if p.group == group
        ]
        if rows:
            out.append((GROUP_TITLES[group], rows))
    return out
