"""The engagement Q&A wizard: gather a scope interactively, front-end-agnostic.

The wizard knows the engagement fields and how to shape free-text answers into
the JSON an ``EngagementConfig`` validates. It never touches a console or a
socket: it drives everything through a :class:`~skuggi.frontend.prompter.Prompter`
bundle supplied by the front-end -- the REPL's prompt_toolkit widgets or the
wrapped-shell attach loop's socket round-trips -- so one wizard serves both.

Fields are grouped into ordered *sections* so the front-end can show a step bar
(``[2/6] Authorization``), and each field declares a *widget* (text, a menu, a
checklist, …) so the operator gets dropdowns and multi-select instead of a blank
line. Validation and persistence stay in ``AgentCore.create_engagement``; this
module collects answers and, on a rejection, re-asks only the offending fields
over the answers already given -- never restarting from the top.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Literal

from skuggi.common.text import split_csv
from skuggi.config.configs import ConfigError, InvalidScopeError
from skuggi.engagement.engagement import EngagementConfig
from skuggi.frontend.prompter import Prompter
from skuggi.tooling.registry import RiskTier

# The risk tiers, low -> high, offered for the autonomous ceiling.
_RISK_TIERS: tuple[str, ...] = tuple(t.name for t in RiskTier)

Apply = Callable[[dict[str, object]], EngagementConfig]

# Arguments to the `engagement` verb that open the wizard rather than show scope.
WIZARD_ARGS = frozenset({"setup", "new", "edit"})

Widget = Literal[
    "text",
    "autocomplete",
    "select",
    "multiselect",
    "confirm",
    "threat_model",
    "osint",
    "burp",
    "roe",
]

# CVSS environmental requirement dimensions, in C-I-A order, and their levels.
_CIA = (
    ("confidentiality_requirement", "Confidentiality"),
    ("integrity_requirement", "Integrity"),
    ("availability_requirement", "Availability"),
)
_CIA_LEVELS = ("low", "medium", "high")


@dataclass(frozen=True)
class Catalog:
    """Runtime option sources the wizard offers (built by the front-end)."""

    timezones: tuple[str, ...]
    tools: tuple[str, ...]
    methods: tuple[str, ...]
    methodologies: tuple[str, ...]
    taxonomies: tuple[str, ...]
    stances: tuple[str, ...]
    osint_sources: tuple[str, ...]
    burp_actions: tuple[str, ...]


@dataclass(frozen=True)
class Field:
    """One engagement field and how to collect it."""

    key: str
    prompt: str
    widget: Widget
    transform: Callable[[str], object] | None = None
    source: Callable[[Catalog], Sequence[str]] | None = None
    preselect_all: bool = False
    default: str | None = None


@dataclass(frozen=True)
class Section:
    """A named group of fields (one step of the wizard)."""

    title: str
    fields: tuple[Field, ...] = dataclass_field(default_factory=tuple)


def _ports(answer: str) -> list[int]:
    """Parse ``80,443,8000-8010`` (nmap ``T:``/``U:`` prefixes tolerated) to ints."""
    out: list[int] = []
    for item in split_csv(answer):
        token = item.split(":", 1)[1] if ":" in item else item
        lo, sep, hi = token.partition("-")
        if sep and lo.isdigit() and hi.isdigit():
            out.extend(range(int(lo), int(hi) + 1))
        elif token.isdigit():
            out.append(int(token))
    return out


def _windows(answer: str) -> list[dict[str, str]]:
    """Parse ``HH:MM-HH:MM`` clock ranges (comma-separated) into scope dicts."""
    windows: list[dict[str, str]] = []
    for chunk in split_csv(answer):
        start, _, end = chunk.partition("-")
        windows.append({"start": start.strip(), "end": end.strip()})
    return windows


def _show(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        parts = [
            f"{v.get('start', '')}-{v.get('end', '')}"
            if isinstance(v, dict)
            else str(v)
            for v in value
        ]
        return ", ".join(parts)
    return str(value)


def _label(prompt: str, current: str) -> str:
    """A text-prompt label, showing the current value when editing."""
    return f"{prompt} [{current}]: " if current else f"{prompt}: "


_SECTIONS: tuple[Section, ...] = (
    Section(
        "Identity",
        (
            Field("name", "engagement name", "text", transform=str),
            Field(
                "timezone",
                "timezone (IANA, e.g. Europe/Helsinki)",
                "autocomplete",
                transform=str,
                source=lambda c: c.timezones,
                default="UTC",
            ),
        ),
    ),
    Section(
        "Authorization",
        (
            Field(
                "authorized_start",
                "authorized start (ISO 8601, tz-aware; blank = no bound)",
                "text",
                transform=str,
            ),
            Field(
                "authorized_end",
                "authorized end (ISO 8601, tz-aware; blank = no bound)",
                "text",
                transform=str,
            ),
        ),
    ),
    Section(
        "Schedule",
        (
            Field(
                "daily_windows",
                "daily windows HH:MM-HH:MM, comma-separated (blank = any)",
                "text",
                transform=_windows,
            ),
        ),
    ),
    Section(
        "Targets",
        (
            Field(
                "target_networks",
                "target networks (CIDR, comma-separated; blank = any)",
                "text",
                transform=split_csv,
            ),
            Field(
                "allowed_hosts",
                "allowed hosts (comma-separated; blank = any)",
                "text",
                transform=split_csv,
            ),
            Field(
                "allowed_ports",
                "allowed ports (comma-sep, ranges ok; blank = any)",
                "text",
                transform=_ports,
            ),
        ),
    ),
    Section(
        "Capabilities",
        (
            Field(
                "allowed_tools",
                "allowed tools (comma-sep; Tab completes; * = all; blank = none)",
                "autocomplete",
                transform=split_csv,
                source=lambda c: c.tools,
            ),
            Field(
                "allowed_methods",
                "allowed methods",
                "multiselect",
                source=lambda c: c.methods,
                preselect_all=True,
            ),
        ),
    ),
    Section(
        "Approach",
        (
            Field(
                "methodology",
                "driving methodology",
                "select",
                source=lambda c: c.methodologies,
                default="phases",
            ),
            Field(
                "taxonomies",
                "finding taxonomies to tag with",
                "multiselect",
                source=lambda c: c.taxonomies,
            ),
            Field(
                "stance",
                "engagement stance (how forward-leaning the agent's proposals are)",
                "select",
                source=lambda c: c.stances,
                default="cautious",
            ),
            Field("autonomous", "autonomous execution?", "confirm"),
            Field(
                "autonomous_ceiling",
                "highest risk tier autonomous mode runs without asking",
                "select",
                source=lambda _c: _RISK_TIERS,
                default="active",
            ),
            Field("threat_model", "threat model", "threat_model"),
        ),
    ),
    Section(
        "OSINT",
        (Field("osint", "OSINT reconnaissance scope", "osint"),),
    ),
    Section(
        "Rules of engagement",
        (Field("rules_of_engagement", "rules of engagement", "roe"),),
    ),
    Section(
        "Burp",
        (Field("burp", "Burp connector scope", "burp"),),
    ),
)

# Every engagement field the wizard owns (for the preserve-on-retry targeting and
# a drift test against EngagementConfig).
KNOWN_KEYS: frozenset[str] = frozenset(
    f.key for section in _SECTIONS for f in section.fields
)

# The wizard field for each key, so `set engagement <param>` can reuse a field's
# widget / transform / option source to collect or parse one value in isolation.
FIELDS_BY_KEY: dict[str, Field] = {
    f.key: f for section in _SECTIONS for f in section.fields
}


def _ask_field(  # noqa: PLR0911, PLR0912 -- a widget dispatch is one return/branch per widget
    prompter: Prompter, catalog: Catalog, field: Field, current: object
) -> tuple[bool, object] | None:
    """Collect one field. Returns (changed, value), or ``None`` on abort.

    ``changed`` is False when a blank text answer should keep the current value.
    """
    if field.widget in ("text", "autocomplete"):
        shown = _show(current)
        label = _label(field.prompt, shown)
        if field.widget == "autocomplete":
            candidates = field.source(catalog) if field.source else ()
            answer = prompter.ask_complete(
                label, list(candidates), shown or field.default
            )
        else:
            answer = prompter.ask(label)
        if answer is None:
            return None
        answer = answer.strip()
        if not answer:
            return (False, current)
        transform = field.transform or str
        return (True, transform(answer))

    options = list(field.source(catalog)) if field.source else []
    if field.widget == "select":
        default = current if isinstance(current, str) else field.default
        choice = prompter.choose(field.prompt, options, default)
        return None if choice is None else (True, choice)
    if field.widget == "multiselect":
        if isinstance(current, list):
            preselected: Sequence[str] = [str(v) for v in current]
        elif field.preselect_all:
            preselected = options
        else:
            preselected = ()
        picks = prompter.multiselect(field.prompt, options, preselected)
        return None if picks is None else (True, picks)
    if field.widget == "threat_model":
        return _ask_threat_model(prompter, current)
    if field.widget == "osint":
        return _ask_osint(prompter, catalog, current)
    if field.widget == "burp":
        return _ask_burp(prompter, catalog, current)
    if field.widget == "roe":
        return _ask_roe(prompter, current)
    # confirm
    answer_bool = prompter.confirm(field.prompt, bool(current))
    return None if answer_bool is None else (True, answer_bool)


def _ask_threat_model(
    prompter: Prompter, current: object
) -> tuple[bool, object] | None:
    """Guided CVSS environmental scoring: a yes/no, then three C-I-A dropdowns."""
    existing = current if isinstance(current, dict) else None
    enable = prompter.confirm(
        "set CVSS environmental requirements (threat model)?", existing is not None
    )
    if enable is None:
        return None
    if not enable:
        return (True, None)
    model: dict[str, str] = {}
    for key, name in _CIA:
        default = existing.get(key) if existing else "medium"
        level = prompter.choose(f"{name} requirement", list(_CIA_LEVELS), str(default))
        if level is None:
            return None
        model[key] = level
    return (True, model)


def _ask_osint(  # noqa: PLR0911 -- one abort-return per OSINT sub-prompt
    prompter: Prompter, catalog: Catalog, current: object
) -> tuple[bool, object] | None:
    """Guided OSINT scope: a yes/no, then sources + subjects + the passive bound.

    Mirrors ``_ask_threat_model`` -- one composite field returning a nested dict
    (or ``None`` when OSINT is left disabled), so the wizard's flat accumulator
    carries OSINT under the single ``osint`` key and ``EngagementConfig`` validates
    it in one place.
    """
    existing = current if isinstance(current, dict) else None
    enable = prompter.confirm("enable OSINT reconnaissance?", existing is not None)
    if enable is None:
        return None
    if not enable:
        return (True, None)
    sources = list(catalog.osint_sources)
    preset = [str(s) for s in existing.get("enabled_sources", ())] if existing else []
    picks = prompter.multiselect("OSINT sources to enable", sources, preset)
    if picks is None:
        return None
    osint: dict[str, object] = {"enabled_sources": picks}
    for key, label in (
        ("organizations", "organizations (comma-separated)"),
        ("domains", "authorized apex domains (comma-separated)"),
        ("people", "people / usernames (comma-separated)"),
        ("github_orgs", "GitHub orgs (comma-separated)"),
    ):
        shown = ", ".join(existing.get(key, ())) if existing else ""
        answer = prompter.ask(_label(label, shown))
        if answer is None:
            return None
        osint[key] = (
            split_csv(answer)
            if answer.strip()
            else list(existing.get(key, ()))
            if existing
            else []
        )
    passive_default = existing.get("passive_only", True) if existing else True
    passive = prompter.confirm("passive sources only?", bool(passive_default))
    if passive is None:
        return None
    osint["passive_only"] = passive
    ceiling_default = (
        str(existing.get("autonomous_ceiling", "recon")) if existing else "recon"
    )
    ceiling = prompter.choose(
        "highest OSINT risk tier to run without asking",
        list(_RISK_TIERS),
        ceiling_default,
    )
    if ceiling is None:
        return None
    osint["autonomous_ceiling"] = ceiling
    return (True, osint)


def _ask_burp(
    prompter: Prompter, catalog: Catalog, current: object
) -> tuple[bool, object] | None:
    """Guided Burp scope: enable, the action allow-list, passive-only, the ceiling.

    Mirrors ``_ask_osint`` -- one composite field returning a nested dict (or
    ``None`` when the connector is left disabled), carried under the single
    ``burp`` key and validated by ``EngagementConfig`` in one place.
    """
    existing = current if isinstance(current, dict) else None
    enable = prompter.confirm("enable the Burp connector?", existing is not None)
    if enable is None:
        return None
    if not enable:
        return (True, None)
    actions = list(catalog.burp_actions)
    preset = [str(a) for a in existing.get("allowed_actions", ())] if existing else []
    picks = prompter.multiselect("Burp actions the agent may drive", actions, preset)
    if picks is None:
        return None
    burp: dict[str, object] = {"allowed_actions": picks}
    passive_default = existing.get("passive_only", True) if existing else True
    passive = prompter.confirm("passive Burp actions only?", bool(passive_default))
    if passive is None:
        return None
    burp["passive_only"] = passive
    ceiling_default = (
        str(existing.get("autonomous_ceiling", "active")) if existing else "active"
    )
    ceiling = prompter.choose(
        "highest Burp risk tier to run without asking",
        list(_RISK_TIERS),
        ceiling_default,
    )
    if ceiling is None:
        return None
    burp["autonomous_ceiling"] = ceiling
    return (True, burp)


def _ask_roe(prompter: Prompter, current: object) -> tuple[bool, object] | None:
    """Guided rules of engagement: a yes/no, then authorization + operational fields.

    One composite field returning a nested dict (or ``None`` when skipped), so the
    wizard's flat accumulator carries the whole RoE under ``rules_of_engagement``
    and ``EngagementConfig`` validates it in one place (mirrors ``_ask_osint``).
    """
    existing = current if isinstance(current, dict) else None
    enable = prompter.confirm(
        "record rules of engagement (authorization, exclusions, limits)?",
        existing is not None,
    )
    if enable is None:
        return None
    if not enable:
        return (True, None)
    roe: dict[str, object] = {}
    for key, label in (
        ("authorized_by", "authorized by"),
        ("point_of_contact", "point of contact"),
        ("authorization_reference", "authorization reference (ticket / signed doc)"),
        ("attack_source", "attack-source identity (IP / hostname)"),
        ("max_scan_rate", "max scan rate (free-form, e.g. 100/s)"),
    ):
        shown = str(existing.get(key, "")) if existing else ""
        answer = prompter.ask(_label(label, shown))
        if answer is None:
            return None
        roe[key] = answer.strip() or (existing.get(key, "") if existing else "")
    for key, label in (
        ("prohibited_actions", "prohibited actions (comma-separated)"),
        ("excluded_networks", "excluded networks/IPs (comma-separated)"),
        ("excluded_hosts", "excluded hostnames (comma-separated)"),
    ):
        shown = ", ".join(existing.get(key, ())) if existing else ""
        answer = prompter.ask(_label(label, shown))
        if answer is None:
            return None
        roe[key] = (
            split_csv(answer)
            if answer.strip()
            else list(existing.get(key, ()))
            if existing
            else []
        )
    stealth = prompter.confirm(
        "stealth posture (rate-limit / evasive)?",
        bool(existing.get("stealth", False)) if existing else False,
    )
    if stealth is None:
        return None
    roe["stealth"] = stealth
    return (True, roe)


def collect_scope(
    prompter: Prompter,
    catalog: Catalog,
    *,
    existing: EngagementConfig | None = None,
    into: dict[str, object] | None = None,
    only: frozenset[str] | None = None,
) -> dict[str, object] | None:
    """Walk the sections, collecting answers into a scope dict (unvalidated).

    The accumulator (`into`, else an `existing` dump, else a fresh seed) is
    mutated in place and returned, so a retry preserves earlier answers. `only`
    restricts collection to those field keys (re-asking just what failed) and
    suppresses the step bar for sections with no targeted field. Returns ``None``
    if the operator aborts.
    """
    if into is not None:
        raw = into
    elif existing is not None:
        raw = existing.model_dump(mode="json")
    else:
        raw = {"timezone": "UTC"}

    total = len(_SECTIONS)
    for index, section in enumerate(_SECTIONS, start=1):
        fields = [f for f in section.fields if only is None or f.key in only]
        if not fields:
            continue
        prompter.progress(index, total, section.title)
        for field in fields:
            result = _ask_field(prompter, catalog, field, raw.get(field.key))
            if result is None:
                return None
            changed, value = result
            if changed:
                raw[field.key] = value
    return raw


def run_wizard(
    prompter: Prompter,
    apply: Apply,
    catalog: Catalog,
    *,
    existing: EngagementConfig | None = None,
) -> EngagementConfig | None:
    """Collect scope answers, apply them, and re-ask only what a rejection names.

    `apply` validates and persists the scope (raising ``InvalidScopeError`` with the
    offending field keys, or a plain ``ConfigError``). On a structured rejection
    the wizard re-asks just those fields over the answers already given; on a
    non-field error it re-asks everything (still preserving prior answers). The
    answer dict lives outside the loop, so a typo never discards the session.
    Returns the loaded config, or ``None`` if the operator aborted.
    """
    raw = collect_scope(prompter, catalog, existing=existing)
    if raw is None:
        prompter.notify("engagement setup cancelled")
        return None
    while True:
        try:
            engagement = apply(raw)
        except InvalidScopeError as exc:
            prompter.notify(f"scope rejected: {exc.summary}")
            keys = exc.field_keys & KNOWN_KEYS
            retry = collect_scope(prompter, catalog, into=raw, only=keys or None)
            if retry is None:
                prompter.notify("engagement setup cancelled")
                return None
            raw = retry
            continue
        except ConfigError as exc:
            prompter.notify(f"scope rejected: {exc}")
            retry = collect_scope(prompter, catalog, into=raw)
            if retry is None:
                prompter.notify("engagement setup cancelled")
                return None
            raw = retry
            continue
        prompter.notify(f"engagement '{engagement.name}' loaded")
        return engagement
