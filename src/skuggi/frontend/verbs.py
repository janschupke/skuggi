"""The canonical verb set -- one source of truth for both front-ends.

The wrapped shell is verb-first (``/skuggi <verb> <rest>``); the REPL keeps its
``/verb`` controls with bare text as an implicit ``ask``. Both read the SAME
registry here for the known-verb set, argument hints and the help listing, so the
two dispatch surfaces can never drift (they did, as ``daemon._CONTROL_HELP`` vs
``tui.HELP``). The handlers themselves stay in each front-end because their
rendering differs (Rich tables/colour in the REPL, plain text over the socket).

The grammar is verb-object: the four grouping verbs ``show`` / ``set`` / ``add``
/ ``remove`` each take a *noun* as their first word (``show config``, ``set
model``) and route on it internally. The nouns live in the same registry (a
``Verb.nouns`` tuple) so ``help <verb>`` can enumerate them and a per-front-end
noun router can be drift-checked against ``noun_names(verb)``, exactly as the
top-level handlers are checked against ``KNOWN``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# Keep this module a LEAF: it may import from `skuggi.common` only, never from
# `frontend`/`agent`. `agent.readiness` and `agent.awareness` import it from the
# core layer, which is sound only because it reaches nothing up the stack -- an
# intra-repo import here would turn that into a real core -> frontend dependency.
# Enforced by test_verbs.test_verbs_is_a_leaf_importing_only_common.
from skuggi.common.modes import Mode

Category = Literal["engagement", "control"]

# Help subheadings. Separate from ``category`` (which only routes the audit log)
# so the two concerns never get conflated.
Group = Literal[
    "agent",
    "state",
    "engagement",
    "review",
    "system",
]

# The three front-end surfaces, each with its own command grammar. A hint shown
# on one surface must use that surface's grammar or it will not run there.
Surface = Literal["shell", "chat", "repl"]


def cmd(invocation: str, surface: Surface = "shell") -> str:
    """Format a command hint for the surface the operator is reading it on.

    - ``shell``: the wrapped-shell prompt, where only ``/skuggi <verb>`` runs
      (a bare ``/verb`` is a filesystem path to the real shell).
    - ``chat``: inside the ``/skuggi`` chat loop, where a bare ``<verb>`` runs.
    - ``repl``: the standalone REPL, which dispatches ``/<verb>``.
    """
    if surface == "shell":
        return f"/skuggi {invocation}"
    if surface == "repl":
        return f"/{invocation}"
    return invocation


@dataclass(frozen=True, slots=True)
class Noun:
    """One sub-command of a grouping verb (``show config``, ``set model`` …).

    ``usage`` is the hint that follows the noun, e.g. ``[all|scoped|…]`` for
    ``show tools``; empty when the noun takes no argument. ``options`` is the next
    grammar level down -- the params of a hierarchical noun such as ``set
    engagement`` (``set engagement methodology`` …) -- so help and completion can
    descend one further step; empty for a flat noun.
    """

    name: str
    summary: str
    usage: str = ""
    options: tuple[Noun, ...] = ()


@dataclass(frozen=True, slots=True)
class Verb:
    """One dispatchable action: its name, a one-line summary, and an arg hint.

    ``category`` separates the two logs the harness keeps: ``engagement`` verbs
    (``ask``, ``cmd``, ``add``) direct the engagement and land on the session
    timeline; ``control`` verbs are harness chatter and are recorded to the
    separate audit log instead (see ``AgentCore.note_interaction``). ``group`` is
    purely the help subheading. ``nouns`` is populated only for the grouping
    verbs (``show``/``set``/``add``/``remove``).
    """

    name: str
    summary: str
    usage: str = ""
    category: Category = "control"
    group: Group = "agent"
    nouns: tuple[Noun, ...] = field(default_factory=tuple)
    # The operating modes this verb is available in. Empty = available in every
    # mode (the default). A non-empty tuple is an allow-list: the verb is hidden
    # from ``/help`` and refused at dispatch in any other mode. This is how the
    # offensive verbs drop out of forensics mode and the forensics verb stays out
    # of the offensive modes -- a UX gate; the hard tool boundary is the guard.
    modes: tuple[Mode, ...] = ()


# The three offensive/defensive engagement modes; forensics is excluded. Used to
# scope the engagement-only verbs out of forensics mode.
_OFFENSIVE: tuple[Mode, ...] = ("pentest", "redteam", "blueteam")

# The params of the hierarchical ``set engagement`` noun -- one per editable
# engagement field (plus the ``scope`` NL editor and the runtime vars). Hand-
# written here because this module is a leaf (it cannot import the param
# registry); ``tests/unit/test_verbs.py`` pins these names to
# ``engagement_params.names()`` so the two never drift.
_ENGAGEMENT_OPTIONS: tuple[Noun, ...] = (
    Noun("name", "engagement name", "<name>"),
    Noun("timezone", "IANA timezone", "<iana>"),
    Noun("authorized_start", "authorized window start", "<iso8601>"),
    Noun("authorized_end", "authorized window end", "<iso8601>"),
    Noun("daily_windows", "daily clock windows", "<HH:MM-HH:MM,…>"),
    Noun("target_networks", "in-scope networks", "<cidr,…>"),
    Noun("allowed_hosts", "in-scope hosts", "<host,…>"),
    Noun("allowed_ports", "in-scope ports", "<ports>"),
    Noun("allowed_tools", "permitted tools", "<tool,…>"),
    Noun("allowed_methods", "permitted methods", "<method,…>"),
    Noun(
        "autonomous_ceiling",
        "highest tier auto-run",
        "<recon|active|intrusive|destructive>",
    ),
    Noun("scope", "natural-language scope edit", "<request>"),
    Noun("methodology", "driving framework", "<phases|ptes|attack>"),
    Noun(
        "stance",
        "how forward-leaning proposals are",
        "<passive|cautious|balanced|aggressive>",
    ),
    Noun("taxonomies", "finding taxonomies", "<wstg,attack>"),
    Noun("autonomous", "arm autonomous execution", "[on|off]"),
    Noun("threat_model", "CVSS environmental requirements"),
    Noun("osint", "OSINT reconnaissance scope"),
    Noun("rules_of_engagement", "rules of engagement"),
    Noun("target", "current ${target} host", "<host>"),
    Noun("wordlist", "${wordlist} path", "<path>"),
    Noun("listener", "listener lhost/lport"),
)

# Ordered for the help listing: the everyday agent path first, controls after.
VERBS: tuple[Verb, ...] = (
    Verb(
        "chat",
        "talk to the agent; no argument enters a persistent chat context",
        "[<prompt>]",
        category="engagement",
    ),
    Verb(
        "cmd",
        "search the command cheatsheet; resolve one to scope-check it",
        "<query|list|add|edit|rm|suggest>",
        category="engagement",
        group="agent",
        modes=_OFFENSIVE,
    ),
    Verb(
        "show",
        "inspect state",
        "<what>",
        group="state",
        nouns=(
            Noun("config", "app settings"),
            Noun("mode", "active operating mode"),
            Noun("autonomous", "whether autonomous execution is armed"),
            Noun("provider", "active provider + credential status"),
            Noun("model", "active model"),
            Noun("engagement", "scope summary"),
            Noun("case", "forensics case summary"),
            Noun("env", "runtime command vars (target/lhost/lport/wordlist)"),
            Noun("db", "session ledger stats"),
            Noun("integrity", "verify the timeline + custody tamper-evidence chains"),
            Noun("latency", "last turn's latency breakdown"),
            Noun("sessions", "past sessions with activity counts"),
            Noun("tools", "recognized tools / host status", "[<filter>]"),
            Noun("memory", "remembered operator preferences"),
            Noun("notes", "engagement notes"),
            Noun("loot", "captured loot"),
            Noun("findings", "recorded findings"),
            Noun("coverage", "exercised WSTG/ATT&CK ids vs the enabled taxonomy"),
            Noun("creds", "captured credentials (secrets masked)"),
            Noun("footholds", "registered pivot footholds (secrets masked)"),
            Noun("history", "recent messages on this thread", "[n]"),
            Noun("trace", "the worker's tool calls on this thread"),
            Noun("threads", "conversation threads"),
            Noun("status", "readiness + a session glance"),
            Noun("grants", "active session approval grants"),
        ),
    ),
    Verb(
        "set",
        "change config / session state",
        "<what>",
        group="state",
        nouns=(
            Noun(
                "engagement",
                "adopt/scaffold a root, run the wizard, or edit one field",
                "[<path>|<param> …|setup]",
                options=_ENGAGEMENT_OPTIONS,
            ),
            Noun(
                "case",
                "adopt a forensics case root (cwd by default), scaffolding if absent",
                "[<path>]",
            ),
            Noun("provider", "switch provider (interactive with no name)", "[<name>]"),
            Noun("model", "switch model (interactive with no name)", "[<name>]"),
            Noun("mode", "operating mode", "<pentest|redteam|blueteam|forensics>"),
            Noun(
                "config",
                "set a setting, or a natural-language request",
                "<key> <value>|<request>",
            ),
            Noun("thread", "start or switch a conversation thread", "<id|new>"),
        ),
    ),
    Verb(
        "add",
        "record engagement data",
        "<what>",
        category="engagement",
        group="state",
        nouns=(
            Noun("note", "record a note", "<text>"),
            Noun("loot", "record a loot item", "<text>"),
            Noun(
                "cred",
                "store a captured credential (secret goes to the vault)",
                "<host> <service> <user> <secret>",
            ),
            Noun(
                "foothold",
                "register a pivot foothold (reachable-host commands route through it)",
                "<host> <command|tunnel> <reach,csv> <template>",
            ),
            Noun("finding", "record a finding", "<severity|CVSS> <title>"),
            Noun("memory", "remember an operator preference", "<entry>"),
        ),
    ),
    Verb(
        "remove",
        "delete records",
        "<what>",
        group="state",
        nouns=(
            Noun("memory", "forget a preference, or all of them", "<id|all>"),
            Noun("grants", "revoke all session approval grants"),
            Noun("foothold", "drop all registered pivot footholds"),
        ),
    ),
    Verb(
        "osint",
        "run the autonomous OSINT reconnaissance loop",
        "<request>",
        category="engagement",
        group="agent",
        modes=_OFFENSIVE,
    ),
    Verb(
        "research",
        "research a service / tech / app / company from public sources",
        "<subject or instruction>",
        category="control",
        group="agent",
    ),
    Verb(
        "forensics",
        "run the read-only forensic examination loop over the case evidence",
        "<instruction>",
        category="engagement",
        group="agent",
        modes=("forensics",),
    ),
    Verb(
        "findings",
        "review a finding (approve / reject / rescore)",
        "<approve|reject|rescore>",
        group="review",
    ),
    Verb(
        "report",
        "write a session or engagement report, or add a changelog note",
        "[pdf|engagement|engagement pdf|note <text>]",
        group="review",
    ),
    Verb(
        "visualize",
        "build an interactive HTML dashboard of the whole engagement",
        group="review",
    ),
    Verb(
        "replay",
        "reconstruct & view a session transcript",
        "[list|<session>]",
        group="review",
    ),
    Verb(
        "review",
        "private LLM review of a session (feedback for you)",
        "[<session>]",
        group="review",
    ),
    Verb(
        "doctor",
        "probe host tools / runtimes / net tools",
        "[install <tool>|install missing|research <tool>]",
        group="system",
    ),
    Verb(
        "login",
        "log in to a ChatGPT account (OAuth) for the chatgpt provider",
        group="system",
    ),
    Verb(
        "ingest",
        "index a file or directory into the retrieval store",
        "<path>",
        group="system",
    ),
    Verb(
        "update",
        "update skuggi (git pull --ff-only, then refresh this install)",
        group="system",
    ),
    Verb(
        "reconcile",
        "update installed config from the packaged templates",
        "[diff <file>|<file>|all]",
        group="system",
    ),
    Verb("clear", "clear the screen", group="system"),
    Verb("help", "show this command reference", "[<verb>]", group="system"),
    Verb("exit", "leave skuggi", group="system"),
)

KNOWN: frozenset[str] = frozenset(v.name for v in VERBS)

# Engagement-directed verbs: their activity is the session timeline, so they are
# NOT written to the harness-interaction audit log (every other verb is).
ENGAGEMENT: frozenset[str] = frozenset(
    v.name for v in VERBS if v.category == "engagement"
)

_BY_NAME: dict[str, Verb] = {v.name: v for v in VERBS}

# Grouping verbs that route on a noun, in help subheading order.
_GROUP_ORDER: tuple[Group, ...] = (
    "agent",
    "state",
    "engagement",
    "review",
    "system",
)
_GROUP_TITLES: dict[Group, str] = {
    "agent": "Agent",
    "state": "Commands",
    "engagement": "Engagement",
    "review": "Findings & reporting",
    "system": "Harness",
}

# Bare words that mean "leave", accepted in addition to `exit`.
_EXIT_ALIASES = frozenset({"exit", "quit"})


def is_available(verb: str, mode: Mode) -> bool:
    """Whether `verb` is available in `mode` (unknown verbs are treated as available).

    A verb with no ``modes`` restriction is available everywhere; a restricted verb
    is available only in the modes it lists. The front-ends call this to refuse a
    mode-locked verb at dispatch and to hide it from ``/help``.
    """
    found = _BY_NAME.get(verb)
    if found is None or not found.modes:
        return True
    return mode in found.modes


def is_engagement(verb: str) -> bool:
    """Whether `verb` directs the engagement (vs. being harness control chatter)."""
    return verb in ENGAGEMENT


def nouns_of(verb: str) -> tuple[Noun, ...]:
    """The sub-command nouns of a grouping verb (empty for a plain verb)."""
    found = _BY_NAME.get(verb)
    return found.nouns if found is not None else ()


def noun_names(verb: str) -> frozenset[str]:
    """The noun names of a grouping verb, for drift-checking a front-end router."""
    return frozenset(n.name for n in nouns_of(verb))


def options_of(verb: str, noun: str) -> tuple[Noun, ...]:
    """The sub-options of a hierarchical noun (``set engagement`` -> its params)."""
    for n in nouns_of(verb):
        if n.name == noun:
            return n.options
    return ()


def option_names(verb: str, noun: str) -> frozenset[str]:
    """The option names under `verb noun`, for drift-checking a sub-router."""
    return frozenset(o.name for o in options_of(verb, noun))


def split_verb(line: str) -> tuple[str, str]:
    """Split an input line into ``(verb, rest)``, tolerating a leading ``/``.

    The verb is lower-cased; ``rest`` keeps its original casing (it may be a
    prompt or a path). An empty line yields ``("", "")``.
    """
    stripped = line.strip()
    if stripped.startswith("/"):
        stripped = stripped[1:].lstrip()
    if not stripped:
        return "", ""
    verb, _, rest = stripped.partition(" ")
    return verb.lower(), rest.strip()


def is_exit(verb: str) -> bool:
    """Whether `verb` requests leaving the session."""
    return verb in _EXIT_ALIASES


def _invocation(name: str, usage: str) -> str:
    return name + (f" {usage}" if usage else "")


def help_sections(
    mode: Mode | None = None,
) -> list[tuple[str, list[tuple[str, str]]]]:
    """``(subheading, [(invocation, summary), …])`` groups, in display order.

    The outline is deliberately terse: each verb is one ``(name, summary)`` row
    with **no** argument grammar -- the full usage (and a grouping verb's nouns)
    lives in ``help <verb>`` via ``help_for``. This keeps the top-level reference
    scannable and stops a verb with rich grammar (``doctor``, ``report``) from
    bloating a line. ``invocation`` carries no front-end prefix; the REPL renders
    ``/<invocation>``, the wrapped-shell help ``/skuggi <invocation>``. When `mode`
    is given, verbs unavailable in that mode are omitted; ``None`` (the default)
    lists every verb, which is what the drift test pins.
    """
    sections: list[tuple[str, list[tuple[str, str]]]] = []
    for group in _GROUP_ORDER:
        rows = [
            (v.name, v.summary)
            for v in VERBS
            if v.group == group and (mode is None or is_available(v.name, mode))
        ]
        if rows:
            sections.append((_GROUP_TITLES[group], rows))
    return sections


def help_detail(
    verb: str, noun: str | None = None
) -> list[tuple[str, str, str]] | None:
    """Detailed ``(invocation, usage, summary)`` rows for a verb, or ``None``.

    Unlike :func:`help_for`, the invocation and its argument grammar are kept
    separate so a renderer can paint the command and its params in different
    roles. With `noun` naming a hierarchical noun that has options, yields one row
    per option (``help set engagement`` -> its params); otherwise a grouping verb
    yields one row per noun and a plain verb its single row. ``None`` for an
    unknown verb, or a noun with no options.
    """
    found = _BY_NAME.get(verb)
    if found is None:
        return None
    if noun is not None:
        options = options_of(verb, noun)
        if not options:
            return None
        return [(f"{verb} {noun} {o.name}", o.usage, o.summary) for o in options]
    if found.nouns:
        return [(f"{found.name} {n.name}", n.usage, n.summary) for n in found.nouns]
    return [(found.name, found.usage, found.summary)]


def help_for(verb: str) -> list[tuple[str, str]] | None:
    """Detailed ``(invocation, summary)`` rows for one verb, or ``None`` if unknown.

    A grouping verb yields one row per noun (``show config``, ``show provider`` …);
    a plain verb yields its single usage row. The invocation carries the usage
    grammar joined in; :func:`help_detail` keeps them separate for painting.
    """
    detail = help_detail(verb)
    if detail is None:
        return None
    return [(_invocation(name, usage), summary) for name, usage, summary in detail]
