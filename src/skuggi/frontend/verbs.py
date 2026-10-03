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
    ``show tools``; empty when the noun takes no argument.
    """

    name: str
    summary: str
    usage: str = ""


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


# Ordered for the help listing: the everyday agent path first, controls after.
VERBS: tuple[Verb, ...] = (
    Verb("ask", "send a prompt to the agent", "<prompt>", category="engagement"),
    Verb(
        "cmd",
        "search the command cheatsheet; resolve one to scope-check it",
        "<query|list|add|edit|rm>",
        category="engagement",
        group="agent",
    ),
    Verb(
        "show",
        "inspect state",
        "<what>",
        group="state",
        nouns=(
            Noun("config", "app settings"),
            Noun("provider", "active provider + credential status"),
            Noun("model", "active model"),
            Noun("engagement", "scope summary"),
            Noun("db", "session ledger stats"),
            Noun("sessions", "past sessions with activity counts"),
            Noun("tools", "recognized tools / host status", "[filter]"),
            Noun("memory", "remembered operator preferences"),
            Noun("notes", "engagement notes"),
            Noun("loot", "captured loot"),
            Noun("findings", "recorded findings"),
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
            Noun("provider", "switch provider (interactive with no name)", "[<name>]"),
            Noun("model", "switch model (interactive with no name)", "[<name>]"),
            Noun("mode", "operating mode", "<pentest|redteam|blueteam>"),
            Noun("autonomous", "arm autonomous command execution", "[on|off]"),
            Noun(
                "config",
                "set a setting, or a natural-language request",
                "<key> <value> | <request>",
            ),
            Noun("thread", "start or switch a conversation thread", "<id>|new"),
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
            Noun("memory", "forget a preference, or all of them", "<id> | all"),
            Noun("grants", "revoke all session approval grants"),
        ),
    ),
    Verb(
        "engagement",
        "run setup, scaffold a scope file, or set the threat model",
        "<setup|scaffold|threat-model>",
        group="engagement",
    ),
    Verb(
        "findings",
        "review a finding (approve / reject / rescore)",
        "<approve|reject|rescore>",
        group="review",
    ),
    Verb(
        "report",
        "write an engagement report, or add a changelog note",
        "[pdf | note <text>]",
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
        "[list | <session>]",
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
        "[install <tool>]",
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
        "update installed config from the packaged templates (diff/overwrite)",
        "[list | diff <file> | overwrite <file>]",
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


def help_sections() -> list[tuple[str, list[tuple[str, str]]]]:
    """``(subheading, [(invocation, summary), …])`` groups, in display order.

    A grouping verb appears as one collapsed row (``show <what>``); its nouns are
    reached through ``help_for``. ``invocation`` carries no front-end prefix; the
    REPL renders ``/<invocation>``, the wrapped-shell help ``/skuggi <invocation>``.
    """
    sections: list[tuple[str, list[tuple[str, str]]]] = []
    for group in _GROUP_ORDER:
        rows = [
            (_invocation(v.name, v.usage), v.summary) for v in VERBS if v.group == group
        ]
        if rows:
            sections.append((_GROUP_TITLES[group], rows))
    return sections


def help_for(verb: str) -> list[tuple[str, str]] | None:
    """Detailed ``(invocation, summary)`` rows for one verb, or ``None`` if unknown.

    A grouping verb yields one row per noun (``show config``, ``show provider`` …);
    a plain verb yields its single usage row.
    """
    found = _BY_NAME.get(verb)
    if found is None:
        return None
    if found.nouns:
        return [
            (_invocation(f"{found.name} {n.name}", n.usage), n.summary)
            for n in found.nouns
        ]
    return [(_invocation(found.name, found.usage), found.summary)]
