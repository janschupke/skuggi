"""The canonical verb set -- one source of truth for both front-ends.

The wrapped shell is verb-first (``/skuggi <verb> <rest>``); the REPL keeps its
``/verb`` controls with bare text as an implicit ``ask``. Both read the SAME
registry here for the known-verb set, argument hints and the help listing, so the
two dispatch surfaces can never drift (they did, as ``daemon._CONTROL_HELP`` vs
``tui.HELP``). The handlers themselves stay in each front-end because their
rendering differs (Rich tables/colour in the REPL, plain text over the socket).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Verb:
    """One dispatchable action: its name, a one-line summary, and an arg hint."""

    name: str
    summary: str
    usage: str = ""


# Ordered for the help listing: the everyday agent path first, controls after.
VERBS: tuple[Verb, ...] = (
    Verb("ask", "send a prompt to the agent", "<prompt>"),
    Verb("run", "resolve a command alias, check scope, advise", "<alias> [args]"),
    Verb("findings", "list findings recorded this session"),
    Verb("report", "write a Markdown engagement report"),
    Verb("engagement", "show the loaded engagement scope"),
    Verb("doctor", "probe host tools / runtimes / net tools", "[install <tool>]"),
    Verb("mode", "switch operating mode", "<pentest|redteam|blueteam>"),
    Verb("autonomous", "toggle autonomous command execution", "[on|off]"),
    Verb("provider", "switch LLM provider", "<openai|chatgpt|anthropic|ollama>"),
    Verb("model", "switch model on the current provider", "<name>"),
    Verb("thread", "start / list / resume a conversation thread", "new|list|<id>"),
    Verb("history", "show recent messages on this thread", "[n]"),
    Verb("trace", "show the worker's tool calls on this thread"),
    Verb("ingest", "index a file or directory into the retrieval store", "<path>"),
    Verb("clear", "clear the screen"),
    Verb("help", "show this command reference"),
    Verb("exit", "leave skuggi"),
)

KNOWN: frozenset[str] = frozenset(v.name for v in VERBS)

# Bare words that mean "leave", accepted in addition to `exit`.
_EXIT_ALIASES = frozenset({"exit", "quit"})


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


def help_rows() -> list[tuple[str, str]]:
    """``(invocation, summary)`` rows for the help listing, in registry order.

    ``invocation`` is the verb plus its arg hint (no front-end prefix); the REPL
    renders it as ``/<invocation>``, the wrapped-shell help as
    ``/skuggi <invocation>``.
    """
    return [(v.name + (f" {v.usage}" if v.usage else ""), v.summary) for v in VERBS]
