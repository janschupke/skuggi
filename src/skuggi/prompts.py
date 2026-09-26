"""Every prompt skuggi sends, in one place.

Prompts used to be scattered: the planner/worker/critic sets lived in
``modes.py``, but the reviewer brief and the automatic-memory extractor brief
were inline constants in ``core.py``, the ``config`` verb's instruction was built
inside ``AgentCore.propose_config``, the "briefly evaluate this command" turn was
duplicated verbatim in both front-ends, and codex's default ``instructions`` sat
in ``codex_chat.py``. This module is the single source; ``modes.py`` is now a thin
re-export shim so existing ``from skuggi.modes import ...`` imports keep working.

The per-mode :class:`PromptSet` is the only thing an operating mode changes. Every
role prompt must contain the literal phrase ``"You are the {role}"``:
``tests.fakes.RoleScriptedChatModel`` dispatches replies by scanning the system
prompt for exactly that phrase, and ``tests/unit/test_modes.py`` pins it, so a
reworded opening line would silently desynchronise the multi-pass harness tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, get_args

Mode = Literal["pentest", "redteam", "blueteam"]

MODES: tuple[Mode, ...] = get_args(Mode)


@dataclass(frozen=True, slots=True)
class PromptSet:
    """The three system prompts a mode runs the graph under."""

    planner: str
    worker: str
    critic: str


# The shared worker contract, appended to every mode's worker prompt. It is the
# req-#6 UX loop, stated once: evaluate, then advise / propose a command /
# summarize. The proposal path is a `run_command` tool call; the guard in
# `skuggi.engagement` -- not this prose -- is what actually enforces scope.
_WORKER_CONTRACT = (
    " For each request, first decide what it needs, then do exactly one of: "
    "give advice in prose; propose a single shell command by calling the "
    "run_command tool (never invent output -- the tool returns it); or "
    "summarize prior results. Record anything noteworthy with the "
    "record_finding tool, citing the command it came from. Stay strictly within "
    "the engagement scope; if a request is out of scope, say so and stop."
)

# The shared critic contract. Defense in depth only: the scope clause makes the
# critic reject a draft that proposes an out-of-scope action, but the guard is
# the real enforcement and the critic is never trusted to do it.
_CRITIC_SCOPE_CLAUSE = (
    " Also reject any draft that proposes acting outside the stated engagement "
    "scope, or that presents unverified output as though a tool had produced it."
)

# The critic's fixed reply contract, shared by every mode. Only the evaluation
# clause before it differs; keeping the APPROVED/REVISE skeleton in one place
# stops the three copies drifting.
_CRITIC_REPLY_FORMAT = (
    " If it is good, reply exactly:\n"
    "  APPROVED: <one-line reason>\n"
    "Otherwise reply:\n"
    "  REVISE: <specific actionable issue>"
)

_PENTEST = PromptSet(
    planner=(
        "You are the planner for an authorized penetration test. Given the "
        "conversation so far and the latest request (plus any prior critique), "
        "produce a short numbered plan (3-6 steps) describing exactly what the "
        "worker should do, in a methodical recon-first order. Reply with the "
        "plan only."
    ),
    worker=(
        "You are the worker on an authorized penetration test. Follow the plan "
        "and answer the operator." + _WORKER_CONTRACT
    ),
    critic=(
        "You are the critic. Evaluate the worker's draft against the operator's "
        "original request." + _CRITIC_REPLY_FORMAT + _CRITIC_SCOPE_CLAUSE
    ),
)

_REDTEAM = PromptSet(
    planner=(
        "You are the planner for an authorized red-team engagement. Think in "
        "terms of an adversary's objective and the path to it -- initial access, "
        "then the next step -- while staying inside the rules of engagement. "
        "Produce a short numbered plan (3-6 steps). Reply with the plan only."
    ),
    worker=(
        "You are the worker on an authorized red-team engagement, emulating a "
        "specific adversary's tradecraft toward the objective." + _WORKER_CONTRACT
    ),
    critic=(
        "You are the critic. Evaluate the worker's draft against the objective "
        "and the rules of engagement." + _CRITIC_REPLY_FORMAT + _CRITIC_SCOPE_CLAUSE
    ),
)

_BLUETEAM = PromptSet(
    planner=(
        "You are the planner for a blue-team / defensive analysis. Given the "
        "request, plan how to detect, triage, or harden -- reading logs, checking "
        "configurations, validating controls. Produce a short numbered plan "
        "(3-6 steps). Reply with the plan only."
    ),
    worker=(
        "You are the worker on a blue-team engagement: detection, triage and "
        "hardening rather than offense." + _WORKER_CONTRACT
    ),
    critic=(
        "You are the critic. Evaluate the worker's draft against the defensive "
        "request." + _CRITIC_REPLY_FORMAT + _CRITIC_SCOPE_CLAUSE
    ),
)

_MODES: dict[Mode, PromptSet] = {
    "pentest": _PENTEST,
    "redteam": _REDTEAM,
    "blueteam": _BLUETEAM,
}


def prompt_set(mode: Mode) -> PromptSet:
    """Return the prompt set for `mode`."""
    return _MODES[mode]


# --- out-of-graph prompts ---------------------------------------------------

# codex carries the system prompt in `instructions`; this is its default prefix.
CODEX_DEFAULT_INSTRUCTIONS = "You are a helpful assistant."

# The `run <alias>` verb: a one-turn advisory pass over a resolved command. Shared
# by both front-ends (was duplicated verbatim in daemon.py and tui.py). Format the
# resolved command in with ``EVALUATE_RUN.format(command=...)``.
EVALUATE_RUN = (
    "Briefly evaluate this proposed command and note any risks; do not run "
    "anything, just advise: {command}"
)

# The reviewer's brief. Private feedback for the operator, deliberately not
# client-facing (stored in the audit log, never the report).
REVIEW_INSTRUCTION = (
    "You are reviewing a completed penetration-testing session to give the "
    "operator private, candid feedback. This is for the operator only and must "
    "never be shown to a client. From the session timeline below, identify: "
    "bottlenecks (where effort or attention was wasted), missed opportunities "
    "(leads, hosts or services that went unexplored), repeated or wrong commands "
    "(retries, errors, out-of-scope attempts), and process feedback. Be specific "
    "and cite command ids as cmd:N. Be concise and honest; this is a critique, "
    "not a report."
)

# The automatic-memory extractor's brief. It runs post-turn on messages that
# pass the cheap ``preferences.looks_like_directive`` gate, and only durable
# operational preferences (how to work) are wanted -- never target-specific or
# one-off facts. One directive per line, or the literal NONE.
MEMORY_EXTRACTION_INSTRUCTION = (
    "You maintain a list of the operator's standing operational preferences for "
    "a pentesting assistant: durable directives about HOW to work -- a preferred "
    "tool when several would do, the language to write helper scripts in, output "
    "tone or verbosity, reporting conventions. From the operator's message "
    "below, output each such durable preference as a short, normalized "
    "imperative on its own line (for example: 'Prefer ffuf over gobuster for "
    "directory brute-forcing'). Do NOT capture one-off requests, questions, or "
    "anything specific to one target or engagement. If there is nothing durable "
    "to remember, output exactly: NONE"
)
