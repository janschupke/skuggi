"""Operating modes and their prompt sets.

skuggi runs one of three modes -- ``pentest``, ``redteam``, ``blueteam`` --
and the only thing a mode changes is the three prompts the graph's planner,
worker and critic run under. Everything else (the graph shape, the tools, the
engagement guard) is identical, so a mode is nothing more than a
``PromptSet``.

The ``pentest`` set is the former module-level prompts from ``graph.py``,
extended for the pentest UX loop. Every prompt must contain the literal phrase
``"You are the {role}"`` for its role: the graph reads nothing from it, but
``tests.fakes.RoleScriptedChatModel`` dispatches replies by scanning the system
prompt for exactly that phrase, so a reworded opening line would silently
desynchronise every multi-pass harness and eval test. ``test_modes.py`` pins
this so a rewrite fails loudly.
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
