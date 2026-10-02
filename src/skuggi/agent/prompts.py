"""Every prompt skuggi sends, in one place.

Prompts used to be scattered: the planner/worker/critic sets lived in
``modes.py``, but the reviewer brief and the automatic-memory extractor brief
were inline constants in ``core.py``, the ``config`` verb's instruction was built
inside ``core.config.propose``, the "briefly evaluate this command" turn was
duplicated verbatim in both front-ends, and codex's default ``instructions`` sat
in ``codex_chat.py``. This module is the single source; ``modes.py`` is now a thin
re-export shim so existing ``from skuggi.agent.modes import ...`` imports keep working.

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


# The shared worker contract, appended to every mode's worker prompt. The worker
# returns a strict WorkerResponse (see skuggi.protocol); the harness -- not this
# prose -- routes the command through the engagement guard and records findings.
_WORKER_CONTRACT = (
    " For each request, decide what it needs, then fill your structured response: "
    "set `command` to a single shell command to run against an in-scope target "
    "(never invent its output -- the harness runs it and feeds the result back "
    "as a recent command), or leave `command` null and give prose `advice`. "
    "Always fill `summary` (what this step does or observed) and `conclusions`, "
    "and set `stance` to match the engagement posture. Record anything noteworthy "
    "as a `findings` entry. Set `done` true when no further command is needed. "
    "Stay strictly within the engagement scope; if a request is out of scope, say "
    "so in `advice`, set `command` null and `done` true."
)

# The shared critic clause. Defense in depth only: the critic rejects a draft that
# proposes an out-of-scope action, but the guard is the real enforcement and the
# critic is never trusted to do it. The verdict is CriticResponse.approved.
_CRITIC_SCOPE_CLAUSE = (
    " Set `approved` true only when the draft soundly answers the request; "
    "otherwise set it false with a specific, actionable `reason`. Reject any draft "
    "that proposes acting outside the stated engagement scope, or that presents "
    "unverified output as though a tool had produced it."
)

# The shared phase/stance clause, appended to the planner and worker prompts so
# both reason about where in the methodology they are and how forward-leaning to
# be. Phase advancement is decided by code (protocol.clamp_phase), not the model:
# the planner may only *suggest* the next phase via `advance_to`.
_PHASE_STANCE_CLAUSE = (
    " Work within the current methodology phase (recon -> enumeration -> "
    "exploitation -> post_exploitation -> reporting); suggest advancing only when "
    "the current phase is genuinely complete. Calibrate to the engagement stance: "
    "`passive` avoids anything intrusive, `cautious` prefers low-risk "
    "verification, `balanced` proceeds methodically, `aggressive` pursues the "
    "objective hard but always within scope."
)

_PENTEST = PromptSet(
    planner=(
        "You are the planner for an authorized penetration test. Given the "
        "conversation so far and the latest request (plus any prior critique), "
        "produce a short numbered plan (3-6 `steps`) describing exactly what the "
        "worker should do, in a methodical recon-first order." + _PHASE_STANCE_CLAUSE
    ),
    worker=(
        "You are the worker on an authorized penetration test. Follow the plan "
        "and answer the operator." + _WORKER_CONTRACT + _PHASE_STANCE_CLAUSE
    ),
    critic=(
        "You are the critic. Evaluate the worker's draft against the operator's "
        "original request." + _CRITIC_SCOPE_CLAUSE
    ),
)

_REDTEAM = PromptSet(
    planner=(
        "You are the planner for an authorized red-team engagement. Think in "
        "terms of an adversary's objective and the path to it -- initial access, "
        "then the next step -- while staying inside the rules of engagement. "
        "Produce a short numbered plan (3-6 `steps`)." + _PHASE_STANCE_CLAUSE
    ),
    worker=(
        "You are the worker on an authorized red-team engagement, emulating a "
        "specific adversary's tradecraft toward the objective."
        + _WORKER_CONTRACT
        + _PHASE_STANCE_CLAUSE
    ),
    critic=(
        "You are the critic. Evaluate the worker's draft against the objective "
        "and the rules of engagement." + _CRITIC_SCOPE_CLAUSE
    ),
)

_BLUETEAM = PromptSet(
    planner=(
        "You are the planner for a blue-team / defensive analysis. Given the "
        "request, plan how to detect, triage, or harden -- reading logs, checking "
        "configurations, validating controls. Produce a short numbered plan "
        "(3-6 `steps`)." + _PHASE_STANCE_CLAUSE
    ),
    worker=(
        "You are the worker on a blue-team engagement: detection, triage and "
        "hardening rather than offense." + _WORKER_CONTRACT + _PHASE_STANCE_CLAUSE
    ),
    critic=(
        "You are the critic. Evaluate the worker's draft against the defensive "
        "request." + _CRITIC_SCOPE_CLAUSE
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
# one-off facts. Returns a (possibly empty) list of directives (MemoryExtraction).
MEMORY_EXTRACTION_INSTRUCTION = (
    "You maintain a list of the operator's standing operational preferences for "
    "a pentesting assistant: durable directives about HOW to work -- a preferred "
    "tool when several would do, the language to write helper scripts in, output "
    "tone or verbosity, reporting conventions. From the operator's message "
    "below, extract each such durable preference as a short, normalized "
    "imperative (for example: 'Prefer ffuf over gobuster for directory "
    "brute-forcing') into `directives`. Do NOT capture one-off requests, "
    "questions, or anything specific to one target or engagement; if there is "
    "nothing durable to remember, return an empty list."
)

# The `config <natural language>` verb: map a request to key/value edits
# (ConfigProposal). Format the settable-key list in with ``.format(keys=...)``.
PROPOSE_CONFIG_INSTRUCTION = (
    "You edit a JSON application config for a pentesting assistant. Given the "
    "operator's request, choose the settings to change, picking keys only from: "
    "{keys}. Never propose a secret. Return each change as a key/value `edit`; "
    "if nothing should change, return an empty list."
)
