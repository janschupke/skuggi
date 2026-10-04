"""Control-verb actions shared by both front-ends.

The wrapped-shell daemon and the Rich REPL route every *non-interactive* control
verb to the same ``run_`` → ``present_`` pairing; only the final emit differs
(ANSI frames over the socket vs Rich markup to the console). This module owns that
pairing once, as functions returning :data:`skuggi.frontend.render.Styled`, so a
control verb's behaviour lives in exactly one place and the two front-ends can
only ever agree.

Each action has the uniform signature ``(core, rest, surface) -> Styled`` so it
can slot into the shared noun tables below; a front-end adapts it by calling it
with its own surface and feeding the result to its own ``_emit``.

Deliberately *not* here, because they genuinely diverge by surface:

- Interactive verbs (the setup wizard, the ``cmd`` editor, natural-language
  config/scope, OAuth login) -- they need a live prompt the socket cannot offer.
- ``set provider``/``set model`` with *no* argument -- the guided picker is
  interactive; only the named path (:func:`set_provider_named`,
  :func:`set_model_named`) is shared.
- Verbs whose two surfaces format bespoke text (``replay``, ``threat-model``,
  ``show db``, ``show history``/``trace``/``notes``/``loot``, ``add`` of a
  finding, which paints its severity only on the Rich surface).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from skuggi.agent import readiness
from skuggi.agent.core import parse_toggle
from skuggi.frontend import dispatch, presenters, presenters_journal, render, verbs
from skuggi.frontend.outcomes import FindingRecorded

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore

# A control action: run the verb against the core and render it for `surface`.
Action = Callable[["AgentCore", str, "verbs.Surface"], "render.Styled"]


# ----- show <noun> -----------------------------------------------------------


def show_provider(core: AgentCore, _rest: str, surface: verbs.Surface) -> render.Styled:
    """Provider readiness: the active provider and whether it can run."""
    return presenters.present_show_provider(readiness.from_core(core), surface)


def show_model(core: AgentCore, _rest: str, _surface: verbs.Surface) -> render.Styled:
    """The active model and provider."""
    return presenters.present_show_model(readiness.from_core(core))


def show_grants(core: AgentCore, _rest: str, _surface: verbs.Surface) -> render.Styled:
    """The active session approval grants."""
    return presenters.present_grants(core.grants.active())


def show_status(core: AgentCore, _rest: str, surface: verbs.Surface) -> render.Styled:
    """A one-glance summary of config readiness plus this session's activity stats."""
    return presenters.present_status(
        dispatch.run_status(core), dispatch.run_session_stats(core), surface
    )


def show_sessions(
    core: AgentCore, _rest: str, _surface: verbs.Surface
) -> render.Styled:
    """The recorded sessions for this engagement."""
    return presenters.present_sessions(dispatch.run_sessions(core))


def show_threads(core: AgentCore, _rest: str, _surface: verbs.Surface) -> render.Styled:
    """The conversation threads on this session, marking the active one."""
    return presenters.present_threads(core.ledger.thread_summaries(), core.thread_id)


def show_memory(core: AgentCore, _rest: str, _surface: verbs.Surface) -> render.Styled:
    """The remembered operator preferences."""
    return presenters.present_memory(dispatch.run_memory(core, ""))


def show_config(core: AgentCore, _rest: str, _surface: verbs.Surface) -> render.Styled:
    """The application config summary (credentials redacted)."""
    return [render.plain(core.config.summary())]


def show_findings(
    core: AgentCore, _rest: str, _surface: verbs.Surface
) -> render.Styled:
    """The recorded findings, severity-painted, flagging threat-model-outdated ones."""
    return presenters_journal.present_findings_list(
        core.journal.findings(), core.ledger.current_threat_model_version()
    )


# ----- set <noun> ------------------------------------------------------------


def set_engagement(core: AgentCore, rest: str, surface: verbs.Surface) -> render.Styled:
    """Adopt the engagement root `rest` (cwd by default), scaffolding if absent."""
    return presenters.present_set_engagement(
        dispatch.run_set_engagement(core, rest), surface
    )


def set_mode(core: AgentCore, rest: str, _surface: verbs.Surface) -> render.Styled:
    """Switch the operating mode, reporting a bad name as an error."""
    try:
        core.set_mode(rest)
    except ValueError as e:
        return presenters.present_error(str(e))
    return presenters.present_mode(core.mode)


def set_autonomous(
    core: AgentCore, rest: str, _surface: verbs.Surface
) -> render.Styled:
    """Arm or disarm autonomous command execution from an on/off toggle."""
    try:
        state = core.set_autonomous(parse_toggle(rest))
    except ValueError as e:
        return presenters.present_error(str(e))
    return presenters.present_autonomous(state)


def set_thread(core: AgentCore, rest: str, _surface: verbs.Surface) -> render.Styled:
    """Start a new conversation thread, or switch to the named one."""
    if rest in ("new", ""):
        return presenters.present_thread("new", core.new_thread())
    core.set_thread(rest)
    return presenters.present_thread("switch", rest)


def set_provider_named(
    core: AgentCore, name: str, surface: verbs.Surface
) -> render.Styled:
    """Switch to the named provider (the no-argument picker is per front-end)."""
    return presenters.present_provider(dispatch.run_provider(core, name), surface)


def set_model_named(
    core: AgentCore, name: str, surface: verbs.Surface
) -> render.Styled:
    """Switch to the named model (the no-argument picker is per front-end)."""
    return presenters.present_model(dispatch.run_model(core, name), surface)


# ----- add / remove <noun> ---------------------------------------------------


def add_memory(core: AgentCore, rest: str, surface: verbs.Surface) -> render.Styled:
    """Remember an operator preference (``add memory <entry>``)."""
    if not rest:
        return presenters.usage("add memory <entry>", surface)
    return presenters.present_memory(dispatch.run_memory(core, f"add {rest}"))


def add_record_for(noun: str) -> Action:
    """An ``add note|loot|finding`` action for `noun` (the record kind).

    A finding keeps its severity colour via
    :func:`presenters_journal.present_finding_recorded`; a note/loot renders through
    the shared :func:`presenters.present_add`. Branching here (not in each
    front-end) is what removed the duplicated ``FindingRecorded`` special-case.
    """

    def action(core: AgentCore, rest: str, surface: verbs.Surface) -> render.Styled:
        outcome = dispatch.run_add(core, f"{noun} {rest}".strip())
        if isinstance(outcome, FindingRecorded):
            return presenters_journal.present_finding_recorded(outcome.row)
        return presenters.present_add(outcome, surface)

    return action


def remove_memory(core: AgentCore, rest: str, surface: verbs.Surface) -> render.Styled:
    """Forget one preference (``remove memory <id>``) or every one (``all``)."""
    if rest == "all":
        return presenters.present_memory(dispatch.run_memory(core, "clear"))
    if not rest.isdigit():
        return presenters.usage("remove memory <id> | all", surface)
    return presenters.present_memory(dispatch.run_memory(core, f"forget {rest}"))


def remove_grants(
    core: AgentCore, _rest: str, _surface: verbs.Surface
) -> render.Styled:
    """Revoke every active session approval grant."""
    return presenters.present_grants_revoked(core.grants.revoke_all())


# ----- verb-level actions (no noun) ------------------------------------------


def resolve_cmd(core: AgentCore, name: str, surface: verbs.Surface) -> render.Styled:
    """Render the resolved shell plan for the exact cheatsheet alias `name`."""
    return presenters.present_cmd_plan(core.cmds.plan(name), surface)


def reconcile(core: AgentCore, rest: str, surface: verbs.Surface) -> render.Styled:
    """Reconcile the installed config against the packaged templates."""
    return presenters.present_reconcile(dispatch.run_reconcile(core, rest), surface)


def report(core: AgentCore, rest: str, surface: verbs.Surface) -> render.Styled:
    """Add a changelog note, or write an engagement report."""
    return presenters_journal.present_report(dispatch.run_report(core, rest), surface)


def visualize(core: AgentCore, _rest: str, _surface: verbs.Surface) -> render.Styled:
    """Write the engagement visualization."""
    return presenters_journal.present_visualize(dispatch.run_visualize(core))


def ingest(core: AgentCore, rest: str, surface: verbs.Surface) -> render.Styled:
    """Index a file or directory of docs into the retrieval store."""
    return presenters_journal.present_ingest(dispatch.run_ingest(core, rest), surface)


# ----- shared noun tables ----------------------------------------------------
# Each front-end merges these (adapted to its emit) with its own bespoke and
# interactive nouns, so the noun -> action mapping is single-source here.

SHOW_ACTIONS: dict[str, Action] = {
    "provider": show_provider,
    "model": show_model,
    "grants": show_grants,
    "status": show_status,
    "sessions": show_sessions,
    "threads": show_threads,
    "memory": show_memory,
    "config": show_config,
    "findings": show_findings,
}

SET_ACTIONS: dict[str, Action] = {
    "engagement": set_engagement,
    "mode": set_mode,
    "autonomous": set_autonomous,
    "thread": set_thread,
}

REMOVE_ACTIONS: dict[str, Action] = {
    "memory": remove_memory,
    "grants": remove_grants,
}
