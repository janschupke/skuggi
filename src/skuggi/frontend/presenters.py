"""Rendering for the control verbs: outcome -> styled lines.

The two front-ends differ in their final emit (Rich markup in the REPL, ANSI over
the daemon socket) but share this view layer: every ``present_*`` maps a typed
outcome from :mod:`skuggi.frontend.outcomes` to a ``render.Styled``, phrased for a
``verbs.Surface``. Keeping it apart from :mod:`skuggi.frontend.dispatch` (the
logic) is what stops the two surfaces drifting on the same command.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from skuggi.agent import readiness
from skuggi.frontend import render, verbs
from skuggi.frontend.outcomes import (
    AddedLoot,
    AddedNote,
    AddOutcome,
    AddUsage,
    BadSeverity,
    EngagementAdopted,
    EngagementScaffolded,
    FindingRecorded,
    Installed,
    InstallFailed,
    InstallOutcome,
    InstallUnknown,
    MemoryAdded,
    MemoryAlreadyKnown,
    MemoryCleared,
    MemoryForgotten,
    MemoryList,
    MemoryMissing,
    MemoryOutcome,
    MemoryUsage,
    ModelError,
    ModelNoCredential,
    ModelOutcome,
    ModelSwitched,
    ModelUsage,
    NoEngagement,
    ProviderError,
    ProviderNoCredential,
    ProviderOutcome,
    ProviderSwitched,
    ProviderUnknown,
    ProviderUsage,
    ReconcileAll,
    ReconcileDiff,
    ReconcileList,
    ReconcileOutcome,
    ReconcileOverwritten,
    ReconcileRow,
    ReconcileUnknown,
    ReconcileUsage,
    SessionCount,
    SetEngagementError,
    SetEngagementOutcome,
)
from skuggi.frontend.render import Styled
from skuggi.install import configdiff, reconcile

if TYPE_CHECKING:
    from pathlib import Path

    from skuggi.agent.readiness import Readiness
    from skuggi.persistence.ledger import ThreadSummary


def usage(invocation: str, surface: verbs.Surface) -> Styled:
    """A single ``usage: <command>`` line, phrased for `surface`."""
    return [render.warning(f"usage: {verbs.cmd(invocation, surface)}")]


def empty(kind: str) -> Styled:
    """A single ``(no <kind> yet)`` empty-state line (uniform across verbs)."""
    return [render.info(f"(no {kind} yet)")]


def present_provider(outcome: ProviderOutcome, surface: verbs.Surface) -> Styled:
    """Render the result of switching provider."""
    match outcome:
        case ProviderUsage():
            return usage("set provider <name>", surface)
        case ProviderUnknown(message):
            return [render.danger(message)]
        case ProviderNoCredential(provider):
            fix = verbs.cmd("set provider", surface)
            return [
                render.warning(f"{provider} isn't configured -- run {fix} to add a key")
            ]
        case ProviderError(message):
            return [render.danger(f"provider error: {message}")]
        case ProviderSwitched(provider, model):
            return [render.info(f"switched to {provider}/{model or '(default)'}")]


def present_model(outcome: ModelOutcome, surface: verbs.Surface) -> Styled:
    """Render the result of switching model."""
    match outcome:
        case ModelUsage():
            return usage("set model <name>", surface)
        case ModelNoCredential(provider):
            fix = verbs.cmd("set provider", surface)
            return [
                render.warning(
                    f"can't switch model: {provider} isn't configured "
                    f"-- run {fix} first"
                )
            ]
        case ModelError(message):
            return [render.danger(f"provider error: {message}")]
        case ModelSwitched(provider, model):
            return [render.info(f"switched to {provider}/{model}")]


def present_memory(outcome: MemoryOutcome) -> Styled:  # noqa: PLR0911 -- one return per outcome
    """Render a memory outcome (callers pre-validate, so no usage case)."""
    match outcome:
        case MemoryUsage():  # pragma: no cover -- callers validate before calling
            return []
        case MemoryAdded(row):
            return [render.success(f"remembered [{row.id}] {row.text}")]
        case MemoryAlreadyKnown():
            return [render.info("already remembered")]
        case MemoryForgotten():
            return [render.info("forgotten")]
        case MemoryMissing(ref):
            return [render.warning(f"no preference {ref}")]
        case MemoryCleared(count):
            return [render.info(f"cleared {count} preference(s)")]
        case MemoryList(rows):
            if not rows:
                return empty("memories")
            return [render.plain(f"[{r.id}] {r.text} ({r.source})") for r in rows]


def present_add(outcome: AddOutcome, surface: verbs.Surface) -> Styled:
    """Render note/loot/usage add outcomes.

    A recorded FINDING is NOT handled here (the front-end paints its severity via
    ``finding_line``); callers branch on ``FindingRecorded`` before calling.
    """
    match outcome:
        case AddUsage(form):
            return usage(f"add {form}", surface)
        case NoEngagement(kind):
            fix = verbs.cmd("engagement setup", surface)
            return [
                render.warning(f"no engagement loaded -- run {fix} to record {kind}s")
            ]
        case BadSeverity(value, allowed):
            choices = ", ".join(allowed)
            return [
                render.danger(f"unknown severity {value!r}; choose one of: {choices}")
            ]
        case AddedNote(path):
            return [render.success(f"noted {path}")]
        case AddedLoot(path):
            return [render.success(f"loot recorded {path}")]
        case FindingRecorded():  # pragma: no cover -- caller renders findings
            return []


def present_install(outcome: InstallOutcome) -> Styled:
    """Render a ``doctor install`` outcome."""
    match outcome:
        case InstallUnknown(binary):
            return [render.danger(f"unknown tool: {binary!r}")]
        case Installed(binary, version, source):
            return [
                render.success(f"installed {binary} ({version or '?'}) via {source}")
            ]
        case InstallFailed(binary):
            return [render.danger(f"install failed or unavailable for {binary}")]


def present_mode(mode: str) -> Styled:
    """Render a mode switch."""
    return [render.info(f"mode: {mode}")]


def present_grants(active: tuple[str, ...]) -> Styled:
    """Render ``show grants``: the capabilities approved for this session."""
    if not active:
        return [render.plain("no active session grants")]
    return [render.heading("session grants:")] + [
        render.info(f"  {cap}") for cap in active
    ]


def present_grants_revoked(count: int) -> Styled:
    """Render ``remove grants``: how many session grants were cleared."""
    noun = "grant" if count == 1 else "grants"
    return [render.plain(f"revoked {count} session {noun}")]


def present_autonomous(state: bool) -> Styled:
    """Render an autonomous toggle, keeping the scope warning on BOTH surfaces."""
    if state:
        return [
            render.danger(
                "autonomous execution is now ON -- proposed commands will "
                "EXECUTE within scope"
            )
        ]
    return [render.plain("autonomous execution is now off")]


def present_thread(action: str, value: str) -> Styled:
    """Render a thread action (``new`` -> value is the id; else a switch)."""
    if action == "new":
        return [render.info(f"new thread: {value}")]
    return [render.info(f"switched to thread: {value}")]


def present_error(message: str) -> Styled:
    """A single error line (e.g. a ValueError from set mode/autonomous/thread)."""
    return [render.danger(message)]


def present_cmd_plan(plan: object, surface: verbs.Surface) -> Styled:  # noqa: ARG001
    """Render a resolved ``cmd`` plan (rendered command + scope verdict).

    `plan` is a ``commandbook.RunPlan``; typed loosely to avoid importing the
    agent layer here. Never fires an agent turn -- it only presents.
    """
    from skuggi.agent.commandbook import RunPlan  # noqa: PLC0415 -- avoid import cycle

    assert isinstance(plan, RunPlan)  # noqa: S101
    if not plan.known:
        return [render.warning(plan.note)]
    lines: Styled = [render.heading(f"$ {plan.raw}")]
    if plan.verdict is not None and not plan.verdict.allowed:
        lines.append(render.danger(f"OUT OF SCOPE: {plan.note}"))
    elif plan.verdict is None:
        lines.append(render.warning(plan.note))
    else:
        lines.append(
            render.success(
                f"{plan.note} -- recorded proposed (cmd:{plan.command_id}); "
                "submit it yourself"
            )
        )
    return lines


def _drift_note(readiness_now: Readiness, surface: verbs.Surface) -> str | None:
    """The config-drift line for ``show status`` (``None`` when nothing drifted).

    Drift is deliberately off the passive banner (config is meant to be edited),
    so the explicit ``show status`` query -- and reinstall / update -- is where it
    is surfaced.
    """
    if not readiness_now.stale_configs:
        return None
    names = ", ".join(readiness_now.stale_configs)
    return (
        f"{len(readiness_now.stale_configs)} config file(s) behind the packaged "
        f"templates ({names}) -- run {verbs.cmd('reconcile', surface)}"
    )


def present_status(readiness_now: Readiness, surface: verbs.Surface) -> Styled:
    """Render ``show status``: the shared glance, pending steps, and any drift."""
    lines: Styled = [render.plain(readiness.glance(readiness_now))]
    notes = readiness.render_banner_notes(readiness_now, surface)
    lines += [render.info(note) for note in notes]
    drift = _drift_note(readiness_now, surface)
    if drift is not None:
        lines.append(render.info(drift))
    if not notes and drift is None:
        lines.append(render.success("ready"))
    return lines


_RECONCILE_STYLE = {
    "up_to_date": render.success,
    "drifted": render.warning,
    "missing": render.info,
}


def _diff_sections(diff: configdiff.StructuredDiff) -> Styled:
    """The Added / Removed / Changed sections of a structured diff (coloured)."""
    lines: Styled = []
    if diff.added:
        lines.append(render.heading("Added:"))
        lines += [render.success(f"  {entry}") for entry in diff.added]
    if diff.removed:
        lines.append(render.heading("Removed:"))
        lines += [render.danger(f"  {entry}") for entry in diff.removed]
    if diff.changed:
        lines.append(render.heading("Changed:"))
        lines += [
            render.warning(f"  {c.path}  {c.old} => {c.new}") for c in diff.changed
        ]
    return lines


def _reconcile_list_lines(
    rows: tuple[ReconcileRow, ...], surface: verbs.Surface
) -> Styled:
    """The ``reconcile`` listing: one status line per file, plus a how-to footer."""
    lines: Styled = [render.heading("installed config vs packaged templates:")]
    for row in rows:
        s = row.status
        mag = (
            f"  (+{row.added} \N{MINUS SIGN}{row.removed} ~{row.changed})"
            if s.state == "drifted"
            else ""
        )
        lines.append(_RECONCILE_STYLE[s.state](f"  {s.name:<16} {s.state}{mag}"))
    if any(r.status.state == "drifted" for r in rows):
        lines.append(
            render.info(
                "update one with "
                + verbs.cmd("reconcile <file>", surface)
                + ", all with "
                + verbs.cmd("reconcile all", surface)
                + " (a backup is saved); inspect with "
                + verbs.cmd("reconcile diff <file>", surface)
            )
        )
    return lines


def _reconcile_diff_lines(
    name: str, diff: configdiff.StructuredDiff, surface: verbs.Surface
) -> Styled:
    """The ``reconcile diff`` view: the structured diff, plus an apply hint."""
    if diff.empty:
        return [render.success(f"{name} is up to date with the packaged template")]
    lines: Styled = [render.heading(f"{name}: installed -> packaged")]
    lines += _diff_sections(diff)
    lines.append(
        render.info(
            "apply with "
            + verbs.cmd(f"reconcile {name}", surface)
            + " (a backup is saved)"
        )
    )
    return lines


def _reconcile_all_lines(results: tuple[tuple[str, Path | None], ...]) -> Styled:
    """The ``reconcile all`` summary: each file updated, with its backup path."""
    if not results:
        return [render.success("all config files already up to date")]
    lines: Styled = [render.heading("updated from the packaged templates:")]
    for name, backup in results:
        lines.append(render.success(f"  {name}"))
        if backup is not None:
            lines.append(render.info(f"    backup saved: {backup}"))
    return lines


def present_reconcile(  # noqa: PLR0911 -- one return per outcome
    outcome: ReconcileOutcome, surface: verbs.Surface
) -> Styled:
    """Render a ``reconcile`` outcome identically on both surfaces."""
    match outcome:
        case ReconcileUsage():
            return [
                render.warning(
                    "usage: "
                    + verbs.cmd("reconcile [diff <file> | <file> | all]", surface)
                )
            ]
        case ReconcileUnknown(name):
            choices = ", ".join(reconcile.known_names())
            return [
                render.danger(f"unknown config file {name!r}; choose one of: {choices}")
            ]
        case ReconcileList(rows):
            return _reconcile_list_lines(rows, surface)
        case ReconcileDiff(name, diff):
            return _reconcile_diff_lines(name, diff, surface)
        case ReconcileOverwritten(name, backup):
            done = render.success(f"{name} updated from the packaged template")
            if backup is not None:
                return [done, render.info(f"backup saved: {backup}")]
            return [done]
        case ReconcileAll(results):
            return _reconcile_all_lines(results)


def present_sessions(rows: list[SessionCount]) -> Styled:
    """Render ``show sessions`` as one compact line per session, with a legend."""
    if not rows:
        return empty("sessions")
    lines: Styled = [
        render.heading(
            "sessions in this engagement "
            "(id · started · mode · Nt turns · Nc commands · Nf findings; * = current):"
        )
    ]
    for s in rows:
        mark = " *" if s.current else ""
        lines.append(
            render.plain(
                f"{s.session_id[:8]}  {s.started_at}  {s.mode}  "
                f"{s.turns}t {s.commands}c {s.findings}f{mark}"
            )
        )
    return lines


def _snippet(text: str, width: int = 48) -> str:
    """A one-line, length-capped snippet of `text` for a list row."""
    flat = " ".join(text.split())
    return flat if len(flat) <= width else flat[: width - 1] + "…"


def present_threads(rows: list[ThreadSummary], current: str) -> Styled:
    """Render ``show threads`` so each thread is recognisable and resumable."""
    if not rows:
        return empty("threads")
    lines: Styled = [
        render.heading(
            "threads on this engagement "
            "(id · Nt turns · last activity · first prompt; * = current):"
        )
    ]
    for t in rows:
        mark = " *" if t.thread_id == current else ""
        label = _snippet(t.first_prompt) if t.first_prompt else "(no prompts yet)"
        lines.append(
            render.plain(
                f"{t.thread_id[:8]}  {t.turns}t  {t.last_activity}  {label}{mark}"
            )
        )
    return lines


def present_show_provider(readiness_now: Readiness, surface: verbs.Surface) -> Styled:
    """Render ``show provider`` (active provider + whether it's configured)."""
    if readiness_now.provider_configured:
        state = "configured"
    else:
        state = f"not configured -- run {verbs.cmd('set provider', surface)}"
    return [render.plain(f"provider {readiness_now.provider} -- {state}")]


def present_show_model(readiness_now: Readiness) -> Styled:
    """Render ``show model`` (active model and its provider)."""
    return [
        render.plain(
            f"model {readiness_now.model} on provider {readiness_now.provider}"
        )
    ]


def present_findings_usage(surface: verbs.Surface) -> Styled:
    """Render the ``findings`` review usage + a pointer to the listing."""
    return [
        render.warning(
            f"usage: {verbs.cmd('findings <approve|reject|rescore>', surface)}"
        ),
        render.info(f"list findings with {verbs.cmd('show findings', surface)}"),
    ]


def present_unknown(verb: str, surface: verbs.Surface) -> Styled:
    """Render an unknown-command error, pointing at help (same on both surfaces)."""
    return [
        render.danger(f"unknown command: {verb!r} -- try {verbs.cmd('help', surface)}")
    ]


def present_set_engagement(
    outcome: SetEngagementOutcome, surface: verbs.Surface
) -> Styled:
    """Render a ``set engagement`` outcome identically on both surfaces."""
    match outcome:
        case EngagementAdopted(name, root):
            return [render.success(f"adopted engagement {name!r} at {root}")]
        case EngagementScaffolded(name, root, scope_path):
            return [
                render.info(f"scaffolded a scope template at {scope_path}"),
                render.success(f"adopted engagement {name!r} at {root}"),
                render.info(
                    "edit the scope with "
                    + verbs.cmd("engagement setup", surface)
                    + f" or by editing {scope_path}"
                ),
            ]
        case SetEngagementError(message):
            return [render.danger(f"could not set engagement: {message}")]
