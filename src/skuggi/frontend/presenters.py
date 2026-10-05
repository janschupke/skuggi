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
from skuggi.common import palette
from skuggi.engagement.runtime_env import EngagementEnv
from skuggi.frontend import render, verbs
from skuggi.frontend.outcomes import (
    EngagementAdopted,
    EngagementScaffolded,
    Installed,
    InstallFailed,
    InstallOutcome,
    InstallUnknown,
    MemoryAdded,
    MemoryAddedOverCap,
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
    SessionStats,
    SetEngagementError,
    SetEngagementOutcome,
)
from skuggi.frontend.render import Styled
from skuggi.install import configdiff, reconcile
from skuggi.persistence.session_summary import (
    command_breakdown,
    finding_breakdown,
    fmt_duration,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from langchain_core.messages import BaseMessage

    from skuggi.agent.protocol import CommandBrief
    from skuggi.agent.readiness import Readiness
    from skuggi.persistence.ledger import ThreadSummary

# ``show history`` renders each message type under a short label; the default
# window and the trace/status truncation caps live here too, so the two front-ends
# share one spelling instead of each re-typing the map and the slice widths.
HISTORY_LABELS = {"human": "you", "ai": "bot", "system": "sys", "tool": "tool"}
DEFAULT_HISTORY_COUNT = 20
TRACE_SUMMARY_CAP = 200
STATUS_LINE_CAP = 100


def usage(invocation: str, surface: verbs.Surface) -> Styled:
    """A single ``usage: <command>`` line, phrased for `surface`."""
    return [render.warning(f"usage: {verbs.cmd(invocation, surface)}")]


def present_history(messages: Sequence[BaseMessage], arg: str) -> Styled:
    """The recent conversation turns (``show history [n]``), newest last.

    ``arg`` is the optional count; a non-numeric or absent one takes the default
    window. Shared by both front-ends so the label map and the window never drift.
    """
    count = int(arg) if arg.isdigit() else DEFAULT_HISTORY_COUNT
    return [
        render.plain(f"{HISTORY_LABELS.get(m.type, m.type)}: {m.text}")
        for m in messages[-count:]
    ]


def present_trace(commands: Sequence[CommandBrief]) -> Styled:
    """The command trail for the active thread (``show trace``).

    Deliberately excluded from ``show history``; each command shows its status, id
    and argv, with a one-line, capped output summary beneath it.
    """
    if not commands:
        return [render.info("(no command activity on this thread)")]
    lines: Styled = []
    for cmd in commands:
        lines.append(render.plain(f"{cmd.status} [cmd:{cmd.id}] {cmd.command}"))
        if cmd.summary:
            summary = cmd.summary.splitlines()[0][:TRACE_SUMMARY_CAP]
            lines.append(render.info(f"  {summary}"))
    return lines


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
        case MemoryAddedOverCap(row, count, maximum):
            return [
                render.success(f"remembered [{row.id}] {row.text}"),
                render.warning(
                    f"memory over capacity ({count}/{maximum}); "
                    "forget some with `remove memory`"
                ),
            ]
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


def present_unavailable(verb: str, mode: str) -> Styled:
    """Render a verb refused because it is not available in the current mode."""
    return [render.warning(f"{verb!r} is not available in {mode} mode")]


def present_case(summary: str | None) -> Styled:
    """Render ``show case``: the adopted forensics case, or an empty state."""
    if summary is None:
        return [render.info("no forensics case loaded -- run `set case [<path>]`")]
    return [render.plain(summary)]


def present_case_adopted(name: str, root: str) -> Styled:
    """Render a ``set case`` adoption: the case name and its root directory."""
    return [
        render.success(f"case adopted: {name}"),
        render.info(root),
    ]


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


def present_env(env: EngagementEnv, scope_default: str | None) -> Styled:
    """Render ``show env``: the runtime vars and where the target comes from.

    The target falls back to the scope-derived first host when unset; the row
    labels its source (manual / scope default / unset) so the operator sees why
    a command's ``${target}`` resolves the way it does. lhost/lport/wordlist are
    shown as set or ``(unset)``.
    """
    if env.target:
        source = "manual"
    elif scope_default:
        source = "scope default"
    else:
        source = "unset"
    target = env.target or scope_default or "(unset)"
    rows = (
        ("target", target, f" [{source}]"),
        ("lhost", env.lhost or "(unset)", ""),
        ("lport", env.lport or "(unset)", ""),
        ("wordlist", env.wordlist or "(unset)", ""),
    )
    return [
        render.heading("runtime vars:"),
        *(
            render.info(f"  {name + ':':<10}{value}{extra}")
            for name, value, extra in rows
        ),
    ]


def present_env_update(name: str, value: str | None) -> Styled:
    """Render a runtime-var change (``set target``/``listener``/``wordlist``)."""
    if value:
        return [render.success(f"{name} set to {value}")]
    return [render.plain(f"{name} cleared")]


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


_STAT_LABEL = 8  # widest status stat label ("commands"/"findings"/"journal")


def _stat(label: str, value: str) -> str:
    return f"{label.ljust(_STAT_LABEL)}  {value}"


def _command_stat_line(stats: SessionStats) -> render.Line:
    """``commands N  (n executed · n blocked …)`` -- plain, no per-token colour."""
    parts = [f"{n} {status}" for status, n in command_breakdown(stats.commands)]
    tail = f"  ({' · '.join(parts)})" if parts else ""
    return render.plain(_stat("commands", f"{len(stats.commands)}{tail}"))


def _finding_stat_line(stats: SessionStats) -> render.Line:
    """``findings N  (n critical · n high …)`` with each severity painted its colour."""
    breakdown = finding_breakdown(stats.findings)
    head = _stat("findings", str(len(stats.findings)))
    if not breakdown:
        return render.plain(head)
    segments: list[render.Span] = [(f"{head}  (", None)]
    for i, (sev, n) in enumerate(breakdown):
        if i:
            segments.append((" · ", None))
        segments.append((f"{n} {sev}", palette.severity_style(sev)))
    segments.append((")", None))
    return render.spans(segments)


def _status_stat_lines(stats: SessionStats) -> Styled:
    """The activity block shared with the exit summary (empty for a quiet session)."""
    if stats.is_empty:
        return []
    lines: Styled = [
        render.plain(_stat("ran for", fmt_duration(stats.elapsed_s))),
        render.plain(_stat("turns", str(stats.turns))),
        _command_stat_line(stats),
        _finding_stat_line(stats),
    ]
    if stats.notes or stats.loot:
        lines.append(
            render.plain(_stat("journal", f"notes {stats.notes} · loot {stats.loot}"))
        )
    return lines


def present_status(
    readiness_now: Readiness, stats: SessionStats, surface: verbs.Surface
) -> Styled:
    """Render ``show status``: the glance, pending steps, drift, and activity stats.

    The activity block (ran for / turns / commands / findings / journal) mirrors the
    exit summary; a session that has done nothing shows no block, keeping the glance
    and the ``ready`` sign-off as before.
    """
    lines: Styled = [render.plain(readiness.glance(readiness_now))]
    notes = readiness.render_banner_notes(readiness_now, surface)
    lines += [render.info(note) for note in notes]
    drift = _drift_note(readiness_now, surface)
    if drift is not None:
        lines.append(render.info(drift))
    stat_lines = _status_stat_lines(stats)
    lines += stat_lines
    if not notes and drift is None and not stat_lines:
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


def _aligned_rows(rows: Sequence[Sequence[str]], aligns: str) -> list[str]:
    """Pad each column to its widest cell so columns line up, joined by two spaces.

    `aligns` gives ``l`` (left) or ``r`` (right) per column; it need only cover the
    columns before the last. The final column is left at its natural width, so a row
    carries no trailing whitespace and a trailing marker can follow it cleanly.
    """
    if not rows:
        return []
    last = len(rows[0]) - 1
    widths = [max(len(row[i]) for row in rows) for i in range(last)]
    out: list[str] = []
    for row in rows:
        cells = [
            cell.rjust(widths[i]) if aligns[i] == "r" else cell.ljust(widths[i])
            for i, cell in enumerate(row[:last])
        ]
        cells.append(row[last])
        out.append("  ".join(cells))
    return out


def present_sessions(rows: list[SessionCount]) -> Styled:
    """Render ``show sessions`` as one aligned row per session, with a legend."""
    if not rows:
        return empty("sessions")
    lines: Styled = [
        render.heading(
            "sessions in this engagement "
            "(id · started · mode · Nt turns · Nc commands · Nf findings; * = current):"
        )
    ]
    # Right-justify each count within its own column so the t/c/f suffixes line up,
    # keeping the single-space grouping; `mode` and the rest align via `_aligned_rows`.
    wt = max(len(str(s.turns)) for s in rows)
    wc = max(len(str(s.commands)) for s in rows)
    wf = max(len(str(s.findings)) for s in rows)
    cells = [
        [
            s.session_id[:8],
            s.started_at,
            s.mode,
            f"{s.turns:>{wt}}t {s.commands:>{wc}}c {s.findings:>{wf}}f",
        ]
        for s in rows
    ]
    for s, row in zip(rows, _aligned_rows(cells, "lll"), strict=True):
        mark = " *" if s.current else ""
        lines.append(render.plain(f"{row}{mark}"))
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
    wt = max(len(str(t.turns)) for t in rows)
    cells = [
        [
            t.thread_id[:8],
            f"{t.turns:>{wt}}t",
            t.last_activity,
            _snippet(t.first_prompt) if t.first_prompt else "(no prompts yet)",
        ]
        for t in rows
    ]
    for t, row in zip(rows, _aligned_rows(cells, "lrl"), strict=True):
        mark = " *" if t.thread_id == current else ""
        lines.append(render.plain(f"{row}{mark}"))
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
