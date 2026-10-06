"""Presenters for ``set engagement`` -- adopt/scaffold and one-field edits.

Split out of :mod:`skuggi.frontend.presenters` so the engagement-edit rendering
(the scaffold cheatsheet and the per-param result) lives next to its registry
(:mod:`skuggi.frontend.engagement_params`) and keeps the general presenters module
under the file-size cap. Each function maps a typed outcome to a ``render.Styled``,
phrased identically on both surfaces.
"""

from __future__ import annotations

from skuggi.common import palette
from skuggi.engagement.scope import EngagementConfig
from skuggi.frontend import engagement_params, render, verbs
from skuggi.frontend.outcomes import (
    EngagementAdopted,
    EngagementFieldUpdated,
    EngagementParamError,
    EngagementParamOutcome,
    EngagementScaffolded,
    SetEngagementError,
    SetEngagementOutcome,
)

Styled = render.Styled


def _method_spans(methods: list[str]) -> list[render.Span]:
    """The ``methods:`` line as palette-painted segments (same on both surfaces)."""
    segments: list[render.Span] = [("  methods: ", None)]
    for i, method in enumerate(methods):
        if i:
            segments.append((", ", None))
        segments.append((method, palette.method_style(method)))
    return segments


def present_engagement(
    engagement: EngagementConfig | None, surface: verbs.Surface
) -> Styled:
    """The loaded engagement summary for ``show engagement``, one code path.

    Both front-ends route through here so the summary (and the "nothing loaded"
    hint) cannot drift, and the method names are palette-painted identically on
    the REPL and over the socket. The field layout mirrors
    ``EngagementConfig.describe``, which stays the plain-text formatter for the
    report and dashboard (where colour has no meaning).
    """
    if engagement is None:
        hint = verbs.cmd("set engagement setup", surface)
        return [render.warning(f"no engagement loaded -- run {hint}")]
    e = engagement
    nets = ", ".join(str(n) for n in e.target_networks) or "(none)"
    daily = ", ".join(f"{w.start}-{w.end}" for w in e.daily_windows) or "any"
    hosts = ", ".join(sorted(e.allowed_hosts)) or "(none)"
    start = e.authorized_start.isoformat() if e.authorized_start else "open"
    end = e.authorized_end.isoformat() if e.authorized_end else "open"
    window = (
        "no time bound"
        if e.authorized_start is None and e.authorized_end is None
        else f"{start} -> {end}"
    )
    return [
        render.plain(f"engagement: {e.name}"),
        render.plain(f"  window: {window} ({e.timezone})"),
        render.plain(f"  daily:  {daily}"),
        render.plain(f"  networks: {nets}"),
        render.plain(f"  hosts:  {hosts}"),
        render.plain(f"  tools:  {', '.join(sorted(e.allowed_tools))}"),
        render.spans(_method_spans(sorted(e.allowed_methods))),
        render.plain(f"  stance: {e.stance}"),
        render.plain(f"  autonomous: {e.autonomous}"),
    ]


def present_set_engagement(
    outcome: SetEngagementOutcome, surface: verbs.Surface
) -> Styled:
    """Render a ``set engagement <path>`` adopt/scaffold outcome (both surfaces).

    A scaffold prints the full ``set engagement <param>`` cheatsheet so a freshly
    created, minimal engagement shows exactly how to fill itself in.
    """
    match outcome:
        case EngagementAdopted(name, root):
            return [render.success(f"adopted engagement {name!r} at {root}")]
        case EngagementScaffolded(name, root, scope_path):
            lines = [
                render.info(f"scaffolded a minimal engagement at {scope_path}"),
                render.success(f"adopted engagement {name!r} at {root}"),
                render.muted("fill it in:"),
            ]
            for title, rows in engagement_params.cheatsheet():
                lines.append(render.muted(f"  {title}"))
                lines += [
                    render.plain(f"    {verbs.cmd(inv, surface)}  {summary}")
                    for inv, summary in rows
                ]
            lines.append(
                render.muted(
                    "  or " + verbs.cmd("set engagement setup", surface) + " (wizard)"
                )
            )
            return lines
        case SetEngagementError(message):
            return [render.danger(f"could not set engagement: {message}")]


def present_engagement_param(outcome: EngagementParamOutcome) -> Styled:
    """Render a one-shot ``set engagement <param>`` edit result (both surfaces)."""
    match outcome:
        case EngagementFieldUpdated(name, value):
            return [render.success(f"{name} set to {value}")]
        case EngagementParamError(message):
            return [render.danger(f"could not edit engagement: {message}")]
