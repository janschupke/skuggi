"""Presenters for ``set engagement`` -- adopt/scaffold and one-field edits.

Split out of :mod:`skuggi.frontend.presenters` so the engagement-edit rendering
(the scaffold cheatsheet and the per-param result) lives next to its registry
(:mod:`skuggi.frontend.engagement_params`) and keeps the general presenters module
under the file-size cap. Each function maps a typed outcome to a ``render.Styled``,
phrased identically on both surfaces.
"""

from __future__ import annotations

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
