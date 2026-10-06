"""Presenters for the ``cmd`` cheatsheet and resolved plan (split from presenters).

Kept in their own module so ``presenters`` stays under the line cap; both
front-ends import these the same way they import the rest of the presenter layer.
"""

from __future__ import annotations

from skuggi.common import palette
from skuggi.frontend import render, verbs
from skuggi.frontend.render import Styled


def present_cheatsheet(
    rows: list[tuple[str, str, str]], query: str, *, verbose: bool
) -> Styled:
    """Render the ``cmd`` cheatsheet listing, one source for both front-ends.

    `rows` are ``(name, rendered_command, description)`` -- the caller renders the
    command (it holds the registry) so this stays free of the tooling layer. The
    name paints in the ``command`` role, the description muted; every hit of
    `query` in either reverse-video (``palette.MATCH``). Compact (the default)
    shows the name then an indented description; ``verbose`` inserts the full
    rendered command between them. Line breaks + indents make each entry a small
    block rather than one dense padded row.
    """
    if not rows:
        return [render.muted("no command aliases configured")]
    lines: Styled = []
    for name, rendered, description in rows:
        lines.append(
            render.spans(render.highlight_spans(name, query, base=palette.PRIMARY))
        )
        if verbose and rendered:
            lines.append(render.spans([("    ", None), (rendered, palette.PARAM)]))
        if description:
            lines.append(
                render.spans(
                    [
                        ("    ", None),
                        *render.highlight_spans(description, query, base=palette.INFO),
                    ]
                )
            )
    return lines


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
