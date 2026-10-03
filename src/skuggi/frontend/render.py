"""One styled-line model so the two front-ends cannot drift.

Every verb's *wording* is produced once (by the ``present_*`` functions in
:mod:`skuggi.frontend.dispatch`) as a list of :class:`Line`: plain text tagged
with a semantic :data:`Style`. Each front-end then renders those lines in its own
way -- the REPL paints them through :mod:`skuggi.common.palette` (Rich markup),
the wrapped-shell daemon emits them as plain text over the socket. Because the
text lives in one place, the REPL and the daemon can no longer say different
things for the same command (they did: missing hints, dropped warnings, diverging
separators). Outputs that are genuinely structural -- Rich tables, Markdown
bodies, severity-painted finding lines -- are not :class:`Line`s; they keep their
own dedicated paths and only share their *content*.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from skuggi.common import palette

# Semantic intent of a line; the surface decides the actual styling.
Style = Literal["success", "warning", "danger", "info", "plain", "heading"]

# Semantic style -> Rich style string. ``plain`` is left unpainted (the
# terminal's own foreground); ``heading`` is bold. The four sentiment styles
# route through the palette's reserved constants so colour stays single-sourced.
_STYLE_TO_RICH: dict[Style, str | None] = {
    "success": palette.SUCCESS,
    "warning": palette.WARNING,
    "danger": palette.DANGER,
    "info": palette.INFO,
    "heading": "bold",
    "plain": None,
}


@dataclass(frozen=True, slots=True)
class Line:
    """One line of output: plain text plus its semantic style."""

    text: str
    style: Style = "plain"


Styled = list[Line]


def success(text: str) -> Line:
    """A success line (green in the REPL)."""
    return Line(text, "success")


def warning(text: str) -> Line:
    """A warning / usage line (yellow in the REPL)."""
    return Line(text, "warning")


def danger(text: str) -> Line:
    """An error line (red in the REPL)."""
    return Line(text, "danger")


def info(text: str) -> Line:
    """A dim, incidental line (paths, hints, empty states)."""
    return Line(text, "info")


def plain(text: str) -> Line:
    """An unstyled line (the terminal's own foreground)."""
    return Line(text, "plain")


def heading(text: str) -> Line:
    """A bold heading line."""
    return Line(text, "heading")


def to_markup(line: Line) -> str:
    """Render `line` as Rich markup for the REPL (unpainted when ``plain``)."""
    style = _STYLE_TO_RICH[line.style]
    return palette.paint(line.text, style) if style is not None else line.text


def to_plain(line: Line) -> str:
    """Render `line` as plain text for the wrapped-shell socket."""
    return line.text
