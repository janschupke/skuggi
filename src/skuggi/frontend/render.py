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

from rich.console import Console
from rich.markup import escape

from skuggi.common import palette

# Semantic intent of a line; the surface decides the actual styling.
Style = Literal[
    "success",
    "warning",
    "danger",
    "info",
    "plain",
    "heading",
    "command",
    "param",
    "muted",
]

# Semantic style -> Rich style string. ``plain`` is left unpainted (the
# terminal's own foreground); ``heading`` is bold. The four sentiment styles
# route through the palette's reserved constants so colour stays single-sourced.
# The structured-output roles (``command``/``param``/``muted``) ride the palette
# role constants so help, cmd and doctor paint the same hierarchy everywhere.
_STYLE_TO_RICH: dict[Style, str | None] = {
    "success": palette.SUCCESS,
    "warning": palette.WARNING,
    "danger": palette.DANGER,
    "info": palette.INFO,
    "heading": "bold",
    "command": palette.PRIMARY,
    "param": palette.PARAM,
    "muted": palette.INFO,
    "plain": None,
}


# A styled segment within a line: literal text plus the resolved Rich style to
# paint it with (``None`` leaves it unpainted). Spans let one line mix colours --
# notably a severity-coloured finding breakdown -- which a single ``style`` cannot.
Span = tuple[str, str | None]


@dataclass(frozen=True, slots=True)
class Line:
    """One line of output: plain text plus its semantic style.

    A line with ``spans`` carries per-segment colour instead; ``text`` is then the
    concatenation of the span texts (so ``.text`` stays usable for the daemon's
    plain fallback and for substring checks) and ``style`` is ignored.
    """

    text: str
    style: Style = "plain"
    spans: tuple[Span, ...] | None = None


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
    """A bold heading line (a section title / category)."""
    return Line(text, "heading")


def command(text: str) -> Line:
    """An actionable command / invocation line (bright white)."""
    return Line(text, "command")


def param(text: str) -> Line:
    """An argument-placeholder line (accent colour)."""
    return Line(text, "param")


def muted(text: str) -> Line:
    """A muted description / incidental line (dim)."""
    return Line(text, "muted")


def spans(segments: list[Span]) -> Line:
    """A line whose segments carry their own resolved Rich styles (multi-colour).

    Each segment is ``(text, style)`` where ``style`` is a resolved Rich style
    string (e.g. from :func:`skuggi.common.palette.severity_style`) or ``None`` to
    leave that segment unpainted. This is how structural, multi-colour content (a
    severity-coloured finding breakdown) rides the one shared emit path.
    """
    return Line("".join(text for text, _ in segments), "plain", tuple(segments))


def highlight_spans(
    text: str, query: str, *, match: str = palette.MATCH, base: str | None = None
) -> list[Span]:
    """Spans for `text`: each case-insensitive hit of `query` tagged `match`.

    The styled-span counterpart of :func:`skuggi.common.text.highlight` (which
    produces Rich markup): both ride :func:`skuggi.common.text.split_matches`, so
    the daemon's aligned cheatsheet listing highlights the same runs the REPL
    does. Non-match runs take `base` (``None`` = unpainted, the default); `match`
    runs the emphasis style. The per-span text is escaped at render time by
    :func:`to_markup`/:func:`to_ansi`, so it is passed through raw here.
    """
    from skuggi.common.text import split_matches  # noqa: PLC0415 -- avoid import cycle

    return [
        (seg, match if is_match else base)
        for seg, is_match in split_matches(text, query)
    ]


def to_markup(line: Line) -> str:
    """Render `line` as Rich markup for the REPL (unpainted when ``plain``).

    The text is escaped first: it is literal content (a tool renders as
    ``name [binary]``, a command carries its argv), never markup, so a stray
    ``[`` must not be read as a style tag. A spanned line paints each segment
    with its own style, escaping each segment's text the same way.
    """
    if line.spans is not None:
        return "".join(
            escape(text) if style is None else palette.paint(escape(text), style)
            for text, style in line.spans
        )
    text = escape(line.text)
    style = _STYLE_TO_RICH[line.style]
    return palette.paint(text, style) if style is not None else text


def to_ansi(line: Line) -> str:
    """Render `line` as an ANSI string for the wrapped-shell socket.

    The daemon runs on a non-terminal (the socket) while the client writes the
    result to the operator's real terminal, so colour is forced on here --
    mirroring :func:`skuggi.tooling.doctor.table_ansi`. Painting goes through
    :func:`to_markup` so the chat loop and the REPL share the one palette and
    cannot drift; a ``plain`` line stays bare text (no escape codes).
    """
    if line.spans is None and _STYLE_TO_RICH[line.style] is None:
        return line.text
    # highlight=False mirrors the REPL console: Rich's auto-highlighter would
    # otherwise repaint `${target}`, digits and paths in our literal content.
    console = Console(force_terminal=True, width=10_000, highlight=False)
    with console.capture() as capture:
        console.print(to_markup(line), end="", soft_wrap=True)
    return capture.get()
