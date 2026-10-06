"""Help rendering for the wrapped-shell daemon / chat loop and the REPL.

Extracted from ``daemon`` so help-formatting lives in one place off the daemon's
dispatch hot path. Both front-ends now render help the same way -- role-painted
``render.Line`` lists (headings for the section titles, the ``command`` role for
an invocation, ``param`` for its argument grammar, ``muted`` for the summary) --
so the Rich REPL and the socket chat loop can no longer look different. Every
invocation is formatted with ``verbs.cmd`` so the grammar matches the surface
(``/skuggi <verb>`` at the shell, a bare ``<verb>`` in the chat loop, ``/<verb>``
in the REPL).
"""

from __future__ import annotations

from skuggi.common import palette
from skuggi.common.modes import Mode
from skuggi.frontend import render, verbs

# The one-line intro per surface -- the same control reads differently depending
# on where it is typed, so the intro names the grammar that works there.
_HELP_INTRO: dict[verbs.Surface, str] = {
    "shell": "skuggi shell commands (/skuggi <verb> <rest>):",
    "chat": "skuggi commands (type a verb):",
    "repl": "skuggi commands (/<verb> <rest>):",
}

# Column width the invocation is padded to before the summary, so the summaries
# line up without a Rich table (the daemon surface has no table).
_PAD = 26


def _row(invocation: str, usage: str, summary: str, *, indent: str) -> render.Line:
    """One ``<indent><command> <usage>   <summary>`` line, painted by role."""
    segments: list[render.Span] = [(indent, None), (invocation, palette.PRIMARY)]
    cell = invocation
    if usage:
        segments.append((f" {usage}", palette.PARAM))
        cell = f"{invocation} {usage}"
    pad = max(1, _PAD - len(cell))
    segments.append((" " * pad, None))
    segments.append((summary, palette.INFO))
    return render.spans(segments)


def help_lines(
    surface: verbs.Surface, mode: Mode, arg: str = "", *, verbose: bool = False
) -> render.Styled:
    """Help for `surface` in `mode`: one verb's detail, or the grouped outline.

    With a verb argument, lists that verb's nouns/usage (the detail view). With no
    argument, the terse grouped outline (name + summary, no grammar); ``verbose``
    expands every verb's full grammar inline instead of only in ``help <verb>``.
    """
    parts = arg.strip().split()
    verb = parts[0] if parts else ""
    noun = parts[1] if len(parts) > 1 else None
    if verb:
        detail = verbs.help_detail(verb, noun)
        if detail is None and noun is not None:
            # An unknown / flat second word: fall back to the verb's own detail.
            detail, noun = verbs.help_detail(verb), None
        if detail is None:
            return [render.danger(f"no such command: {verb}")]
        label = f"{verb} {noun}" if noun else verb
        lines = [render.heading(f"{verbs.cmd(label, surface)}:")]
        lines += [
            _row(verbs.cmd(name, surface), usage, summary, indent="  ")
            for name, usage, summary in detail
        ]
        return lines
    lines = [render.muted(_HELP_INTRO[surface])]
    for title, section_rows in verbs.help_sections(mode):
        lines.append(render.heading(f"  {title}"))
        for name, _summary in section_rows:
            if name == "clear":
                continue
            if verbose:
                for dname, usage, summary in verbs.help_detail(name) or []:
                    lines.append(
                        _row(verbs.cmd(dname, surface), usage, summary, indent="    ")
                    )
            else:
                lines.append(
                    _row(verbs.cmd(name, surface), "", _summary, indent="    ")
                )
    return lines
