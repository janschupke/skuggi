"""Plain-text help rendering for the wrapped-shell daemon / chat loop.

Extracted from ``daemon`` so the help-formatting lives in one place off the daemon's
dispatch hot path (and the daemon stays within its size budget). The REPL renders
help as a Rich table instead -- genuinely different output -- so it keeps its own
renderer; this is the plain, one-command-per-line form the socket surfaces emit.
Every invocation is formatted with ``verbs.cmd`` so the grammar matches the surface
(``/skuggi <verb>`` at the shell, a bare ``<verb>`` in the chat loop).
"""

from __future__ import annotations

from skuggi.common.modes import Mode
from skuggi.frontend import verbs

# The one-line intro per surface -- the same control reads differently depending on
# where it is typed, so the intro names the grammar that works there.
_HELP_INTRO: dict[verbs.Surface, str] = {
    "shell": "skuggi shell commands (/skuggi <verb> <rest>):",
    "chat": "skuggi commands (type a verb):",
    "repl": "skuggi commands (/<verb> <rest>):",
}


def plain_help(surface: verbs.Surface, mode: Mode, arg: str = "") -> str:
    """Render help for `surface` in `mode`: one verb's nouns, or the full listing.

    With a verb argument, lists that verb's nouns/usage; otherwise the grouped
    command listing, filtered to the verbs available in `mode`.
    """
    verb = arg.strip().split(" ", 1)[0]
    if verb:
        rows = verbs.help_for(verb)
        if rows is None:
            return f"no such command: {verb}\n"
        lines = [
            f"{verbs.cmd(verb, surface)}:",
            *(f"  {verbs.cmd(inv, surface):<40} {summary}" for inv, summary in rows),
        ]
        return "\n".join(lines) + "\n"
    lines = [_HELP_INTRO[surface]]
    for title, section_rows in verbs.help_sections(mode):
        lines.append(f"  {title}:")
        lines += [
            f"    {verbs.cmd(inv, surface):<38} {summary}"
            for inv, summary in section_rows
            if not inv.startswith("clear")
        ]
    return "\n".join(lines) + "\n"
