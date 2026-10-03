"""The wrapped shell's startup banner.

A pure renderer so ``shell.main()`` (which is ``# pragma: no cover`` -- it
launches a child shell + daemon) stays wiring-only and the banner's layout is
unit-tested. Returns one Rich-markup string; the caller prints it through a Rich
``Console``. Styling draws on the shared :mod:`skuggi.common.palette` so the
wrapped shell reads the same as the REPL, and the verb invocations are formatted
through :func:`skuggi.frontend.verbs.cmd` so the shell grammar can never drift
from the dispatcher.
"""

from __future__ import annotations

from skuggi.common import palette
from skuggi.frontend import verbs

# (invocation, what it does) for the four things the operator needs at a glance.
# The invocation is run through ``verbs.cmd`` (shell surface) to become the real
# ``/skuggi …`` the hook dispatches.
_VERBS: tuple[tuple[str, str], ...] = (
    ("", "opens a chat loop"),
    ("ask <prompt>", "asks once"),
    ("help", "lists verbs"),
    ("exit", "leaves"),
)


def render_startup_banner(
    *,
    engagement: str | None,
    has_llm: bool,
    warnings: list[str],
    unsupported_shell: str | None,
) -> str:
    """Compose the wrapped shell's startup banner as a Rich-markup string.

    ``engagement`` is the scoped engagement name (``None`` -> agent-only, which
    adds the scope-an-engagement next step); ``has_llm`` False adds the
    configure-a-model next step; ``warnings`` are ``core.warnings`` verbatim;
    ``unsupported_shell`` is the shell's name when it cannot take the hook, else
    ``None``.
    """
    lines: list[str] = [f"{palette.SHIELD} [bold]skuggi shell[/bold]", ""]

    hints = [(verbs.cmd(inv), what) for inv, what in _VERBS]
    width = max(len(cmd) for cmd, _ in hints)
    lines.extend(
        f"  {cmd.ljust(width)}  {palette.paint(what, palette.INFO)}"
        for cmd, what in hints
    )

    notes: list[str] = list(warnings)
    if engagement is None:
        notes.append(f"run '{verbs.cmd('engagement setup')}' to scope an engagement")
    if not has_llm:
        notes.append(f"run '{verbs.cmd('setup')}' to configure a model")
    if notes:
        lines.append("")
        lines.extend(f"  {palette.paint(note, palette.INFO)}" for note in notes)
    if unsupported_shell is not None:
        lines.append(
            "  "
            + palette.paint(
                f"{unsupported_shell} is unsupported; /skuggi is disabled "
                "(bash or zsh gets the hook)",
                palette.WARNING,
            )
        )
    return "\n".join(lines)
