"""The wrapped shell's startup banner.

A pure renderer so ``shell.main()`` (which is ``# pragma: no cover`` -- it
launches a child shell + daemon) stays wiring-only and the banner's layout is
unit-tested. Returns one Rich-markup string; the caller prints it through a Rich
``Console``. Styling draws on the shared :mod:`skuggi.common.palette` so the
wrapped shell reads the same as the REPL, and the glance fields + next-step notes
come from one :class:`skuggi.agent.readiness.Readiness` so the shell can never
drift from the REPL or ``show status``.
"""

from __future__ import annotations

from skuggi.agent import readiness as readiness_mod
from skuggi.agent.readiness import Readiness
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
    readiness: Readiness,
    unsupported_shell: str | None,
) -> str:
    """Compose the wrapped shell's startup banner as a Rich-markup string.

    ``readiness`` carries the glance fields (provider/model/engagement) and the
    pending next steps; ``unsupported_shell`` is the shell's name when it cannot
    take the hook, else ``None``.
    """
    scope = readiness.engagement or "(none)"
    lines: list[str] = [
        f"{palette.SHIELD} [bold]skuggi shell[/bold]",
        "  "
        + palette.paint(
            f"provider {readiness.provider} · model {readiness.model} "
            f"· engagement {scope}",
            palette.INFO,
        ),
        "",
    ]

    hints = [(verbs.cmd(inv), what) for inv, what in _VERBS]
    width = max(len(cmd) for cmd, _ in hints)
    lines.extend(
        f"  {cmd.ljust(width)}  {palette.paint(what, palette.INFO)}"
        for cmd, what in hints
    )

    notes = readiness_mod.render_banner_notes(readiness, "shell")
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
