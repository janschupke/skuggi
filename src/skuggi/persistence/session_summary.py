"""The wrapped shell's exit session summary.

Where :func:`skuggi.persistence.transcript.render_transcript` replays a whole
session, this is the one-screen sign-off printed when the operator leaves the
shell: how long it ran and what it did (turns, commands, findings, notes, loot).
Pure -- it takes rows already read from the ledger and returns a Rich-markup
string -- so ``shell.main()`` (``# pragma: no cover``) keeps only the I/O and the
layout is unit-tested, exactly as ``transcript`` is split from ``session_archive``.
"""

from __future__ import annotations

from skuggi.common import palette
from skuggi.persistence.ledger import CommandRow, FindingRow

_SIGN_OFF = "session closed · ledger saved"

# Command statuses worth calling out, in display order (the same set
# ``visualize._usage`` aggregates). A status with a zero count is dropped.
_STATUSES: tuple[str, ...] = ("executed", "blocked", "proposed", "passthrough")

_LABEL_WIDTH = 10
_PER_MINUTE = 60  # seconds in a minute, and minutes in an hour


def fmt_duration(seconds: float | None) -> str:
    """A compact human duration: ``45s``, ``14m 02s``, ``2h 05m``."""
    if seconds is None:
        return "unknown"
    total = int(seconds)
    if total < _PER_MINUTE:
        return f"{total}s"
    minutes, secs = divmod(total, _PER_MINUTE)
    if minutes < _PER_MINUTE:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, _PER_MINUTE)
    return f"{hours}h {minutes:02d}m"


def command_breakdown(commands: list[CommandRow]) -> list[tuple[str, int]]:
    """Non-zero command-status counts in display order (``executed`` first).

    Shared with ``show status`` so the exit summary and the live status view
    count and order command statuses identically.
    """
    counts = dict.fromkeys(_STATUSES, 0)
    for cmd in commands:
        if cmd.status in counts:
            counts[cmd.status] += 1
    return [(status, counts[status]) for status in _STATUSES if counts[status]]


def finding_breakdown(findings: list[FindingRow]) -> list[tuple[str, int]]:
    """Finding counts by severity, ranked critical..info (unknowns last).

    Shared with ``show status`` so both views group and order severities the same;
    each consumer paints the result in its own way (markup string here, spans in
    the status view).
    """
    by_sev: dict[str, int] = {}
    for finding in findings:
        by_sev[finding.severity] = by_sev.get(finding.severity, 0) + 1
    rank = {sev: i for i, sev in enumerate(palette.severities())}
    return sorted(by_sev.items(), key=lambda kv: rank.get(kv[0], len(rank)))


def _row(label: str, value: str) -> str:
    return f"  {label.ljust(_LABEL_WIDTH)} {value}"


def _command_line(commands: list[CommandRow]) -> str:
    parts = [f"{n} {status}" for status, n in command_breakdown(commands)]
    breakdown = f"  ({' · '.join(parts)})" if parts else ""
    return _row("commands", f"{len(commands)}{breakdown}")


def _finding_line(findings: list[FindingRow]) -> str:
    parts = [
        palette.paint(f"{n} {sev}", palette.severity_style(sev))
        for sev, n in finding_breakdown(findings)
    ]
    breakdown = f"  ({' · '.join(parts)})" if parts else ""
    return _row("findings", f"{len(findings)}{breakdown}")


def render_session_summary(  # noqa: PLR0913 -- one keyword-only arg per metric
    *,
    engagement_name: str | None,
    mode: str,
    elapsed_s: float | None,
    turns: int,
    commands: list[CommandRow],
    findings: list[FindingRow],
    notes: int,
    loot: int,
) -> str:
    """Compose the exit session summary as a Rich-markup string.

    ``engagement_name`` is ``None`` for an agent-only session. A session that did
    nothing (no turns, commands, findings, notes or loot) collapses to just the
    header and sign-off, so opening and immediately leaving the shell is quiet.
    """
    header = f"{palette.SHIELD} [bold]skuggi session ended[/bold]"
    sign_off = f"  {palette.paint(_SIGN_OFF, palette.INFO)}"

    if turns == 0 and not commands and not findings and not notes and not loot:
        return f"{header}\n\n{sign_off}"

    rows = [
        _row("engagement", engagement_name or "agent-only"),
        _row("mode", mode),
        _row("ran for", fmt_duration(elapsed_s)),
        _row("turns", str(turns)),
        _command_line(commands),
        _finding_line(findings),
    ]
    if notes or loot:
        rows.append(_row("journal", f"notes {notes} · loot {loot}"))
    return "\n".join([header, "", *rows, "", sign_off])
