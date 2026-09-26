"""Reconstruct a session as an ordered, replayable transcript.

Where ``reports.render_report`` is the outward-facing artifact (scope, findings,
a command table), the transcript is the *internal* record: the whole session
replayed in the order it happened -- operator prompts, the agent's answers, every
command (with its captured output) and every finding, interleaved. It reads the
``events`` spine (see :mod:`skuggi.ledger`) and joins each ``command`` /
``finding`` event to its detail row; ``prompt`` / ``response`` events carry their
own text. A ledger written before the events table existed has no spine, so a
timestamp-ordered fallback over commands + findings keeps old sessions viewable.

This is also the input the ``review`` feature feeds to the LLM, so the same
renderer serves both the human replay and the model's context (``max_output``
caps captured output there to keep the prompt bounded).
"""

from __future__ import annotations

from skuggi.ledger import CommandRow, EventRow, FindingRow, SessionRow
from skuggi.text import join_blocks


def _clip(text: str, limit: int | None) -> str:
    """Trim `text` to `limit` chars with an elision marker, or leave it whole."""
    if limit is None or len(text) <= limit:
        return text
    return text[:limit] + f"\n... [{len(text) - limit} more chars]"


def _command_block(cmd: CommandRow, max_output: int | None) -> str:
    exit_ = "" if cmd.exit_code is None else f" exit={cmd.exit_code}"
    head = f"**cmd:{cmd.id}** `{cmd.status}`{exit_} · `{cmd.command}`"
    if cmd.reason:
        head += f"\n> {cmd.reason}"
    out = "\n".join(part for part in (cmd.stdout, cmd.stderr) if part).strip()
    if out:
        head += f"\n\n```\n{_clip(out, max_output)}\n```"
    return head


def _finding_block(finding: FindingRow) -> str:
    src = f" (from cmd:{finding.command_id})" if finding.command_id is not None else ""
    body = f"**finding:{finding.id}** {finding.severity.upper()}: {finding.title}{src}"
    if finding.description:
        body += f"\n\n{finding.description}"
    return body


def _fallback_blocks(
    commands: dict[int, CommandRow],
    findings: dict[int, FindingRow],
    max_output: int | None,
) -> list[str]:
    """A timestamp-ordered stream for a pre-events ledger (no spine to walk)."""
    dated: list[tuple[str, str]] = [
        (c.started_at, _command_block(c, max_output)) for c in commands.values()
    ]
    dated += [(f.created_at, _finding_block(f)) for f in findings.values()]
    return [block for _, block in sorted(dated, key=lambda pair: pair[0])]


def render_transcript(
    session: SessionRow,
    events: list[EventRow],
    commands: dict[int, CommandRow],
    findings: dict[int, FindingRow],
    *,
    max_output: int | None = None,
) -> str:
    """Compose the ordered Markdown transcript for one session.

    `events` is the timeline spine (empty for a legacy ledger -> the fallback);
    `commands`/`findings` map row id to the detail a command/finding event
    points at. `max_output` caps captured command output (used by review).
    """
    header = (
        f"# Session transcript: {session.engagement_name}\n\n"
        f"- Session: `{session.session_id}`\n"
        f"- Mode: {session.mode}\n"
        f"- Started: {session.started_at}\n"
        f"- Events: {len(events)} · Commands: {len(commands)} · "
        f"Findings: {len(findings)}"
    )
    blocks: list[str] = []
    if events:
        for ev in events:
            if ev.kind == "prompt":
                blocks.append(f"**you** · {ev.created_at}\n\n{ev.text}")
            elif ev.kind == "response":
                blocks.append(f"**skuggi** · {ev.created_at}\n\n{ev.text}")
            elif ev.kind == "command" and ev.ref_id in commands:
                blocks.append(_command_block(commands[ev.ref_id], max_output))
            elif ev.kind == "finding" and ev.ref_id in findings:
                blocks.append(_finding_block(findings[ev.ref_id]))
    else:
        blocks = _fallback_blocks(commands, findings, max_output)
    if not blocks:
        blocks = ["_No activity recorded._"]
    return join_blocks(header, *blocks)
