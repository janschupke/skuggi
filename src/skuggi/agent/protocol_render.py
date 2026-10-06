"""Deterministic text layout for the agent protocol (request/response rendering).

Split from :mod:`skuggi.agent.protocol`, which holds the pydantic request/response
*schemas*; this module holds the independent concern of laying those typed
objects out as the single labelled Human-message block (``render_request``), the
operator/ledger-facing response (``render_response``) and the clean terminal
answer (``render_answer``). Keeping the layout apart from the contract lets either
grow without pushing the other over the file-size cap, and makes the
"model text only ever appears inside harness-controlled sections" boundary one
readable unit.
"""

from __future__ import annotations

from collections.abc import Sequence

from skuggi.agent.protocol import (
    CommandBrief,
    CredentialBrief,
    EngagementBrief,
    FindingBrief,
    LootBrief,
    NoteBrief,
    RequestContext,
    WorkerResponse,
)
from skuggi.common.text import join_blocks, labeled, untrusted


def _findings_block(findings: Sequence[FindingBrief]) -> str:
    lines = []
    for f in findings:
        cmd = f" (cmd:{f.command_id})" if f.command_id is not None else ""
        if f.status == "rejected":
            why = f" -- {f.reason}" if f.reason else ""
            lines.append(f"[{f.id}] REJECTED {f.title}{why}{cmd} (do not re-assert)")
        else:
            tag = "" if f.status == "approved" else f" ({f.status})"
            lines.append(f"[{f.id}] {f.severity.upper()}{tag}: {f.title}{cmd}")
    return "\n".join(lines)


def _credentials_block(credentials: Sequence[CredentialBrief]) -> str:
    lines = []
    for c in credentials:
        who = "@".join(p for p in (c.username, c.host) if p) or "(unknown)"
        svc = f" ({c.service})" if c.service else ""
        secret = f" secret={c.secret_ref}" if c.secret_ref else ""
        flag = " [validated]" if c.validated else ""
        lines.append(f"[{c.id}] {who}{svc}{secret}{flag}")
    return "\n".join(lines)


def _loot_block(loot: Sequence[LootBrief]) -> str:
    lines = []
    for item in loot:
        kind = f"[{item.kind}] " if item.kind else ""
        where = f"{item.host}: " if item.host else ""
        secret = f" secret={item.secret_ref}" if item.secret_ref else ""
        lines.append(f"[{item.id}] {kind}{where}{item.label}{secret}")
    return "\n".join(lines)


def _notes_block(notes: Sequence[NoteBrief]) -> str:
    lines = []
    for n in notes:
        subject = f"[{n.subject}] " if n.subject else ""
        where = f"({n.host}) " if n.host else ""
        lines.append(f"[{n.id}] {subject}{where}{n.text}")
    return "\n".join(lines)


def _commands_block(commands: Sequence[CommandBrief]) -> str:
    lines = []
    for c in commands:
        code = "" if c.exit_code is None else f" exit={c.exit_code}"
        tail = f" -- {c.summary}" if c.summary else ""
        lines.append(f"[{c.id}] {c.status}{code}: {c.command}{tail}")
    return "\n".join(lines)


def _engagement_block(brief: EngagementBrief) -> str:
    methodology = str(brief.methodology)
    if brief.methodology_phases:
        methodology += f" (phases: {', '.join(brief.methodology_phases)})"
    taxonomies = ", ".join(brief.taxonomies) or "(none)"
    return (
        f"name: {brief.name}\n"
        f"stance: {brief.stance}\n"
        f"autonomous: {brief.autonomous}\n"
        f"networks: {', '.join(brief.networks) or '(none)'}\n"
        f"hosts: {', '.join(brief.hosts) or '(none)'}\n"
        f"allowed tools: {', '.join(brief.allowed_tools) or '(none)'}\n"
        f"allowed methods: {', '.join(brief.allowed_methods) or '(none)'}\n"
        f"methodology: {methodology}\n"
        f"finding taxonomies: {taxonomies}\n"
        f"threat model: {'configured' if brief.threat_model else 'none'}"
    )


def render_request(ctx: RequestContext) -> str:
    """Render a request context to the single labelled Human-message block.

    Blocks self-elide when empty (see ``text.labeled``), so a planner request and
    a critic request share this one renderer and simply differ in which fields
    are populated.
    """
    engagement = _engagement_block(ctx.engagement) if ctx.engagement else ""
    steps = "\n".join(f"{i}. {s}" for i, s in enumerate(ctx.plan, start=1))
    return join_blocks(
        labeled("Phase", ctx.phase),
        labeled("Engagement", engagement),
        labeled("System", ctx.system_facts),
        labeled("Harness commands", ctx.harness_catalogue),
        labeled("Operator preferences", ctx.preferences),
        labeled("Conversation summary", ctx.conversation_summary),
        labeled("Conversation so far", ctx.history),
        labeled("Prior findings", _findings_block(ctx.findings)),
        labeled("Captured credentials", _credentials_block(ctx.credentials)),
        labeled("Captured loot", _loot_block(ctx.loot)),
        labeled("Notes", _notes_block(ctx.notes)),
        untrusted("Recent commands", _commands_block(ctx.recent_commands)),
        untrusted("Lookup results", "\n\n".join(ctx.lookup_results)),
        labeled("Data files", ctx.data_files),
        untrusted("Retrieved context", ctx.retrieved_context),
        labeled("Plan", steps),
        labeled("Prior critique", ctx.prior_critique),
        labeled("Draft", ctx.draft),
        labeled("Request", ctx.request),
    )


def render_response(resp: WorkerResponse) -> str:
    """Lay a worker response out deterministically for the operator.

    The only place model text becomes operator-facing output, and it is placed
    field by field into sections the harness controls -- never emitted raw.
    """
    blocks = [
        labeled("Summary", resp.summary),
        labeled("Proposed command", resp.command or ""),
        labeled("Advice", resp.advice),
        labeled("Conclusions", resp.conclusions),
    ]
    if resp.findings:
        blocks.append(labeled("Findings", _worker_findings_block(resp)))
    return join_blocks(*blocks) or "(no answer)"


def _worker_findings_block(resp: WorkerResponse) -> str:
    """The worker's recorded findings as a compact ``- SEVERITY: title`` list."""
    return "\n".join(
        f"- {f.display_severity().upper()}: {f.title}" for f in resp.findings
    )


def render_answer(resp: WorkerResponse) -> str:
    """The clean, operator-facing answer: the worker's advice as prose.

    Unlike :func:`render_response` (which lays every field out with labels for the
    ledger, the critic's input and the conversation history), this is what the
    terminal shows -- just the answer, plus a compact note when the worker proposes
    a command or records findings. ``summary`` and ``conclusions`` are diagnostic
    detail: they stay in the ledger and the log, but out of the operator's face.

    The body falls back from ``advice`` to ``conclusions`` to ``summary`` so a turn
    that puts its answer in a different field is never rendered blank.
    """
    body = resp.advice.strip() or resp.conclusions.strip() or resp.summary.strip()
    blocks = [body]
    if resp.command:
        blocks.append(f"Proposed command:\n```\n{resp.command}\n```")
    if resp.findings:
        blocks.append(_worker_findings_block(resp))
    return join_blocks(*blocks) or "(no answer)"
