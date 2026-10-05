"""The worker's command sub-system: guard, record, run, and record findings.

Lifted out of ``graph.py`` as a cohesive unit -- everything that takes a
``WorkerResponse``'s command, sends it through the engagement guard and risk gate,
persists it (and any findings) to the ledger, and in autonomous mode runs it and
feeds a bounded summary back to the worker. These are the dependencies the old
``run_command`` tool closed over (the ``engagement``/``ledger``/``registry`` group
of ``GraphDeps``), now a free-function module the graph wires in as its executor
node and post-executor route.

The redaction factory ``_redactor`` lives here (not in ``graph.py``) so this module
stays self-contained at runtime: ``graph.py`` imports it back for prompt assembly,
while this module only needs ``GraphDeps`` as a type. That one-way edge
(graph -> executor) is what keeps the split cycle-free.
"""

from __future__ import annotations

import shlex
from datetime import datetime
from typing import TYPE_CHECKING, Literal

from skuggi.agent.protocol import CommandBrief, WorkerResponse
from skuggi.common import execution
from skuggi.common.logs import get_logger
from skuggi.engagement.engagement import ParsedCommand, check_command, parse_command
from skuggi.engagement.pivot import Route, select_route, wrap_command
from skuggi.engagement.risk import risk_tier
from skuggi.persistence.ledger import FindingEvidenceInput, FindingRefInput, Ledger
from skuggi.persistence.ledger_schema import FindingAuthor
from skuggi.security import boundaries
from skuggi.security.policy import RedactionPolicy
from skuggi.security.redaction import redact
from skuggi.tooling.registry import RiskTier

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from skuggi.agent.graph import GraphDeps
    from skuggi.agent.protocol import FindingDraft
    from skuggi.agent.state import AgentState, ExecutorUpdate
    from skuggi.engagement.engagement import EngagementConfig
    from skuggi.persistence.ledger_schema import CommandRow

    # The session's bound redactor (``_redactor``): free text in -> scrubbed out.
    Redact = Callable[[str], str]

log = get_logger(__name__)

# How much captured command output the executor hands back to the worker as the
# command's summary -- enough to decide the next step without dumping a whole scan.
_OUTPUT_SUMMARY_CAP = 1_500
# A larger budget for an explicit `lookup command <id>`: the worker asked to
# re-read a command's full output, so give far more than the turn summary (still
# head+tail bounded, still under the 256 KiB capture ceiling).
_LOOKUP_OUTPUT_CAP = 8_000


def _redactor(deps: GraphDeps) -> Callable[[str], str]:
    """A redact function bound to this session's policy and vault.

    With a vault each secret becomes a reversible ``«KIND:id»`` placeholder;
    without one (agent-only mode) a default policy still masks one-way, so no
    request can carry a raw secret even when no engagement is loaded.
    """
    policy = deps.redaction_policy or RedactionPolicy()
    return lambda text: redact(text, policy, deps.vault)


def _summarize_output(
    exit_code: int | None,
    stdout: str,
    stderr: str,
    clean: Redact,
    *,
    cap: int = _OUTPUT_SUMMARY_CAP,
) -> str:
    """A bounded, redacted summary of captured output for a model-facing brief.

    ``clean`` redacts the captured output before it becomes model-facing: scan
    output is the single largest source of discovered secrets/PII, so it is
    scrubbed (and any secret vaulted) *before* truncation, so a secret cannot
    survive by sitting past the cap. Works on the primitive fields so both a live
    ``CommandResult`` (this turn) and a persisted ``CommandRow`` (a prior turn, via
    :func:`brief_from_row`) summarize identically. ``cap`` is the head+tail budget;
    a ``lookup command <id>`` passes a larger one to re-read the full output.
    """
    parts = [stdout.strip()]
    if stderr.strip():
        parts.append("stderr: " + stderr.strip())
    text = clean("\n".join(p for p in parts if p))
    if not text:
        return f"exit={exit_code} (no output)"
    return f"exit={exit_code}\n{_head_tail(text, cap)}"


def _summarize_result(result: execution.CommandResult, clean: Redact) -> str:
    """A bounded summary of a just-run command's output for the worker."""
    return _summarize_output(result.exit_code, result.stdout, result.stderr, clean)


def brief_from_row(row: CommandRow, clean: Redact) -> CommandBrief:
    """A redacted :class:`CommandBrief` from a persisted row, for cross-turn recall.

    Mirrors the in-turn brief built in :func:`_run_or_propose`: an executed row is
    summarized from its captured output (redacted, head+tail bounded); a
    proposed/blocked/passthrough row carries its reason. The command string and the
    output are both redacted here -- the ledger stores a row raw (report-facing),
    but a brief is model-facing and must not reintroduce a secret.
    """
    if row.status == "executed":
        summary = _summarize_output(row.exit_code, row.stdout, row.stderr, clean)
        exit_code = row.exit_code
    else:
        summary = clean(row.reason)
        exit_code = None
    return CommandBrief(
        id=row.id,
        status=row.status,
        command=clean(row.command),
        exit_code=exit_code,
        summary=summary,
    )


def _head_tail(text: str, cap: int) -> str:
    """Bound `text` to `cap` chars keeping BOTH ends, not just a raw prefix.

    A verbose tool (nmap, nuclei, sqlmap) often puts the salient result -- the
    open-port table, the hit summary -- at the END, past a prefix cap; feeding the
    worker only the head made the autonomous loop reason on a banner and miss the
    finding (audit D4). Keeping a head and a tail with an explicit elision marker
    surfaces both the start and the conclusion within the same budget.
    """
    if len(text) <= cap:
        return text
    head = cap * 2 // 3
    tail = cap - head
    elided = len(text) - head - tail
    return f"{text[:head]}\n...[{elided} chars elided]...\n{text[-tail:]}"


_LOOKUP_TARGETS = ("findings", "loot", "creds", "notes", "command")


def _lookup_findings(ledger: Ledger, sid: str, name: str, q: str, clean: Redact) -> str:
    rows = ledger.findings_for_engagement(name) if name else ledger.findings_for(sid)
    hits = [
        r for r in rows if not q or q in r.title.lower() or q in r.affected_host.lower()
    ]
    lines = [
        f"[{r.id}] {r.severity.upper()} {clean(r.title)}"
        f" @ {r.affected_host or '-'} [{r.status}]"
        for r in hits[:50]
    ]
    return "\n".join(lines) or "(no matching findings)"


def _lookup_loot(ledger: Ledger, sid: str, name: str, q: str, clean: Redact) -> str:
    rows = ledger.loot_for_engagement(name) if name else ledger.loot_for(sid)
    hits = [
        r
        for r in rows
        if not q or q in r.label.lower() or q in r.host.lower() or q in r.kind.lower()
    ]
    lines = [f"[{r.id}] {r.kind} {r.host}: {clean(r.label)}" for r in hits[:50]]
    return "\n".join(lines) or "(no matching loot)"


def _lookup_creds(ledger: Ledger, sid: str, name: str, q: str) -> str:
    # No redactor: a credential row carries only identifiers + a vault placeholder.
    rows = (
        ledger.credentials_for_engagement(name) if name else ledger.credentials_for(sid)
    )
    hits = [r for r in rows if not q or q in r.host.lower() or q in r.username.lower()]
    lines = [
        f"[{r.id}] {r.username or '?'}@{r.host or '?'} ({r.service or '-'})"
        f" secret={r.secret_ref or '-'}"
        for r in hits[:50]
    ]
    return "\n".join(lines) or "(no matching credentials)"


def _lookup_notes(ledger: Ledger, sid: str, name: str, q: str, clean: Redact) -> str:
    rows = ledger.notes_for_engagement(name) if name else ledger.notes_for(sid)
    hits = [r for r in rows if not q or q in r.text.lower() or q in r.subject.lower()]
    lines = [
        f"[{r.id}] {r.subject} ({r.host or '-'}): {clean(r.text)}" for r in hits[:50]
    ]
    return "\n".join(lines) or "(no matching notes)"


def _lookup_command(ledger: Ledger, rest: str, q: str, clean: Redact) -> str:
    row = ledger.command(int(q)) if q.isdigit() else None
    if row is None:
        return f"(no command with id {rest!r})"
    body = _summarize_output(
        row.exit_code, row.stdout, row.stderr, clean, cap=_LOOKUP_OUTPUT_CAP
    )
    return f"[{row.id}] {row.status} {clean(row.command)}\n{body}"


# Accepted lookup targets, normalized (singular) to their resolver.
_LOOKUP_ALIASES = {
    "finding": "finding",
    "loot": "loot",
    "cred": "cred",
    "credential": "cred",
    "note": "note",
    "command": "command",
    "cmd": "command",
    "output": "command",
}


def resolve_lookup(deps: GraphDeps, lookup: str) -> str:
    """Resolve a worker's read-only `lookup` against the engagement's record.

    Read-only by construction -- it only queries the ledger -- so it is safe to run
    without the operator and regardless of autonomy. Every free-text field is
    redacted (a vaulted secret stays a placeholder), and credential/loot rows carry
    only placeholders already. Returns a compact text block for the worker to read.
    """
    ledger = deps.ledger
    if ledger is None or not deps.session_id:
        return "(no engagement record available)"
    clean = _redactor(deps)
    sid = deps.session_id
    name = deps.engagement.name if deps.engagement is not None else ""
    target, _, rest = lookup.strip().partition(" ")
    q = rest.strip().lower()
    resolvers: dict[str, Callable[[], str]] = {
        "finding": lambda: _lookup_findings(ledger, sid, name, q, clean),
        "loot": lambda: _lookup_loot(ledger, sid, name, q, clean),
        "cred": lambda: _lookup_creds(ledger, sid, name, q),
        "note": lambda: _lookup_notes(ledger, sid, name, q, clean),
        "command": lambda: _lookup_command(ledger, rest, q, clean),
    }
    resolver = resolvers.get(_LOOKUP_ALIASES.get(target.lower().rstrip("s"), ""))
    if resolver is None:
        return f"(unknown lookup target {target!r}; use {' | '.join(_LOOKUP_TARGETS)})"
    return resolver()


def execute_node(state: AgentState, deps: GraphDeps, work_dir: Path) -> ExecutorUpdate:
    """Run/propose the worker's command, resolve a lookup, and record any findings."""
    resp = state.get("worker")
    if resp is None:
        return {}
    commands = list(state.get("commands", []))
    rounds = state.get("command_rounds") or 0
    updates: ExecutorUpdate = {}
    command_id: int | None = None
    runnable = (
        resp.command is not None
        and deps.ledger is not None
        and deps.engagement is not None
        and deps.registry is not None
        and bool(deps.session_id)
    )
    if runnable and resp.command is not None:
        command_id, brief, ran = _run_or_propose(
            deps, resp.command, work_dir, now=_now(deps)
        )
        commands.append(brief)
        updates["commands"] = commands
        if ran:
            updates["command_rounds"] = rounds + 1
    elif resp.command is None and resp.lookup:
        lookups = list(state.get("lookups", []))
        lookups.append(f"{resp.lookup} ->\n{resolve_lookup(deps, resp.lookup)}")
        updates["lookups"] = lookups
        updates["command_rounds"] = rounds + 1
    _record_findings(deps, resp, command_id)
    return updates


def route_after_executor(  # noqa: PLR0911 -- a flat guard ladder reads clearer than nesting the autonomous/advice/review branches
    state: AgentState, deps: GraphDeps
) -> Literal["worker", "critic", "respond"]:
    """Route after the executor: loop, review, or (for advice-only turns) answer.

    Loop back to the worker only while an autonomous run can still make progress.
    Otherwise review with the critic -- except when the worker proposed no command
    and recorded no finding: that pure advice/conversational answer has nothing
    high-stakes to vet, so in non-autonomous mode it skips straight to ``respond``.
    That removes one sequential reasoning round-trip (the critic cost as much as
    the worker in the latency audit) on the common chat turn, while any command or
    finding still goes through the critic.
    """
    resp = state.get("worker")
    if resp is None:
        return "critic"
    # A read-only lookup just resolved: loop back so the worker reads the result and
    # decides, regardless of autonomy (nothing was executed). Bounded by the shared
    # round budget so repeated lookups cannot spin forever.
    if resp.command is None and resp.lookup:
        if (state.get("command_rounds") or 0) < deps.max_command_rounds:
            return "worker"
        return "critic"
    autonomous = deps.engagement is not None and deps.engagement.autonomous
    if not autonomous and resp.command is None and not resp.findings:
        return "respond"
    if resp.done or resp.command is None:
        return "critic"
    if not autonomous:
        return "critic"
    if (state.get("command_rounds") or 0) >= deps.max_command_rounds:
        return "critic"
    commands = state.get("commands") or []
    if not commands or commands[-1].status != "executed":
        return "critic"
    return "worker"


def _now(deps: GraphDeps) -> datetime:
    """The current time in the engagement timezone (or the injected clock)."""
    if deps.clock is not None:
        return deps.clock()
    assert deps.engagement is not None  # noqa: S101 -- only called on the guarded path
    return datetime.now(deps.engagement.tzinfo())


def _record_command(  # noqa: PLR0913 -- keyword-only ledger columns
    deps: GraphDeps,
    ledger: Ledger,
    parsed: ParsedCommand,
    command: str,
    *,
    status: str,
    reason: str = "",
    result: execution.CommandResult | None = None,
    risk_tier: str = "",
    authority: str = "",
) -> int:
    """Insert one command row, tagged with this turn's session/thread/prompt ids.

    The shared tagging (``session_id``/``thread_id``/``turn_event_id``) lives here
    so the blocked, proposed and executed paths cannot drift on how a row is linked
    back to the turn that drove it. ``risk_tier``/``authority`` record the
    deterministic tier the command was evaluated at and under whose authority it
    ran, so the audit trail does not have to re-derive them.
    """
    return ledger.record_command(
        session_id=deps.session_id,
        thread_id=deps.thread_id(),
        command=command,
        binary=parsed.binary,
        method=parsed.method,
        status=status,
        reason=reason,
        result=result,
        turn_event_id=deps.turn_id(),
        risk_tier=risk_tier,
        authority=authority,
    )


def _proposed_reason(
    autonomous: bool, tier: RiskTier, ceiling: RiskTier, route: Route
) -> str:
    """The operator-facing reason a command was held proposed (incl. any pivot)."""
    via = (
        f" (routes via foothold {route.foothold.host})"
        if route.foothold is not None
        else ""
    )
    if not autonomous:
        return f"recorded proposed; the operator runs it manually{via}"
    return (
        f"recorded proposed; risk tier '{tier.name}' exceeds the autonomous "
        f"ceiling '{ceiling.name}' -- run it manually{via}"
    )


def _run_or_propose(
    deps: GraphDeps, command: str, work_dir: Path, *, now: datetime
) -> tuple[int, CommandBrief, bool]:
    """Guard, record and (autonomously) run one command. Returns (id, brief, ran).

    ``ran`` is True only when the command actually executed, which is what gates
    another turn of the worker <-> executor loop.
    """
    assert deps.ledger is not None  # noqa: S101
    assert deps.engagement is not None  # noqa: S101
    assert deps.registry is not None  # noqa: S101
    ledger = deps.ledger
    parsed = parse_command(command, deps.registry)
    verdict = check_command(
        parsed,
        deps.engagement,
        now=now,
        workspace=deps.workspace,
        cwd=work_dir,
        wordlist_roots=deps.wordlist_roots,
    )
    if not verdict.allowed:
        cid = _record_command(
            deps, ledger, parsed, command, status="blocked", reason=verdict.reason
        )
        brief = CommandBrief(
            id=cid,
            status="blocked",
            command=command,
            summary=boundaries.label(
                boundaries.BoundaryKind.HARD_BLOCK, verdict.reason
            ),
        )
        return cid, brief, False
    # Reachability: is the target reachable directly, or only through a registered
    # foothold? Routing never widens authority (the scope check above already
    # passed on the real target) -- it only decides the path and, when a pivot is
    # needed, elevates the effective risk tier (running THROUGH a compromised host
    # is an intrusive act even for a benign inner command).
    footholds = ledger.footholds_for(deps.session_id)
    route = select_route(parsed.targets, footholds)
    # Risk gate: in scope, but is it low-risk enough to run unattended? A command
    # above the engagement's autonomous ceiling is held as ``proposed`` for the
    # operator to run by hand -- "manual escalation" -- exactly like the
    # non-autonomous path, but with a reason that names the tier. Deterministic:
    # no LLM decides this (see skuggi.engagement.risk).
    tier = risk_tier(deps.registry.spec_for(parsed.binary), parsed.argv)
    if route.foothold is not None:
        tier = max(tier, RiskTier.intrusive)
    ceiling = deps.engagement.autonomous_ceiling
    if not deps.engagement.autonomous or tier > ceiling:
        summary = boundaries.label(
            boundaries.BoundaryKind.ESCALATION,
            _proposed_reason(deps.engagement.autonomous, tier, ceiling, route),
        )
        cid = _record_command(
            deps, ledger, parsed, command, status="proposed", risk_tier=tier.name
        )
        brief = CommandBrief(
            id=cid, status="proposed", command=command, summary=summary
        )
        return cid, brief, False
    # Build the argv to run. A pivoted command is first wrapped so it runs through
    # the foothold (operator-supplied template); then every «KIND:id» placeholder
    # -- the foothold's own secret and any credential in the inner command -- is
    # rehydrated to its real value just before the tool runs, and nowhere else. The
    # recorded command and model-facing brief keep the clean inner placeholder form.
    to_run = (
        wrap_command(route.foothold, command) if route.foothold is not None else command
    )
    tokens = shlex.split(to_run) if route.foothold is not None else list(parsed.argv)
    argv = (
        tuple(deps.vault.rehydrate(token) for token in tokens)
        if deps.vault is not None
        else tuple(tokens)
    )
    backend = deps.backend or execution.HostBackend()
    result = backend.run(
        argv,
        timeout=deps.command_timeout_s,
        cwd=work_dir,
        env=execution.safe_env(),
        display_command=command,
    )
    try:
        cid = _record_command(
            deps,
            ledger,
            parsed,
            command,
            status="executed",
            result=result,
            risk_tier=tier.name,
            authority="autonomous",
        )
    except Exception:
        # Evidence loss: the command ran but its result did not persist. Make it
        # unmistakable in the log, then let it surface (a bad turn is not silent).
        # error, not exception: the full traceback is logged once where the turn
        # catches it; here we want the one-line evidence-loss marker.
        log.error(  # noqa: TRY400 -- traceback logged at the turn boundary
            "evidence loss: failed to record executed command %r", command
        )
        raise
    summary = _summarize_result(result, _redactor(deps))
    if route.foothold is not None:
        summary = f"[via foothold {route.foothold.host}] {summary}"
    brief = CommandBrief(
        id=cid,
        status="executed",
        command=command,
        exit_code=result.exit_code,
        summary=summary,
    )
    return cid, brief, True


def record_finding_drafts(
    ledger: Ledger,
    findings: Sequence[FindingDraft],
    *,
    session_id: str,
    engagement: EngagementConfig | None,
    command_id: int | None,
) -> None:
    """Persist a batch of ``FindingDraft``s to the ledger (the shared recorder).

    The single write path for agent findings, whatever produced them: the turn
    worker (linked to the command it cited) and the OSINT verifier (no command).
    CVSS environmental metrics, the threat-model version and the primary taxonomy
    are derived from the engagement exactly once, so the two callers cannot drift.
    """
    if not findings:
        return
    threat_model = engagement.threat_model if engagement else None
    env_metrics = threat_model.cvss_environmental_metrics() if threat_model else {}
    tm_version = ledger.current_threat_model_version() or None
    primary = "attack" if engagement and engagement.methodology == "attack" else "wstg"
    for finding in findings:
        refs = [
            FindingRefInput(
                ref.framework, ref.ref_id, is_primary=ref.framework == primary
            )
            for ref in finding.refs
        ]
        evidence_items = [
            FindingEvidenceInput(
                kind=item.kind, content=item.content, media_path=item.media_path
            )
            for item in finding.evidence_items
        ]
        try:
            affected = finding.affected
            ledger.record_finding(
                session_id=session_id,
                title=finding.title,
                severity=finding.severity,
                description=finding.description,
                evidence=finding.evidence,
                command_id=command_id,
                cvss_vector=finding.cvss_vector or None,
                env_metrics=env_metrics,
                tm_version=tm_version,
                refs=refs,
                evidence_items=evidence_items,
                author=FindingAuthor.AGENT,
                impact=finding.impact,
                remediation=finding.remediation,
                affected_host=affected.host if affected else "",
                affected_port=affected.port if affected else "",
                affected_url=affected.url if affected else "",
                affected_param=affected.parameter if affected else "",
            )
        except Exception:
            # Evidence loss: a finding the agent produced did not persist. This is
            # the worst case for an engagement, so name it explicitly, then raise.
            # error, not exception: the traceback is logged once at the turn boundary.
            log.error(  # noqa: TRY400 -- traceback logged at the turn boundary
                "evidence loss: failed to record finding %r", finding.title
            )
            raise


def _record_findings(
    deps: GraphDeps, resp: WorkerResponse, command_id: int | None
) -> None:
    """Record each of the worker's findings, linked to the command it cites."""
    if deps.ledger is None or not deps.session_id or not resp.findings:
        return
    link = (
        command_id
        if command_id is not None
        else deps.ledger.latest_command_id(deps.session_id)
    )
    record_finding_drafts(
        deps.ledger,
        resp.findings,
        session_id=deps.session_id,
        engagement=deps.engagement,
        command_id=link,
    )
