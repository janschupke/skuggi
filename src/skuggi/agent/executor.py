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

from datetime import datetime
from typing import TYPE_CHECKING, Literal

from skuggi.agent.protocol import CommandBrief, WorkerResponse
from skuggi.common import execution
from skuggi.common.logs import get_logger
from skuggi.engagement.engagement import ParsedCommand, check_command, parse_command
from skuggi.engagement.risk import risk_tier
from skuggi.persistence.ledger import FindingRefInput, Ledger
from skuggi.persistence.ledger_schema import FindingAuthor
from skuggi.security.policy import RedactionPolicy
from skuggi.security.redaction import redact

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from skuggi.agent.graph import GraphDeps
    from skuggi.agent.protocol import FindingDraft
    from skuggi.agent.state import AgentState, ExecutorUpdate
    from skuggi.engagement.engagement import EngagementConfig

log = get_logger(__name__)

# How much captured command output the executor hands back to the worker as the
# command's summary -- enough to decide the next step without dumping a whole scan.
_OUTPUT_SUMMARY_CAP = 1_500


def _redactor(deps: GraphDeps) -> Callable[[str], str]:
    """A redact function bound to this session's policy and vault.

    With a vault each secret becomes a reversible ``«KIND:id»`` placeholder;
    without one (agent-only mode) a default policy still masks one-way, so no
    request can carry a raw secret even when no engagement is loaded.
    """
    policy = deps.redaction_policy or RedactionPolicy()
    return lambda text: redact(text, policy, deps.vault)


def _summarize_result(
    result: execution.CommandResult, clean: Callable[[str], str]
) -> str:
    """A bounded summary of a command's output for the worker's next request.

    ``clean`` redacts the captured output before it becomes model-facing: scan
    output is the single largest source of discovered secrets/PII, so it is
    scrubbed (and any secret vaulted) *before* truncation, so a secret cannot
    survive by sitting past the cap.
    """
    parts = [result.stdout.strip()]
    if result.stderr.strip():
        parts.append("stderr: " + result.stderr.strip())
    text = clean("\n".join(p for p in parts if p))
    if not text:
        return f"exit={result.exit_code} (no output)"
    return f"exit={result.exit_code}\n{text[:_OUTPUT_SUMMARY_CAP]}"


def execute_node(state: AgentState, deps: GraphDeps, work_dir: Path) -> ExecutorUpdate:
    """Run (autonomous) or propose the worker's command, recording any findings."""
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
) -> int:
    """Insert one command row, tagged with this turn's session/thread/prompt ids.

    The shared tagging (``session_id``/``thread_id``/``turn_event_id``) lives here
    so the blocked, proposed and executed paths cannot drift on how a row is linked
    back to the turn that drove it.
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
            id=cid, status="blocked", command=command, summary=verdict.reason
        )
        return cid, brief, False
    # Risk gate: in scope, but is it low-risk enough to run unattended? A command
    # above the engagement's autonomous ceiling is held as ``proposed`` for the
    # operator to run by hand -- "manual escalation" -- exactly like the
    # non-autonomous path, but with a reason that names the tier. Deterministic:
    # no LLM decides this (see skuggi.engagement.risk).
    tier = risk_tier(deps.registry.spec_for(parsed.binary), parsed.argv)
    ceiling = deps.engagement.autonomous_ceiling
    if not deps.engagement.autonomous or tier > ceiling:
        if not deps.engagement.autonomous:
            summary = "recorded proposed; the operator runs it manually"
        else:
            summary = (
                f"recorded proposed; risk tier '{tier.name}' exceeds the "
                f"autonomous ceiling '{ceiling.name}' -- run it manually"
            )
        cid = _record_command(deps, ledger, parsed, command, status="proposed")
        brief = CommandBrief(
            id=cid, status="proposed", command=command, summary=summary
        )
        return cid, brief, False
    # Rehydrate any «KIND:id» placeholder in the argv to its real value just
    # before the tool runs: a credential the agent discovered (and only ever saw
    # as a placeholder) reaches the tool here, and nowhere else. The recorded
    # command and the model-facing brief keep the placeholder form.
    argv = (
        tuple(deps.vault.rehydrate(token) for token in parsed.argv)
        if deps.vault is not None
        else parsed.argv
    )
    result = execution.run(
        argv,
        timeout=deps.command_timeout_s,
        cwd=work_dir,
        env=execution.safe_env(),
        display_command=command,
    )
    try:
        cid = _record_command(
            deps, ledger, parsed, command, status="executed", result=result
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
    brief = CommandBrief(
        id=cid,
        status="executed",
        command=command,
        exit_code=result.exit_code,
        summary=_summarize_result(result, _redactor(deps)),
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
        try:
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
                author=FindingAuthor.AGENT,
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
