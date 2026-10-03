"""planner -> retriever -> worker <-> executor -> critic graph.

Every node speaks the structured protocol (``skuggi.protocol``): the planner
returns a ``PlannerResponse`` (plan + a phase judgement), the worker a
``WorkerResponse`` (a command to run/propose, or advice, plus summary,
conclusions, stance and findings), the critic a ``CriticResponse`` (an
``approved`` boolean, not a parsed prefix). Each request is built from a
``RequestContext`` -- conversation history, the engagement scope + stance, the
current methodology phase, prior findings and the commands run so far this turn.

The worker's command handling is a real graph cycle -- worker -> executor ->
worker -- rather than a tool loop inside one node: the executor sends the command
through the engagement guard, records it (and any findings) to the ledger, and in
autonomous mode runs it and feeds the result back as a recent command. Every step
is a checkpointed superstep, so a crash mid-loop is resumable and ``/trace`` can
show the trail. Non-autonomous, the command is recorded ``proposed`` and the loop
stops for the operator to run it by hand.

``respond`` is the only node that writes to ``messages``, so a revised turn leaves
exactly one rendered answer in the conversation rather than one per pass.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
)
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from skuggi.agent.prompts import PromptSet, prompt_set
from skuggi.agent.protocol import (
    CommandBrief,
    CriticResponse,
    EngagementBrief,
    FindingBrief,
    PlannerResponse,
    RequestContext,
    WorkerResponse,
    clamp_phase,
    methodology_phases,
    render_request,
    render_response,
    structured_invoke,
)
from skuggi.agent.state import (
    AgentState,
    ContextUpdate,
    CritiqueUpdate,
    ExecutorUpdate,
    PlanUpdate,
    ReplyUpdate,
    RevisionUpdate,
    WorkerUpdate,
)
from skuggi.common import execution
from skuggi.common.logs import get_logger
from skuggi.engagement.engagement import EngagementConfig, check_command, parse_command
from skuggi.engagement.risk import risk_tier
from skuggi.engagement.workspace import Workspace
from skuggi.persistence.ledger import FindingRefInput, Ledger
from skuggi.persistence.vectorstore import Store, format_hits
from skuggi.security.policy import RedactionPolicy
from skuggi.security.redaction import redact
from skuggi.security.tripwire import scrub
from skuggi.security.vault import SecretVault
from skuggi.tooling.registry import ToolRegistry

log = get_logger(__name__)

# How much captured command output the executor hands back to the worker as the
# command's summary -- enough to decide the next step without dumping a whole scan.
_OUTPUT_SUMMARY_CAP = 1_500


@dataclass(frozen=True, slots=True)
class GraphDeps:
    """Everything `build_graph` needs, bundled so the signature stays small.

    The engagement/ledger/registry group is what the executor uses to guard,
    record and (autonomously) run the worker's command -- the dependencies the old
    ``run_command`` tool closed over, now owned by the graph. They are ``None`` in
    agent-only mode (no engagement loaded), where the worker can still advise.
    """

    # None only transiently, before a model is configured: the core's `turn`
    # builds the model (and rebuilds the graph) before ever streaming it, so a
    # node always sees a live llm. The `ask` helper guards defensively.
    llm: BaseChatModel | None = None
    store: Store | None = None
    engagement: EngagementConfig | None = None
    ledger: Ledger | None = None
    registry: ToolRegistry | None = None
    # The data-plane boundary. ``redaction_policy`` says what to scrub and which
    # in-scope identifiers to leave alone; ``vault`` makes the scrub reversible
    # (a discovered secret becomes a placeholder here, rehydrated for a tool at
    # execution). Both ``None`` in agent-only mode, where a default policy still
    # masks one-way so RAG/history cannot leak a secret into a request.
    redaction_policy: RedactionPolicy | None = None
    vault: SecretVault | None = None
    # The engagement workspace, for confining data-file paths a command names.
    workspace: Workspace | None = None
    # Directories outside the workspace a data-file path may also point at
    # (the operator's system wordlist/seclist roots).
    wordlist_roots: tuple[Path, ...] = ()
    session_id: str = ""
    thread_id: Callable[[], str] = field(default=lambda: "")
    turn_id: Callable[[], int | None] = field(default=lambda: None)
    clock: Callable[[], datetime] | None = None
    cwd: Path | None = None
    command_timeout_s: float = execution.DEFAULT_COMMAND_TIMEOUT_S
    # Whether the provider supports native structured output; the chatgpt path
    # (False) uses protocol's JSON-contract fallback. See Settings.
    native_structured: bool = True
    max_command_rounds: int = 4
    retrieve_k: int = 4
    history_messages: int = 8
    history_chars: int = 4_000
    findings_limit: int = 10
    commands_limit: int = 10
    # The host-awareness block (OS, installers, scoped tool presence) and the
    # harness command catalogue, pre-rendered by the core (see agent.awareness).
    system_facts: str = ""
    harness_catalogue: str = ""
    # The operator's standing preferences, pre-rendered as a bullet list.
    preferences: str = ""
    # Metadata-only inventory of tool-input/evidence files, pre-rendered. The
    # agent references a file by path; its contents never enter a request.
    data_files: str = ""
    # The mode's prompts. Defaults to pentest so an unset caller still gets a
    # coherent (and role-dispatchable) set; the REPL passes the active mode's.
    prompts: PromptSet = field(default_factory=lambda: prompt_set("pentest"))


# --- prompt assembly --------------------------------------------------------


def _redactor(deps: GraphDeps) -> Callable[[str], str]:
    """A redact function bound to this session's policy and vault.

    With a vault each secret becomes a reversible ``«KIND:id»`` placeholder;
    without one (agent-only mode) a default policy still masks one-way, so no
    request can carry a raw secret even when no engagement is loaded.
    """
    policy = deps.redaction_policy or RedactionPolicy()
    return lambda text: redact(text, policy, deps.vault)


def last_user_text(messages: Sequence[BaseMessage]) -> str:
    """The most recent user message, as plain text."""
    for message in reversed(messages):
        if isinstance(message, HumanMessage):
            return message.text
    return ""


def prior_turns(messages: Sequence[BaseMessage]) -> list[BaseMessage]:
    """Completed conversation turns, excluding the request being answered.

    The graph is invoked with the new user message already appended, so the
    trailing human turn(s) are dropped. Only human and assistant messages are
    kept, so nothing but the conversation can reach a prompt.
    """
    kept: list[BaseMessage] = [
        m for m in messages if isinstance(m, (HumanMessage, AIMessage))
    ]
    while kept and isinstance(kept[-1], HumanMessage):
        kept.pop()
    return kept


def render_history(
    messages: Sequence[BaseMessage], *, max_messages: int, max_chars: int
) -> str:
    """Render recent turns as text, bounded by both message count and size.

    Both bounds are needed: a turn count alone is unbounded in size (one pasted
    stack trace fills the context), and a character budget alone would slice a
    message mid-sentence. Whole messages are dropped from the oldest end.
    """
    if max_messages <= 0 or max_chars <= 0:
        return ""
    window = list(messages)[-max_messages:]
    lines = [
        f"{'user' if isinstance(m, HumanMessage) else 'assistant'}: {m.text}"
        for m in window
    ]
    while len(lines) > 1 and sum(len(line) + 1 for line in lines) > max_chars:
        lines.pop(0)
    return "\n".join(lines)


def engagement_brief(engagement: EngagementConfig) -> EngagementBrief:
    """Condense an engagement into the scope brief the model reasons within."""
    return EngagementBrief(
        name=engagement.name,
        stance=engagement.stance,
        autonomous=engagement.autonomous,
        networks=tuple(str(n) for n in engagement.target_networks),
        hosts=tuple(sorted(engagement.allowed_hosts)),
        allowed_tools=tuple(sorted(engagement.allowed_tools)),
        allowed_methods=tuple(sorted(engagement.allowed_methods)),
        methodology=engagement.methodology,
        methodology_phases=methodology_phases(engagement.methodology),
        taxonomies=tuple(sorted(engagement.taxonomies)),
        threat_model=engagement.threat_model is not None,
    )


def _finding_briefs(deps: GraphDeps) -> tuple[FindingBrief, ...]:
    """The most recent findings recorded this session, for a request.

    The title is model-facing, so it is redacted: the ledger stores a finding's
    text raw (operator/report-facing), but a title echoed back into a prompt must
    not reintroduce a secret the evidence happened to contain.
    """
    if deps.ledger is None or not deps.session_id:
        return ()
    clean = _redactor(deps)
    rows = deps.ledger.findings_for(deps.session_id)[-deps.findings_limit :]
    return tuple(
        FindingBrief(
            id=r.id,
            severity=r.severity,
            title=clean(r.title),
            command_id=r.command_id,
            status=r.status,
            # The rejection reason is model-facing, so redact it like the title.
            reason=clean(r.review_reason),
        )
        for r in rows
    )


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


# --- routing ----------------------------------------------------------------


def route_after_critic(state: AgentState) -> Literal["bump", "respond"]:
    """Send an approved draft to the user, otherwise spend a revision."""
    if state.get("approved"):
        return "respond"
    if (state.get("revision_count") or 0) >= (state.get("max_revisions") or 0):
        return "respond"
    return "bump"


def route_after_plan(state: AgentState) -> Literal["retriever", "respond"]:
    """A triaged direct answer skips the pipeline; everything else continues.

    The decision itself is made in ``plan_node`` (so this stays trivially pure,
    like ``route_after_critic``): it writes ``plan_action="answer"`` only when the
    turn is a safe direct reply, and the draft is already set for ``respond``.
    """
    if state.get("plan_action") == "answer":
        return "respond"
    return "retriever"


# An IPv4 address or CIDR block anywhere in the text -- the clearest signal that a
# turn names a target, whatever words surround it. IPv6 and hostnames are covered
# by the engagement-scope check in ``needs_pipeline`` instead, where an exact
# in-scope literal avoids the false positives a loose IPv6/domain regex would hit.
_IP_OR_CIDR = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
# A bare word token, for matching a tool binary name against the message.
_WORD = re.compile(r"[a-z0-9][a-z0-9._-]*")


def needs_pipeline(text: str, deps: GraphDeps) -> bool:
    """Deterministic backstop: True when the turn plainly targets the engagement.

    The planner's triage is an LLM judgement and can mis-read a real recon/tool
    request as conversational. This no-LLM check forces the full pipeline when the
    message names a target (an IP/CIDR token, or an in-scope host/network literal)
    or a known tool binary, so a mis-triage can never answer a scanning request
    from the model's head -- it only ever degrades to taking the slow, safe path.
    Kept to cheap string/set/regex work so it never re-introduces latency.
    """
    if not text.strip():
        return False
    lowered = text.lower()
    if _IP_OR_CIDR.search(text):
        return True
    engagement = deps.engagement
    if engagement is not None:
        if any(host.lower() in lowered for host in engagement.allowed_hosts):
            return True
        if any(str(net).lower() in lowered for net in engagement.target_networks):
            return True
    if deps.registry is not None:
        words = set(_WORD.findall(lowered))
        if any(spec.binary.lower() in words for spec in deps.registry.tools):
            return True
    return False


# --- graph ------------------------------------------------------------------


def _plan_update(
    resp: PlannerResponse, state: AgentState, deps: GraphDeps
) -> PlanUpdate:
    """Map a planner response to a state update, triaging direct answers.

    A direct answer short-circuits the pipeline (planner -> respond) for
    conversational/identity/clarification turns -- but only on the first pass
    (never abandon an in-flight revision and discard the worker's accumulated
    draft/critique), only with a real answer to give, and never when the turn
    plainly targets the engagement (the deterministic backstop). A conversational
    turn does NOT advance the methodology phase.
    """
    current = state.get("phase", "recon")
    revising = (state.get("revision_count") or 0) > 0
    answer = resp.answer.strip()
    direct = (
        resp.action == "answer"
        and bool(answer)
        and not revising
        and not needs_pipeline(last_user_text(state["messages"]), deps)
    )
    if direct:
        return {
            "plan_action": "answer",
            "draft": answer,
            "phase": current,
            "commands": [],
            "command_rounds": 0,
        }
    # Advance the phase at most once per turn (on the first pass), so a
    # multi-revision turn cannot walk several phases forward.
    phase = clamp_phase(current, resp.advance_to) if not revising else current
    return {
        "plan_action": "plan",
        "plan": list(resp.steps),
        "phase": phase,
        # Reset this turn's command trail and round counter for the new pass.
        "commands": [],
        "command_rounds": 0,
    }


def _execute_node(state: AgentState, deps: GraphDeps, work_dir: Path) -> ExecutorUpdate:
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


def _respond_node(state: AgentState) -> ReplyUpdate:
    """Emit the accumulated draft as the turn's answer."""
    return {"messages": [AIMessage(content=state.get("draft") or "")]}


def _bump_node(state: AgentState) -> RevisionUpdate:
    """Count a revision pass so the planner can cap how many it allows."""
    return {"revision_count": (state.get("revision_count") or 0) + 1}


def _retrieve_node(
    state: AgentState, deps: GraphDeps, clean: Callable[[str], str]
) -> ContextUpdate:
    """Inline a top-k retrieval snippet ahead of the worker."""
    if deps.store is None:
        return {}
    hits = deps.store.search(last_user_text(state["messages"]), k=deps.retrieve_k)
    # Redact before the snippet is stored in graph state, so a secret in an
    # ingested document never lands in the checkpoint either.
    return {"context": clean(format_hits(hits))} if hits else {}


def _route_after_executor(
    state: AgentState, deps: GraphDeps
) -> Literal["worker", "critic"]:
    """Loop back to the worker only while an autonomous run can still make progress."""
    resp = state.get("worker")
    if resp is None or resp.done or resp.command is None:
        return "critic"
    if deps.engagement is None or not deps.engagement.autonomous:
        return "critic"
    if (state.get("command_rounds") or 0) >= deps.max_command_rounds:
        return "critic"
    commands = state.get("commands") or []
    if not commands or commands[-1].status != "executed":
        return "critic"
    return "worker"


def build_graph(
    deps: GraphDeps, checkpointer: BaseCheckpointSaver[str]
) -> CompiledStateGraph[AgentState]:
    """Compile the agent graph (its nodes are its statements)."""
    work_dir = (deps.cwd or Path.cwd()).resolve()
    policy = deps.redaction_policy or RedactionPolicy()
    clean = _redactor(deps)

    def history(state: AgentState, *, divisor: int = 1) -> str:
        return render_history(
            prior_turns(state["messages"]),
            max_messages=deps.history_messages,
            max_chars=deps.history_chars // divisor,
        )

    def context(
        state: AgentState, *, divisor: int = 1, **extra: object
    ) -> RequestContext:
        brief = (
            engagement_brief(deps.engagement) if deps.engagement is not None else None
        )
        commands = list(state.get("commands", []))[-deps.commands_limit :]
        # Redact every free-text field that originates outside the harness
        # before it is assembled into a request: the operator's prompt and
        # history (an accidental paste), the operator's preferences, and the
        # retrieved context. Command summaries and finding titles are already
        # redacted at their own ingress; findings/engagement/phase/plan are
        # harness-structured. ``ask`` then applies the egress net over the whole.
        return RequestContext(
            request=clean(last_user_text(state["messages"])),
            phase=state.get("phase", "recon"),
            engagement=brief,
            system_facts=deps.system_facts,
            harness_catalogue=deps.harness_catalogue,
            history=clean(history(state, divisor=divisor)),
            preferences=clean(deps.preferences),
            data_files=deps.data_files,
            retrieved_context=clean(state.get("context") or ""),
            findings=_finding_briefs(deps),
            recent_commands=tuple(commands),
            **extra,  # type: ignore[arg-type]
        )

    def ask[T: (PlannerResponse, WorkerResponse, CriticResponse)](
        system: str, ctx: RequestContext, schema: type[T]
    ) -> T:
        # The egress net: every model-bound request is assembled here, so this
        # is the one place to re-scan the whole block. Ingress redaction already
        # masked the free-text fields; ``scrub`` masks-and-logs anything that
        # only a detector sees in the assembled context (defence in depth), so a
        # detector gap degrades to an over-mask, never a disclosure.
        prompt: list[BaseMessage] = [
            SystemMessage(content=system),
            HumanMessage(content=scrub(render_request(ctx), policy)),
        ]
        llm = deps.llm
        if llm is None:  # defensive: core.turn builds the model before streaming
            msg = "no model provider configured; run /setup"
            raise RuntimeError(msg)
        return structured_invoke(llm, schema, prompt, native=deps.native_structured)

    def plan_node(state: AgentState) -> PlanUpdate:
        ctx = context(state, prior_critique=state.get("critique") or "")
        resp = ask(deps.prompts.planner, ctx, PlannerResponse)
        return _plan_update(resp, state, deps)

    def retrieve_node(state: AgentState) -> ContextUpdate:
        return _retrieve_node(state, deps, clean)

    def work_node(state: AgentState) -> WorkerUpdate:
        ctx = context(state, plan=tuple(state.get("plan") or ()))
        resp = ask(deps.prompts.worker, ctx, WorkerResponse)
        return {"worker": resp, "draft": render_response(resp)}

    def execute_node(state: AgentState) -> ExecutorUpdate:
        return _execute_node(state, deps, work_dir)

    def route_after_executor(state: AgentState) -> Literal["worker", "critic"]:
        return _route_after_executor(state, deps)

    def critique_node(state: AgentState) -> CritiqueUpdate:
        ctx = context(state, divisor=2, draft=state.get("draft") or "")
        resp = ask(deps.prompts.critic, ctx, CriticResponse)
        return {"approved": resp.approved, "critique": resp.reason}

    graph: StateGraph[AgentState, None, AgentState, AgentState] = StateGraph(AgentState)
    graph.add_node("planner", plan_node)
    graph.add_node("retriever", retrieve_node)
    graph.add_node("worker", work_node)
    graph.add_node("executor", execute_node)
    graph.add_node("critic", critique_node)
    graph.add_node("respond", _respond_node)
    graph.add_node("bump", _bump_node)

    graph.add_edge(START, "planner")
    graph.add_conditional_edges("planner", route_after_plan)
    graph.add_edge("retriever", "worker")
    graph.add_edge("worker", "executor")
    graph.add_conditional_edges("executor", route_after_executor)
    graph.add_conditional_edges("critic", route_after_critic)
    graph.add_edge("bump", "planner")
    graph.add_edge("respond", END)
    return graph.compile(checkpointer=checkpointer)


def _now(deps: GraphDeps) -> datetime:
    """The current time in the engagement timezone (or the injected clock)."""
    if deps.clock is not None:
        return deps.clock()
    assert deps.engagement is not None  # noqa: S101 -- only called on the guarded path
    return datetime.now(deps.engagement.tzinfo())


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
        cid = deps.ledger.record_command(
            session_id=deps.session_id,
            thread_id=deps.thread_id(),
            command=command,
            binary=parsed.binary,
            method=parsed.method,
            status="blocked",
            reason=verdict.reason,
            turn_event_id=deps.turn_id(),
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
        cid = deps.ledger.record_command(
            session_id=deps.session_id,
            thread_id=deps.thread_id(),
            command=command,
            binary=parsed.binary,
            method=parsed.method,
            status="proposed",
            turn_event_id=deps.turn_id(),
        )
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
    )
    try:
        cid = deps.ledger.record_command(
            session_id=deps.session_id,
            thread_id=deps.thread_id(),
            command=command,
            binary=parsed.binary,
            method=parsed.method,
            status="executed",
            result=result,
            turn_event_id=deps.turn_id(),
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
    threat_model = deps.engagement.threat_model if deps.engagement else None
    env_metrics = threat_model.cvss_environmental_metrics() if threat_model else {}
    tm_version = deps.ledger.current_threat_model_version() or None
    primary = (
        "attack"
        if deps.engagement and deps.engagement.methodology == "attack"
        else "wstg"
    )
    for finding in resp.findings:
        vector = finding.cvss_vector or None
        refs = [
            FindingRefInput(
                ref.framework, ref.ref_id, is_primary=ref.framework == primary
            )
            for ref in finding.refs
        ]
        try:
            deps.ledger.record_finding(
                session_id=deps.session_id,
                title=finding.title,
                severity=finding.severity,
                description=finding.description,
                evidence=finding.evidence,
                command_id=link,
                cvss_vector=vector,
                env_metrics=env_metrics,
                tm_version=tm_version,
                refs=refs,
                author="agent",
            )
        except Exception:
            # Evidence loss: a finding the agent produced did not persist. This is
            # the worst case for an engagement, so name it explicitly, then raise.
            # error, not exception: the traceback is logged once at the turn boundary.
            log.error(  # noqa: TRY400 -- traceback logged at the turn boundary
                "evidence loss: failed to record finding %r", finding.title
            )
            raise


def recursion_limit(*, max_revisions: int, max_command_rounds: int) -> int:
    """Supersteps needed for the worst-case turn, plus headroom.

    One pass is planner + retriever + (worker + executor) per command round +
    critic + bump/respond. A turn that both loops on commands and gets revised
    needs more than langgraph's default of 25.
    """
    per_pass = 2 * (max_command_rounds + 1) + 3
    return (max_revisions + 1) * per_pass + 4
