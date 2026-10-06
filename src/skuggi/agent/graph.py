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
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from skuggi.agent.executor import (
    _redactor,
    brief_from_row,
    execute_node,
    route_after_executor,
)
from skuggi.agent.prompts import SUMMARY_INSTRUCTION, PromptSet, prompt_set
from skuggi.agent.protocol import (
    CommandBrief,
    CredentialBrief,
    CriticResponse,
    EngagementBrief,
    FindingBrief,
    LootBrief,
    NoteBrief,
    PlannerResponse,
    RequestContext,
    SummaryResponse,
    WorkerResponse,
    clamp_phase,
    methodology_phases,
)
from skuggi.agent.protocol_render import render_request, render_response
from skuggi.agent.requests import ask as _ask
from skuggi.agent.requests import last_user_text, prior_turns, render_history
from skuggi.agent.state import (
    AgentState,
    ContextUpdate,
    CritiqueUpdate,
    ExecutorUpdate,
    PlanUpdate,
    ReplyUpdate,
    RevisionUpdate,
    SummaryUpdate,
    WorkerUpdate,
)
from skuggi.common import execution
from skuggi.common.logs import get_logger
from skuggi.engagement.engagement import EngagementConfig
from skuggi.engagement.workspace import Workspace
from skuggi.persistence.ledger import Ledger
from skuggi.persistence.vectorstore import Store, format_hits
from skuggi.security.policy import RedactionPolicy
from skuggi.security.vault import SecretVault
from skuggi.tooling.registry import ToolRegistry

log = get_logger(__name__)


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
    # How a cleared, in-scope command is actually run: a hardened host
    # subprocess (default) or a container with a netns egress allow-list.
    # None falls back to a default ``HostBackend`` in the executor, so an
    # agent-only ``GraphDeps`` keeps working.
    backend: execution.ExecutionBackend | None = None
    # Whether the provider supports native structured output; the chatgpt path
    # (False) uses protocol's JSON-contract fallback. See Settings.
    native_structured: bool = True
    max_command_rounds: int = 4
    retrieve_k: int = 4
    # When False, a plain target/tool turn skips retrieval (audit D3).
    retrieve_on_recon: bool = False
    history_messages: int = 8
    history_chars: int = 4_000
    # Fold turns scrolling out of the window into a running summary (compactor node).
    compact_history: bool = True
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
    """The most recent findings for this engagement, for a request.

    Engagement-scoped, not session-scoped: ``session_id`` is a fresh UUID every
    launch, so a session-only recall would blank the agent's memory of findings on
    day two of the same engagement. With an engagement loaded we pull its whole
    cross-session record (deduped); with none (agent-only mode) we fall back to the
    current session.

    The title is model-facing, so it is redacted: the ledger stores a finding's
    text raw (operator/report-facing), but a title echoed back into a prompt must
    not reintroduce a secret the evidence happened to contain.
    """
    if deps.ledger is None:
        return ()
    if deps.engagement is not None:
        rows = deps.ledger.findings_for_engagement(deps.engagement.name)
    elif deps.session_id:
        rows = deps.ledger.findings_for(deps.session_id)
    else:
        return ()
    clean = _redactor(deps)
    rows = rows[-deps.findings_limit :]
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


def _credential_briefs(deps: GraphDeps) -> tuple[CredentialBrief, ...]:
    """The captured credentials for a request -- their nature, never the secret.

    Engagement-scoped like findings (``session_id`` is per-launch, so a session-only
    view would hide a credential captured on an earlier day), falling back to the
    session in agent-only mode. No redaction step is needed: a row holds only a
    vault ``secret_ref`` placeholder, which the worker may reference in a command
    (rehydrated at exec) without ever seeing the value. Capped like findings.
    """
    if deps.ledger is None:
        return ()
    if deps.engagement is not None:
        rows = deps.ledger.credentials_for_engagement(deps.engagement.name)
    elif deps.session_id:
        rows = deps.ledger.credentials_for(deps.session_id)
    else:
        return ()
    return tuple(
        CredentialBrief(
            id=r.id,
            host=r.host,
            service=r.service,
            username=r.username,
            secret_ref=r.secret_ref,
            validated=bool(r.validated),
        )
        for r in rows[-deps.findings_limit :]
    )


def _loot_briefs(deps: GraphDeps, clean: Callable[[str], str]) -> tuple[LootBrief, ...]:
    """Captured loot for a request -- its nature, never a raw secret.

    Engagement-scoped like findings. ``label`` is redacted at storage; it is cleaned
    again here as the egress net (idempotent), and ``secret_ref`` is a vault
    placeholder, so the brief is safe to show. Capped like findings.
    """
    if deps.ledger is None:
        return ()
    if deps.engagement is not None:
        rows = deps.ledger.loot_for_engagement(deps.engagement.name)
    elif deps.session_id:
        rows = deps.ledger.loot_for(deps.session_id)
    else:
        return ()
    return tuple(
        LootBrief(
            id=r.id,
            kind=r.kind,
            host=r.host,
            label=clean(r.label),
            secret_ref=r.secret_ref,
        )
        for r in rows[-deps.findings_limit :]
    )


def _note_briefs(deps: GraphDeps, clean: Callable[[str], str]) -> tuple[NoteBrief, ...]:
    """Notes for a request -- subject/asset + redacted body. Engagement-scoped."""
    if deps.ledger is None:
        return ()
    if deps.engagement is not None:
        rows = deps.ledger.notes_for_engagement(deps.engagement.name)
    elif deps.session_id:
        rows = deps.ledger.notes_for(deps.session_id)
    else:
        return ()
    return tuple(
        NoteBrief(id=r.id, subject=r.subject, host=r.host, text=clean(r.text))
        for r in rows[-deps.findings_limit :]
    )


def _command_briefs(
    deps: GraphDeps, state: AgentState, clean: Callable[[str], str]
) -> tuple[CommandBrief, ...]:
    """The recent commands for a request: cross-turn via the ledger, redacted.

    ``state["commands"]`` holds only this turn's trail (the planner resets it each
    turn), so sourcing from it alone meant the worker forgot what it ran on earlier
    turns. A bounded ledger window restores that cross-turn recall. Each row is
    re-redacted into a model-facing brief (the ledger stores raw output). Falls back
    to the in-turn trail in agent-only mode (no ledger), where the state briefs were
    already redacted when the executor built them.
    """
    if deps.ledger is not None and deps.session_id:
        rows = deps.ledger.recent_commands_for(deps.session_id, deps.commands_limit)
        return tuple(brief_from_row(row, clean) for row in rows)
    return tuple(list(state.get("commands", []))[-deps.commands_limit :])


# The node each response schema belongs to, so the per-turn latency breakdown
# labels a round-trip by its node (planner/worker/critic) rather than by the
# schema class name. Used by the ``ask`` closure in ``build_graph``.
_NODE_LABELS: dict[type, str] = {
    PlannerResponse: "planner",
    WorkerResponse: "worker",
    CriticResponse: "critic",
}


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
            "lookups": [],
            "command_rounds": 0,
        }
    # Advance the phase at most once per turn (on the first pass), so a
    # multi-revision turn cannot walk several phases forward.
    phase = clamp_phase(current, resp.advance_to) if not revising else current
    return {
        "plan_action": "plan",
        "plan": list(resp.steps),
        "phase": phase,
        # Reset this turn's command trail, lookup results and round counter.
        "commands": [],
        "lookups": [],
        "command_rounds": 0,
    }


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
    text = last_user_text(state["messages"])
    # A plain target/tool turn (a scan/exploit request) gains nothing from the
    # ingested knowledge corpus, so skip the embed unless configured otherwise
    # (audit D3); a research/knowledge turn still retrieves.
    if not deps.retrieve_on_recon and needs_pipeline(text, deps):
        return {}
    hits = deps.store.search(text, k=deps.retrieve_k)
    # Redact before the snippet is stored in graph state, so a secret in an
    # ingested document never lands in the checkpoint either.
    return {"context": clean(format_hits(hits))} if hits else {}


def _compact_node(
    state: AgentState, deps: GraphDeps, clean: Callable[[str], str]
) -> SummaryUpdate:
    """Fold turns that scrolled out of the window into the running summary.

    Runs once at the start of a turn, before the planner. Only when prior turns now
    exceed the verbatim window does it spend a model call, folding just the
    newly-overflowed turns (``summary_len`` advances) into the existing summary. A
    short session never overflows, so it is free there.
    """
    if not deps.compact_history or deps.llm is None:
        return {}
    prior = prior_turns(state["messages"])
    cut = len(prior) - deps.history_messages
    already = state.get("summary_len") or 0
    if cut <= already:
        return {}
    overflow = prior[already:cut]
    rendered = clean(
        render_history(
            overflow, max_messages=len(overflow), max_chars=deps.history_chars
        )
    )
    existing = state.get("summary") or "(none)"
    human = f"Existing summary:\n{existing}\n\nNew exchanges:\n{rendered}"
    resp = _ask(
        deps.llm,
        SUMMARY_INSTRUCTION,
        human,
        SummaryResponse,
        policy=deps.redaction_policy or RedactionPolicy(),
        native=deps.native_structured,
        label="compactor",
    )
    return {"summary": clean(resp.summary), "summary_len": cut}


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
        commands = _command_briefs(deps, state, clean)
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
            conversation_summary=clean(state.get("summary") or ""),
            history=clean(history(state, divisor=divisor)),
            preferences=clean(deps.preferences),
            data_files=deps.data_files,
            retrieved_context=clean(state.get("context") or ""),
            findings=_finding_briefs(deps),
            credentials=_credential_briefs(deps),
            loot=_loot_briefs(deps, clean),
            notes=_note_briefs(deps, clean),
            recent_commands=tuple(commands),
            lookup_results=tuple(state.get("lookups", [])),
            **extra,  # type: ignore[arg-type]
        )

    def ask[T: (PlannerResponse, WorkerResponse, CriticResponse)](
        system: str, ctx: RequestContext, schema: type[T]
    ) -> T:
        # Delegates to the shared egress seam (``requests.ask``): it scrubs the
        # rendered request -- the one place the whole block is re-scanned -- and
        # obtains the validated schema. This closure only binds the turn graph's
        # plumbing (llm/policy/native) and renders the turn's RequestContext.
        # The schema identifies the node, so the latency breakdown can attribute
        # each round-trip without the node call sites passing a label by hand.
        return _ask(
            deps.llm,
            system,
            render_request(ctx),
            schema,
            policy=policy,
            native=deps.native_structured,
            label=_NODE_LABELS.get(schema, schema.__name__.lower()),
        )

    def compact_node(state: AgentState) -> SummaryUpdate:
        return _compact_node(state, deps, clean)

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

    def executor_node(state: AgentState) -> ExecutorUpdate:
        return execute_node(state, deps, work_dir)

    def after_executor(state: AgentState) -> Literal["worker", "critic", "respond"]:
        return route_after_executor(state, deps)

    def critique_node(state: AgentState) -> CritiqueUpdate:
        ctx = context(state, divisor=2, draft=state.get("draft") or "")
        resp = ask(deps.prompts.critic, ctx, CriticResponse)
        return {"approved": resp.approved, "critique": resp.reason}

    graph: StateGraph[AgentState, None, AgentState, AgentState] = StateGraph(AgentState)
    graph.add_node("compactor", compact_node)
    graph.add_node("planner", plan_node)
    graph.add_node("retriever", retrieve_node)
    graph.add_node("worker", work_node)
    graph.add_node("executor", executor_node)
    graph.add_node("critic", critique_node)
    graph.add_node("respond", _respond_node)
    graph.add_node("bump", _bump_node)

    graph.add_edge(START, "compactor")
    graph.add_edge("compactor", "planner")
    graph.add_conditional_edges("planner", route_after_plan)
    graph.add_edge("retriever", "worker")
    graph.add_edge("worker", "executor")
    graph.add_conditional_edges("executor", after_executor)
    graph.add_conditional_edges("critic", route_after_critic)
    graph.add_edge("bump", "planner")
    graph.add_edge("respond", END)
    return graph.compile(checkpointer=checkpointer)


def recursion_limit(*, max_revisions: int, max_command_rounds: int) -> int:
    """Supersteps needed for the worst-case turn, plus headroom.

    One pass is planner + retriever + (worker + executor) per command round +
    critic + bump/respond. A turn that both loops on commands and gets revised
    needs more than langgraph's default of 25.

    ``2 * (rounds + 1)`` is the worker+executor pair per command round (plus the
    final non-command pair); the ``+ 3`` is the per-pass planner, retriever and
    critic. The trailing ``+ 5`` is slack -- the once-per-turn compactor superstep
    plus headroom so a worst-case turn stops at ``respond`` rather than tripping
    langgraph's recursion guard one step early.
    """
    per_pass = 2 * (max_command_rounds + 1) + 3
    return (max_revisions + 1) * per_pass + 5
