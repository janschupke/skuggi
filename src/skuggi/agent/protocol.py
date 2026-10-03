"""The strict structured request/response protocol for every LLM interaction.

skuggi used to hand the model free text and read free text back: the planner and
critic consumed ``.text`` verbatim, the critic was routed by a ``startswith
("APPROVED")`` string test, and the worker proposed commands through a tool whose
string result was pasted to the operator's terminal. This module replaces all of
that with a typed contract.

Two halves, both pydantic so they validate at the boundary:

- **Request** -- what the harness sends. A :class:`RequestContext` bundles the
  conversation history, the engagement scope + stance, the current methodology
  :data:`Phase`, and the relevant prior findings and commands. It is rendered to
  a single labelled text block by :func:`render_request`.
- **Response** -- what the model must return. Each node has one strict schema
  (:class:`PlannerResponse`, :class:`WorkerResponse`, :class:`CriticResponse`,
  plus the out-of-graph :class:`ConfigProposal` / :class:`MemoryExtraction`).
  :func:`structured_invoke` is the single seam that obtains a validated instance,
  natively (``with_structured_output``) where the provider supports it and via a
  JSON contract + one repair retry on the tool-less chatgpt path.

:func:`render_response` lays a :class:`WorkerResponse` out deterministically, so
the operator only ever sees model text inside fields the harness placed -- never
raw model output pasted to a CLI.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Literal, cast, get_args

from langchain_core.language_models import BaseChatModel, LanguageModelInput
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from skuggi.common.text import join_blocks, labeled
from skuggi.frameworks import cvss, registry

# --- domain enums -----------------------------------------------------------

# The pentest methodology phase. Ordered: advancement is forward-only and by at
# most one step (see clamp_phase), so the model can suggest progress but never
# skip recon straight to exploitation.
Phase = Literal[
    "recon", "enumeration", "exploitation", "post_exploitation", "reporting"
]
PHASES: tuple[Phase, ...] = get_args(Phase)

# The engagement's posture -- how forward-leaning the agent's suggestions should
# be. Advisory: it calibrates what the agent *proposes*, never what the guard
# *allows* (scope enforcement stays entirely in skuggi.engagement.check_command).
Stance = Literal["passive", "cautious", "balanced", "aggressive"]
STANCES: tuple[Stance, ...] = get_args(Stance)

# Kept in lockstep with palette.severities(); test_protocol pins the two equal.
Severity = Literal["info", "low", "medium", "high", "critical"]

# The engagement's driving methodology (prescriptive -- what the agent follows):
# skuggi's built-in phase model, PTES, or ATT&CK adversary-emulation. It shapes the
# phase vocabulary presented to the planner/worker; the internal Phase channel above
# stays the stable state machine regardless.
Methodology = Literal["phases", "ptes", "attack"]
METHODOLOGIES: tuple[Methodology, ...] = get_args(Methodology)

# Optional per-finding classification taxonomies (descriptive -- applied where they
# fit, never forced). CVSS is always-on and is NOT one of these.
Taxonomy = Literal["wstg", "attack"]
TAXONOMIES: tuple[Taxonomy, ...] = get_args(Taxonomy)

# The ATT&CK Enterprise tactics, in kill-chain order -- the "phases" an adversary-
# emulation engagement works through (the technique catalogue is in frameworks.data).
_ATTACK_TACTICS: tuple[str, ...] = (
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
)  # fmt: skip


def methodology_phases(methodology: Methodology) -> tuple[str, ...]:
    """The phase/stage names a methodology works through, for the prompt framing.

    ``phases`` is skuggi's built-in model; ``ptes`` reads the vendored PTES phase
    titles (single source with the taxonomy data); ``attack`` is the ATT&CK tactic
    chain. This is what the driver uses to steer the agent without changing the
    internal :data:`Phase` channel.
    """
    if methodology == "ptes":
        return tuple(ref.title for ref in registry.entries("ptes"))
    if methodology == "attack":
        return _ATTACK_TACTICS
    return PHASES


def clamp_phase(current: Phase, requested: Phase | None) -> Phase:
    """Resolve a model-requested phase to a safe next phase.

    Forward-only and by at most one step: a request to stay or regress keeps the
    current phase, a request to jump ahead is clamped to exactly ``current + 1``.
    The model advises; this function -- not the model -- decides.
    """
    if requested is None:
        return current
    ci, ri = PHASES.index(current), PHASES.index(requested)
    return PHASES[min(max(ri, ci), ci + 1, len(PHASES) - 1)]


# --- request side -----------------------------------------------------------


class EngagementBrief(BaseModel):
    """The engagement scope, as much as the model needs to reason within it."""

    model_config = ConfigDict(frozen=True)

    name: str
    stance: Stance
    autonomous: bool
    networks: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    allowed_methods: tuple[str, ...] = ()
    # Framework awareness: the driving methodology + its phase outline, the enabled
    # per-finding classification taxonomies, and whether a CVSS threat model is set.
    methodology: Methodology = "phases"
    methodology_phases: tuple[str, ...] = ()
    taxonomies: tuple[Taxonomy, ...] = ()
    threat_model: bool = False


class FindingBrief(BaseModel):
    """A prior finding, condensed for a request. Full text lives in the ledger.

    ``status`` lets the worker see which findings were approved vs rejected; a
    rejected finding carries its ``reason`` so the worker learns why and does not
    re-assert it. ``title`` and ``reason`` are redacted before this is built (both
    reach the model); ``evidence`` is never projected here.
    """

    model_config = ConfigDict(frozen=True)

    id: int
    severity: str
    title: str
    command_id: int | None = None
    status: str = "draft"
    reason: str = ""


class CommandBrief(BaseModel):
    """A prior command and how it ended, condensed for a request."""

    model_config = ConfigDict(frozen=True)

    id: int
    status: str
    command: str
    exit_code: int | None = None
    summary: str = ""


class RequestContext(BaseModel):
    """Everything a node's request carries, assembled by the harness.

    A single object so a new node builds a request the same way as every other,
    and so a test can assert that phase / findings / scope actually reached the
    prompt rather than eyeballing a concatenated string.
    """

    model_config = ConfigDict(frozen=True)

    request: str
    phase: Phase = "recon"
    engagement: EngagementBrief | None = None
    # Host awareness: OS, available installers, scoped tool presence (metadata
    # only, no file contents). The harness command catalogue (verbs/nouns + saved
    # cmd aliases) so the agent can direct the operator in the harness's own terms.
    # Both are harness-generated, so -- like the engagement block -- they are not
    # run through the ingress redactor; the egress scrub in ``ask`` still covers them.
    system_facts: str = ""
    harness_catalogue: str = ""
    history: str = ""
    preferences: str = ""
    retrieved_context: str = ""
    # Metadata-only inventory of tool-input/evidence files (names, sizes, hashes)
    # so the agent can point a tool at one by path without ever seeing contents.
    data_files: str = ""
    findings: tuple[FindingBrief, ...] = ()
    recent_commands: tuple[CommandBrief, ...] = ()
    plan: tuple[str, ...] = ()  # planner output, for the worker
    prior_critique: str = ""  # critic output, for the planner's next pass
    draft: str = ""  # worker output, for the critic


# --- response side ----------------------------------------------------------


class PlannerResponse(BaseModel):
    """The planner's strict output: a triage decision, a plan, a phase judgement.

    The planner evaluates whether the full pipeline is warranted. For a
    conversational / identity / clarification / simple-advice turn that needs no
    recon, tools or multi-step work it returns ``action="answer"`` with the reply
    in ``answer``; the graph then routes straight to ``respond`` in a single model
    call, skipping the worker and critic. For anything that needs reconnaissance,
    a command, or multi-step investigation it returns ``action="plan"`` with
    ``steps`` and the existing pipeline runs. ``action`` defaults to ``"plan"`` so
    a provider (or fake) that omits it keeps the old always-pipeline behaviour.
    ``answer`` is read only when ``action == "answer"``.
    """

    model_config = ConfigDict(frozen=True)

    # Phase advancement is owned by code (``clamp_phase``), not the model: the
    # planner only *suggests* the next phase via ``advance_to``. There is no
    # required ``phase`` field -- a provider that omits it must not fail the turn.
    advance_to: Phase | None = None
    action: Literal["answer", "plan"] = "plan"
    answer: str = ""
    steps: tuple[str, ...] = ()
    rationale: str = ""


class FindingRefDraft(BaseModel):
    """A framework classification the worker attaches to a finding (validated)."""

    model_config = ConfigDict(frozen=True)

    framework: Taxonomy
    ref_id: str

    @model_validator(mode="after")
    def _known_id(self) -> FindingRefDraft:
        if not registry.validate_id(self.framework, self.ref_id):
            msg = f"unknown {self.framework} id: {self.ref_id!r}"
            raise ValueError(msg)
        return self


class FindingDraft(BaseModel):
    """A finding the worker wants recorded, before it reaches the ledger.

    The worker supplies a CVSS v3.1 ``cvss_vector`` (it assesses the metrics; the
    harness computes the score -- never the model) and optionally classifies the
    finding with ``refs`` from the engagement's enabled taxonomies. ``severity`` is
    only for a finding CVSS does not apply to (e.g. an informational note); when a
    vector is given the band is derived from it.
    """

    model_config = ConfigDict(frozen=True)

    title: str
    description: str
    evidence: str = ""
    cvss_vector: str = ""
    severity: Severity | None = None
    refs: tuple[FindingRefDraft, ...] = ()

    @model_validator(mode="after")
    def _scorable(self) -> FindingDraft:
        if self.cvss_vector:
            cvss.parse(self.cvss_vector)  # raises on a malformed vector
        elif self.severity is None:
            msg = "a finding needs a cvss_vector or a severity"
            raise ValueError(msg)
        return self

    def display_severity(self) -> str:
        """The severity band to show/record: from the vector, else the bare severity."""
        if self.cvss_vector:
            return cvss.score(self.cvss_vector).severity
        return self.severity or "info"


class WorkerResponse(BaseModel):
    """The worker's strict output -- the heart of the protocol.

    Exactly one of the action shapes is expressed: a ``command`` to run/propose,
    or prose ``advice`` when none is warranted. ``summary`` and ``conclusions``
    are always meaningful; ``findings`` are recorded by the executor; ``done``
    signals the autonomous loop that no further command is needed this turn.
    """

    model_config = ConfigDict(frozen=True)

    command: str | None = None
    summary: str = ""
    stance: Stance = "cautious"
    conclusions: str = ""
    advice: str = ""
    findings: tuple[FindingDraft, ...] = ()
    done: bool = False


class CriticResponse(BaseModel):
    """The critic's strict output -- a boolean verdict, not a parsed prefix."""

    model_config = ConfigDict(frozen=True)

    approved: bool
    reason: str = ""


class ConfigEdit(BaseModel):
    """One proposed ``key = value`` edit to the application config."""

    model_config = ConfigDict(frozen=True)

    key: str
    value: str


class ConfigProposal(BaseModel):
    """The `config <natural language>` verb's strict output."""

    model_config = ConfigDict(frozen=True)

    edits: tuple[ConfigEdit, ...] = ()


ScopeField = Literal[
    "allowed_hosts",
    "target_networks",
    "allowed_tools",
    "allowed_methods",
    "autonomous_ceiling",
]
SCOPE_FIELDS: tuple[ScopeField, ...] = get_args(ScopeField)


class ScopeEdit(BaseModel):
    """One proposed edit to the engagement scope.

    ``add``/``remove`` apply to the set-valued fields (hosts/networks/tools/
    methods); ``set`` applies to a scalar (``autonomous_ceiling``). The value is
    a single element/scalar as a string -- a host, a CIDR, a tool/method name, or
    a risk-tier name -- re-validated by ``EngagementConfig`` before it is written.
    """

    model_config = ConfigDict(frozen=True)

    field: ScopeField
    action: Literal["add", "remove", "set"]
    value: str


class ScopeProposal(BaseModel):
    """The ``set scope <natural language>`` verb's strict output."""

    model_config = ConfigDict(frozen=True)

    edits: tuple[ScopeEdit, ...] = ()


class CmdProposal(BaseModel):
    """The ``cmd suggest <request>`` verb's strict output: one proposed alias.

    Validator-free so a stray field never fails the LLM call; the harness builds
    and validates a real ``CommandAlias`` from it before anything is written (and
    reports a rejection). An empty ``name``/``argv`` means "nothing proposed".
    """

    model_config = ConfigDict(frozen=True)

    name: str = ""
    argv: tuple[str, ...] = ()
    description: str = ""
    tool: str = ""
    label: str = ""


class MemoryExtraction(BaseModel):
    """The automatic-memory extractor's strict output: durable directives only."""

    model_config = ConfigDict(frozen=True)

    directives: tuple[str, ...] = ()


# --- rendering --------------------------------------------------------------


def _findings_block(findings: Sequence[FindingBrief]) -> str:
    lines = []
    for f in findings:
        cmd = f" (cmd:{f.command_id})" if f.command_id is not None else ""
        if f.status == "rejected":
            why = f" — {f.reason}" if f.reason else ""
            lines.append(f"[{f.id}] REJECTED {f.title}{why}{cmd} (do not re-assert)")
        else:
            tag = "" if f.status == "approved" else f" ({f.status})"
            lines.append(f"[{f.id}] {f.severity.upper()}{tag}: {f.title}{cmd}")
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
        labeled("Conversation so far", ctx.history),
        labeled("Prior findings", _findings_block(ctx.findings)),
        labeled("Recent commands", _commands_block(ctx.recent_commands)),
        labeled("Data files", ctx.data_files),
        labeled("Retrieved context", ctx.retrieved_context),
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


# --- the structured-output seam ---------------------------------------------

_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.MULTILINE)


def format_instructions(schema: type[BaseModel]) -> str:
    """The JSON contract appended to a request on the non-native path."""
    js = json.dumps(schema.model_json_schema(), indent=2, sort_keys=True)
    return (
        "Respond with a SINGLE JSON object and nothing else -- no prose, no "
        "markdown, no code fences -- conforming to this JSON schema:\n" + js
    )


def _text_of(reply: object) -> str:
    """The plain text of a chat reply, however the provider shaped it.

    A chat model returns a ``BaseMessage``. With the OpenAI Responses API -- the
    ``chatgpt``/codex provider, and the only one on this non-native path -- its
    ``content`` is a list of content blocks (a reasoning item plus a text item),
    not a string. ``BaseMessage.text`` flattens that to the assistant's text,
    skipping the reasoning/non-text blocks; ``str(content)`` would instead yield a
    Python repr (single quotes) that is not valid JSON and crashes ``_extract_json``.
    The ``.text`` *property* is used deliberately -- calling ``.text()`` is
    deprecated and the suite runs under ``-W error``.
    """
    if isinstance(reply, BaseMessage):
        return str(reply.text)
    content = getattr(reply, "content", reply)
    return content if isinstance(content, str) else str(content)


def _extract_json[T: BaseModel](text: str, schema: type[T]) -> T:
    """Parse the first JSON object out of ``text`` and validate it as ``schema``.

    Tolerant of a stray code fence or leading prose: the object is located by its
    outermost braces. A parse or validation failure raises, so the caller can
    decide whether to spend a repair retry.
    """
    stripped = _FENCE.sub("", text).strip()
    start, end = stripped.find("{"), stripped.rfind("}")
    if start == -1 or end <= start:
        msg = "no JSON object found in the reply"
        raise ValueError(msg)
    return schema.model_validate_json(stripped[start : end + 1])


def structured_invoke[T: BaseModel](
    llm: BaseChatModel,
    schema: type[T],
    messages: Sequence[BaseMessage],
    *,
    native: bool,
    repair: bool = True,
) -> T:
    """Obtain a validated ``schema`` instance from one LLM call.

    ``native`` providers use ``with_structured_output``. The tool-less chatgpt
    path instead appends :func:`format_instructions`, parses the JSON out of the
    reply, and -- once, when ``repair`` is set -- re-asks with the validation
    error if the first reply does not validate.
    """
    msgs = list(messages)
    if native:
        raw = llm.with_structured_output(schema).invoke(
            cast("LanguageModelInput", msgs)
        )
        return schema.model_validate(raw)

    instructed: list[BaseMessage] = [
        *msgs,
        SystemMessage(content=format_instructions(schema)),
    ]
    text = _text_of(llm.invoke(cast("LanguageModelInput", instructed)))
    try:
        return _extract_json(text, schema)
    except (ValidationError, ValueError):
        if not repair:
            raise
        retry: list[BaseMessage] = [
            *instructed,
            AIMessage(content=text),
            HumanMessage(
                content="That was not valid JSON for the schema. Return ONLY the "
                "JSON object, nothing else."
            ),
        ]
        return _extract_json(
            _text_of(llm.invoke(cast("LanguageModelInput", retry))), schema
        )
