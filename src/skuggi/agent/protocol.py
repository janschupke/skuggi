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
from pydantic import BaseModel, ConfigDict, ValidationError

from skuggi.common.text import join_blocks, labeled

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


class FindingBrief(BaseModel):
    """A prior finding, condensed for a request. Full text lives in the ledger."""

    model_config = ConfigDict(frozen=True)

    id: int
    severity: str
    title: str
    command_id: int | None = None


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
    history: str = ""
    preferences: str = ""
    retrieved_context: str = ""
    findings: tuple[FindingBrief, ...] = ()
    recent_commands: tuple[CommandBrief, ...] = ()
    plan: tuple[str, ...] = ()  # planner output, for the worker
    prior_critique: str = ""  # critic output, for the planner's next pass
    draft: str = ""  # worker output, for the critic


# --- response side ----------------------------------------------------------


class PlannerResponse(BaseModel):
    """The planner's strict output: a plan plus a phase judgement."""

    model_config = ConfigDict(frozen=True)

    phase: Phase
    advance_to: Phase | None = None
    steps: tuple[str, ...] = ()
    rationale: str = ""


class FindingDraft(BaseModel):
    """A finding the worker wants recorded, before it reaches the ledger."""

    model_config = ConfigDict(frozen=True)

    title: str
    severity: Severity
    description: str
    evidence: str = ""


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


class MemoryExtraction(BaseModel):
    """The automatic-memory extractor's strict output: durable directives only."""

    model_config = ConfigDict(frozen=True)

    directives: tuple[str, ...] = ()


# --- rendering --------------------------------------------------------------


def _findings_block(findings: Sequence[FindingBrief]) -> str:
    return "\n".join(
        f"[{f.id}] {f.severity.upper()}: {f.title}"
        + (f" (cmd:{f.command_id})" if f.command_id is not None else "")
        for f in findings
    )


def _commands_block(commands: Sequence[CommandBrief]) -> str:
    lines = []
    for c in commands:
        code = "" if c.exit_code is None else f" exit={c.exit_code}"
        tail = f" -- {c.summary}" if c.summary else ""
        lines.append(f"[{c.id}] {c.status}{code}: {c.command}{tail}")
    return "\n".join(lines)


def _engagement_block(brief: EngagementBrief) -> str:
    return (
        f"name: {brief.name}\n"
        f"stance: {brief.stance}\n"
        f"autonomous: {brief.autonomous}\n"
        f"networks: {', '.join(brief.networks) or '(none)'}\n"
        f"hosts: {', '.join(brief.hosts) or '(none)'}\n"
        f"allowed tools: {', '.join(brief.allowed_tools) or '(none)'}\n"
        f"allowed methods: {', '.join(brief.allowed_methods) or '(none)'}"
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
        labeled("Operator preferences", ctx.preferences),
        labeled("Conversation so far", ctx.history),
        labeled("Prior findings", _findings_block(ctx.findings)),
        labeled("Recent commands", _commands_block(ctx.recent_commands)),
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
        recorded = "\n".join(
            f"- {f.severity.upper()}: {f.title}" for f in resp.findings
        )
        blocks.append(labeled("Findings", recorded))
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
    """The plain text of a chat reply, however the provider shaped it."""
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
