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

import re
from collections.abc import Sequence
from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict, model_validator

from skuggi.common.logs import get_logger
from skuggi.common.text import join_blocks, labeled
from skuggi.frameworks import cvss, registry

log = get_logger(__name__)

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

# The frameworks a FINDING may cite. A superset of the engagement taxonomies: a
# finding can always be classified by a CVE or a CWE (the lingua franca of vuln
# reporting) and by PTES, independent of which taxonomies the engagement enabled.
RefFramework = Literal["wstg", "attack", "ptes", "cve", "cwe"]
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CWE_ID = re.compile(r"^CWE-\d+$", re.IGNORECASE)

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


class CredentialBrief(BaseModel):
    """A captured credential's nature, for a request -- never its value.

    Model-facing by construction: ``secret_ref`` is the vault ``«CRED:id»``
    placeholder, which the worker may put in a command (the executor rehydrates it
    at exec), so the agent can *use* a credential it has never seen. The plaintext
    secret is not a field here and lives only in the engagement vault.
    """

    model_config = ConfigDict(frozen=True)

    id: int
    host: str = ""
    service: str = ""
    username: str = ""
    secret_ref: str = ""
    validated: bool = False


class LootBrief(BaseModel):
    """A captured loot item's nature, for a request -- never a raw secret.

    ``label`` is already redacted (any secret appears as a ``«KIND:id»``
    placeholder); ``secret_ref`` is a vault placeholder when the item is a bare
    secret. The plaintext value is not a field here.
    """

    model_config = ConfigDict(frozen=True)

    id: int
    kind: str = ""
    host: str = ""
    label: str = ""
    secret_ref: str = ""


class NoteBrief(BaseModel):
    """An operator/agent note's nature, for a request -- body already redacted."""

    model_config = ConfigDict(frozen=True)

    id: int
    subject: str = ""
    host: str = ""
    text: str = ""


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
    credentials: tuple[CredentialBrief, ...] = ()
    loot: tuple[LootBrief, ...] = ()
    notes: tuple[NoteBrief, ...] = ()
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

    framework: RefFramework
    ref_id: str

    @model_validator(mode="after")
    def _known_id(self) -> FindingRefDraft:
        if self.framework == "cve":
            ok = bool(_CVE_ID.match(self.ref_id))
        elif self.framework == "cwe":
            ok = bool(_CWE_ID.match(self.ref_id))
        else:
            ok = registry.validate_id(self.framework, self.ref_id)
        if not ok:
            msg = f"unknown {self.framework} id: {self.ref_id!r}"
            raise ValueError(msg)
        return self


EvidenceKind = Literal["request", "response", "screenshot", "image", "log"]


class FindingEvidenceItem(BaseModel):
    """One structured proof item a worker attaches to a finding (audit E4).

    ``kind`` names what it is; a text item (request/response/log) carries its text
    in ``content``; a screenshot/image carries a workspace-relative ``media_path``
    (confined and embedded at report time, never fetched from the network). Like
    ``FindingDraft.evidence``, this is raw proof and never reaches the model.
    """

    model_config = ConfigDict(frozen=True)

    kind: EvidenceKind
    content: str = ""
    media_path: str = ""


class AffectedAsset(BaseModel):
    """Where a finding lives: the host/port/URL/parameter it was proven on.

    A finding without an affected asset is not client-actionable; every field is
    optional so an info/architectural finding can omit them, but a real
    vulnerability should name at least the host (or URL).
    """

    model_config = ConfigDict(frozen=True)

    host: str = ""
    port: str = ""
    url: str = ""
    parameter: str = ""

    def is_empty(self) -> bool:
        """Whether no locus was given (so the report omits the Affected line)."""
        return not (self.host or self.port or self.url or self.parameter)


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
    # Client-report material: the business/technical impact, how to fix it, and the
    # asset it was proven on. A model should fill these for a real vulnerability; an
    # info finding may leave them blank.
    impact: str = ""
    remediation: str = ""
    affected: AffectedAsset | None = None
    # Structured proof (request/response pairs, screenshots, logs) -- audit E4.
    evidence_items: tuple[FindingEvidenceItem, ...] = ()
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


class InstallCandidate(BaseModel):
    """One package the model picked to install a requested tool.

    Validator-free (like ``CmdProposal``): the harness re-validates every field --
    allow-listing the installer, checking the package against the search results it
    was shown (grounding), and rebuilding the argv itself -- so a stray or malicious
    value can never become an executed command. ``package`` must be copied verbatim
    from the search results, never invented.
    """

    model_config = ConfigDict(frozen=True)

    installer: str = ""  # "brew" | "brew-cask" | "apt" | "pip"
    package: str = ""
    rationale: str = ""


class InstallResearch(BaseModel):
    """The install researcher's strict output: grounded candidates, or advice.

    Empty ``candidates`` with non-empty ``advice`` means "nothing in the search
    results installs this tool -- here is what to do instead" (e.g. a manual step).
    """

    model_config = ConfigDict(frozen=True)

    candidates: tuple[InstallCandidate, ...] = ()
    advice: str = ""


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
        labeled("Conversation so far", ctx.history),
        labeled("Prior findings", _findings_block(ctx.findings)),
        labeled("Captured credentials", _credentials_block(ctx.credentials)),
        labeled("Captured loot", _loot_block(ctx.loot)),
        labeled("Notes", _notes_block(ctx.notes)),
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
