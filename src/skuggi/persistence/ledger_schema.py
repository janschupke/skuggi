"""The ledger's data definitions: table DDL, migrations, row types, vocabulary.

Split out of ``ledger.py`` because these are pure declarations with no dependency
on the ``Ledger`` class or a live sqlite connection -- they change for a different
reason (schema evolution) than the query behaviour does, and keeping them separate
lets a light consumer (``visualize``, ``presenters``) import a row type or a status
constant without pulling in sqlite/threading.

The status/kind/author vocabularies are ``StrEnum``s so the one spelling lives here
and ``ledger``/``dispatch``/``visualize`` stop re-typing the bare strings. Each
member's value is the string stored in the DB, so a row's plain-text ``status``
compares equal to the enum and an enum passes anywhere a column string is expected.
The DDL ``DEFAULT`` clauses below stay literal (they are raw SQL) but mirror these.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import StrEnum

from skuggi.frameworks import cvss, registry


def effective_score(
    vector: str | None, env_metrics: dict[str, str] | None
) -> cvss.Score | None:
    """Score ``vector`` with the threat-model env overlay applied (not baked in).

    A pure CVSS helper with no ``Ledger``/connection dependency, so it lives here
    beside the row types the ledger builds from a score rather than in ``ledger``.
    """
    if not vector:
        return None
    effective = cvss.merged(vector, env_metrics) if env_metrics else vector
    return cvss.score(effective)


class CommandStatus(StrEnum):
    """How a recorded command relates to execution."""

    PROPOSED = "proposed"
    BLOCKED = "blocked"
    EXECUTED = "executed"
    PASSTHROUGH = "passthrough"


class FindingStatus(StrEnum):
    """A finding's review lifecycle; only ``APPROVED`` reaches a report."""

    DRAFT = "draft"
    APPROVED = "approved"
    REJECTED = "rejected"


class FindingAuthor(StrEnum):
    """Who recorded a finding."""

    AGENT = "agent"
    OPERATOR = "operator"


class EventKind(StrEnum):
    """The kind of a timeline event (the ordered session spine)."""

    PROMPT = "prompt"
    RESPONSE = "response"
    COMMAND = "command"
    FINDING = "finding"


class AuditKind(StrEnum):
    """The channel of a harness-interaction audit entry."""

    CONTROL = "control"
    CLI = "cli"
    REVIEW = "review"


# Columns added to `commands` after the initial release; each is applied to an
# already-created table with ADD COLUMN when missing (a fresh DB gets them from
# the schema above). Kept plain (no REFERENCES) so ADD COLUMN is always legal.
_COMMAND_MIGRATIONS = (
    ("turn_event_id", "INTEGER"),
    ("risk_tier", "TEXT NOT NULL DEFAULT ''"),
    ("authority", "TEXT NOT NULL DEFAULT ''"),
)

# Chain-of-custody columns added to an older case DB (audit E20/E21).
_EVIDENCE_MIGRATIONS = (
    ("prev_hash", "TEXT NOT NULL DEFAULT ''"),
    ("row_hmac", "TEXT NOT NULL DEFAULT ''"),
)
_PROCEDURE_MIGRATIONS = (
    ("examiner", "TEXT NOT NULL DEFAULT ''"),
    ("tool_version", "TEXT NOT NULL DEFAULT ''"),
    ("prev_hash", "TEXT NOT NULL DEFAULT ''"),
    ("row_hmac", "TEXT NOT NULL DEFAULT ''"),
)

# Columns added to `findings` for CVSS scoring; applied to an older DB with ADD
# COLUMN when missing (a fresh DB gets them from the schema). All nullable, since a
# pre-existing finding (or an info finding) has no vector. `finding_refs` is a new
# table, so it is created by the IF NOT EXISTS schema and needs no migration here.
_FINDING_MIGRATIONS = (
    ("cvss_version", "TEXT"),
    ("cvss_vector", "TEXT"),
    ("cvss_base", "REAL"),
    ("cvss_temporal", "REAL"),
    ("cvss_environmental", "REAL"),
    ("cvss_score", "REAL"),
    ("cvss_severity", "TEXT"),
    ("author", "TEXT NOT NULL DEFAULT 'agent'"),
    ("status", "TEXT NOT NULL DEFAULT 'draft'"),
    ("review_reason", "TEXT NOT NULL DEFAULT ''"),
    ("reviewed_at", "TEXT"),
    ("cvss_tm_version", "INTEGER"),
    ("cvss_scored_at", "TEXT"),
    ("impact", "TEXT NOT NULL DEFAULT ''"),
    ("remediation", "TEXT NOT NULL DEFAULT ''"),
    ("affected_host", "TEXT NOT NULL DEFAULT ''"),
    ("affected_port", "TEXT NOT NULL DEFAULT ''"),
    ("affected_url", "TEXT NOT NULL DEFAULT ''"),
    ("affected_param", "TEXT NOT NULL DEFAULT ''"),
)


@dataclass(frozen=True, slots=True)
class SessionRow:
    """One engagement session."""

    session_id: str
    engagement_name: str
    mode: str
    started_at: str


@dataclass(frozen=True, slots=True)
class CommandRow:
    """One recorded command (proposed, blocked or executed)."""

    id: int
    session_id: str
    thread_id: str
    command: str
    binary: str
    method: str | None
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    reason: str
    started_at: str
    finished_at: str | None
    turn_event_id: int | None
    # Audit completeness: the deterministic risk tier the command was evaluated
    # at, and who authorized it running -- ``autonomous`` (auto-ran under the
    # ceiling), ``operator`` (operator-approved), ``passthrough`` (operator typed
    # it in their own shell), or ``""`` for a blocked/proposed row that never ran.
    # The trail can then answer "under what authority did this run" without
    # re-deriving the tier.
    risk_tier: str = ""
    authority: str = ""


@dataclass(frozen=True, slots=True)
class FindingRow:
    """One finding, linked to its session and (optionally) source command.

    The ``cvss_*`` fields are populated when the finding carries a CVSS v3.1 vector
    (``cvss_vector`` + ``cvss_version`` reconstruct every score); they are ``None``
    for an info/manual finding scored only by ``severity``.

    Model-facing boundary: storing a finding raw is fine (this row is the record
    behind the report), but reaching the model is not. ``evidence`` is the raw
    proof -- a captured response, a credential dump -- and is *never* put into a
    request: it is absent from ``FindingBrief`` (``executor._finding_briefs``,
    which also redacts the title) and from ``transcript._finding_block``. ``title``
    and ``description`` do reach the model (brief title; review transcript), so both
    are passed through redaction on those paths. Keep ``evidence`` out of any new
    model-facing projection.
    """

    id: int
    session_id: str
    command_id: int | None
    title: str
    severity: str
    description: str
    evidence: str
    cvss_version: str | None
    cvss_vector: str | None
    cvss_base: float | None
    cvss_temporal: float | None
    cvss_environmental: float | None
    cvss_score: float | None
    cvss_severity: str | None
    author: str
    status: str
    review_reason: str
    reviewed_at: str | None
    cvss_tm_version: int | None
    cvss_scored_at: str | None
    impact: str
    remediation: str
    affected_host: str
    affected_port: str
    affected_url: str
    affected_param: str
    created_at: str


@dataclass(frozen=True, slots=True)
class FindingRefRow:
    """One framework citation attached to a finding (a WSTG/ATT&CK/PTES id + link)."""

    id: int
    finding_id: int
    framework: str
    ref_id: str
    title: str
    url: str
    is_primary: int


@dataclass(frozen=True, slots=True)
class FindingEvidenceRow:
    """One structured evidence item attached to a finding (audit E4).

    ``kind`` is request/response/screenshot/image/log. Text proof (a request,
    response or log excerpt) lives in ``content``; a screenshot/image is a
    workspace-confined ``media_path`` the report embeds. Evidence is raw proof and
    MUST NOT reach the model -- keep it out of any model-facing projection, like
    ``FindingRow.evidence``.
    """

    id: int
    finding_id: int
    kind: str
    content: str
    media_path: str
    created_at: str


@dataclass(frozen=True, slots=True)
class CredentialRow:
    """One captured credential; the secret lives in the vault, not here (E8/E9)."""

    id: int
    session_id: str
    host: str
    service: str
    username: str
    secret_ref: str
    source: str
    validated: int
    created_at: str


@dataclass(frozen=True, slots=True)
class FootholdRow:
    """A compromised/jump host registered as a runtime execution channel (pivot).

    ``secret_ref`` is a vault placeholder (never plaintext); ``reachable_networks``
    and ``reachable_hosts`` are comma-separated lists naming what this foothold can
    reach, which the execution router uses to send a command through it.
    """

    id: int
    session_id: str
    host: str
    transport: str
    template: str
    secret_ref: str
    reachable_networks: str
    reachable_hosts: str
    created_at: str


@dataclass(frozen=True, slots=True)
class LootRow:
    """One captured loot item -- structured, recallable, secret-safe.

    The looser sibling of a credential: anything worth keeping that is not a clean
    host/service/user credential (a token, a hash, a key, a lifted file, a config
    snippet). ``label`` is the redacted description (a secret in it is vaulted and
    appears as a ``«KIND:id»`` placeholder); ``secret_ref`` is the vault placeholder
    when the item itself is a single secret. Plaintext is never stored here.
    """

    id: int
    session_id: str
    kind: str
    host: str
    label: str
    secret_ref: str
    source: str
    created_at: str


@dataclass(frozen=True, slots=True)
class NoteRow:
    """One operator/agent note -- a structured, recallable observation.

    ``text`` is the redacted note body (any secret in it is vaulted to a
    ``«KIND:id»`` placeholder before storage); ``subject`` is a short topic and
    ``host`` the asset it concerns, if any. Plaintext secrets are never stored here.
    """

    id: int
    session_id: str
    subject: str
    host: str
    text: str
    source: str
    created_at: str


@dataclass(frozen=True, slots=True)
class CoverageRow:
    """One exercised/skipped methodology id for a session (audit E7)."""

    id: int
    session_id: str
    framework: str
    ref_id: str
    status: str
    note: str
    created_at: str


@dataclass(frozen=True, slots=True)
class FindingEvidenceInput:
    """A structured evidence item to attach to a finding (request/response/image)."""

    kind: str
    content: str = ""
    media_path: str = ""


@dataclass(frozen=True, slots=True)
class FindingRefInput:
    """A framework id to attach to a finding; the ledger resolves its title + link."""

    framework: str
    ref_id: str
    is_primary: bool = False


@dataclass(frozen=True, slots=True)
class ThreatModelVersionRow:
    """One recorded threat-model version -- CVSS env scores are tagged by it."""

    version: int
    snapshot: str
    note: str
    created_at: str


@dataclass(frozen=True, slots=True)
class EventRow:
    """One entry on the engagement timeline (the ordered session spine).

    ``kind`` is ``prompt`` / ``response`` (``text`` holds the operator directive
    or agent answer) or ``command`` / ``finding`` (``ref_id`` points at the
    ``commands`` / ``findings`` row carrying the detail).
    """

    id: int
    session_id: str
    thread_id: str | None
    kind: str
    ref_id: int | None
    text: str
    created_at: str


@dataclass(frozen=True, slots=True)
class AuditRow:
    """One harness-interaction record (a control verb, CLI noise, or a review)."""

    id: int
    session_id: str
    kind: str
    verb: str
    detail: str
    created_at: str


@dataclass(frozen=True, slots=True)
class EvidenceRow:
    """One acquired evidence artifact, pinned by its content hash (forensics)."""

    id: int
    session_id: str
    source_path: str
    sha256: str
    size: int
    media_type: str
    acquired_at: str
    note: str
    prev_hash: str = ""
    row_hmac: str = ""


@dataclass(frozen=True, slots=True)
class ProcedureRow:
    """One examination step in the chain-of-custody procedure log (forensics)."""

    id: int
    session_id: str
    step: int
    operation: str
    actor: str
    argv: str
    input_sha256: str
    output_digest: str
    created_at: str
    note: str
    examiner: str = ""
    tool_version: str = ""
    prev_hash: str = ""
    row_hmac: str = ""


@dataclass(frozen=True, slots=True)
class ThreadSummary:
    """A conversation thread, summarised for ``show threads`` (so it is actionable).

    ``first_prompt`` is the thread's opening operator directive (a label to
    recognise it by); ``turns`` counts prompts; ``last_activity`` is the most
    recent event's timestamp. Derived from the ``events`` table -- the langgraph
    checkpointer stores only the id.
    """

    thread_id: str
    turns: int
    first_prompt: str
    last_activity: str


# Column lists derived from the row dataclasses, so SELECT order (and the
# positional Row(*row) unpacking) can never drift from the field order. The
# INSERT lists drop the autoincrement id.
_SESSION_COLS = tuple(f.name for f in fields(SessionRow))
_COMMAND_COLS = tuple(f.name for f in fields(CommandRow))
_FINDING_COLS = tuple(f.name for f in fields(FindingRow))
_FINDING_REF_COLS = tuple(f.name for f in fields(FindingRefRow))
_FINDING_EVIDENCE_COLS = tuple(f.name for f in fields(FindingEvidenceRow))
_COVERAGE_COLS = tuple(f.name for f in fields(CoverageRow))
_CREDENTIAL_COLS = tuple(f.name for f in fields(CredentialRow))
_FOOTHOLD_COLS = tuple(f.name for f in fields(FootholdRow))
_LOOT_COLS = tuple(f.name for f in fields(LootRow))
_NOTE_COLS = tuple(f.name for f in fields(NoteRow))
_TM_VERSION_COLS = tuple(f.name for f in fields(ThreatModelVersionRow))
_EVENT_COLS = tuple(f.name for f in fields(EventRow))
_AUDIT_COLS = tuple(f.name for f in fields(AuditRow))
_EVIDENCE_COLS = tuple(f.name for f in fields(EvidenceRow))
_PROCEDURE_COLS = tuple(f.name for f in fields(ProcedureRow))


def _insert_sql(table: str, columns: tuple[str, ...]) -> str:
    """An INSERT statement for `columns` with positional placeholders."""
    placeholders = ", ".join("?" * len(columns))
    cols = ", ".join(columns)
    return f"INSERT INTO {table} ({cols}) VALUES ({placeholders})"  # noqa: S608


def _select_sql(table: str, columns: tuple[str, ...], clause: str) -> str:
    """A SELECT of `columns` from `table` with a trailing WHERE/ORDER clause."""
    cols = ", ".join(columns)
    return f"SELECT {cols} FROM {table} {clause}"  # noqa: S608


def _ref_display(framework: str, ref_id: str) -> tuple[str, str]:
    """The (title, url) stored for a finding ref.

    A vendored framework (WSTG/ATT&CK/PTES) resolves a title + canonical link; a
    CVE or CWE has no vendored catalogue here, so the canonical public URL is
    synthesised (NVD / MITRE) and the title left to the report to format.
    """
    if framework in registry.FRAMEWORKS:
        resolved = registry.resolve(framework, ref_id)
        return (resolved.title, resolved.url) if resolved else ("", "")
    if framework == "cve":
        return ("", f"https://nvd.nist.gov/vuln/detail/{ref_id.upper()}")
    if framework == "cwe":
        number = ref_id.upper().removeprefix("CWE-")
        return ("", f"https://cwe.mitre.org/data/definitions/{number}.html")
    return ("", "")


def dedup_findings(findings: list[FindingRow]) -> list[FindingRow]:
    """Drop duplicate findings by (title, affected asset, cvss vector) -- audit E5.

    The engagement-level report aggregates approved findings from every session; the
    same issue proven twice should appear once. The first occurrence (callers pass
    rows in started-at order) wins, so the original instance is kept.
    """
    seen: set[tuple[str, str, str, str, str, str]] = set()
    deduped: list[FindingRow] = []
    for f in findings:
        key = (
            f.title.strip().lower(),
            f.affected_host,
            f.affected_port,
            f.affected_url,
            f.affected_param,
            f.cvss_vector or "",
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped
