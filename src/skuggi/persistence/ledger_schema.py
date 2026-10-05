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

from skuggi.frameworks import registry


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


_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    engagement_name TEXT NOT NULL,
    mode            TEXT NOT NULL,
    started_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    thread_id   TEXT NOT NULL,
    command     TEXT NOT NULL,
    binary      TEXT NOT NULL,
    method      TEXT,
    status      TEXT NOT NULL,
    exit_code   INTEGER,
    stdout      TEXT NOT NULL DEFAULT '',
    stderr      TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT '',
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    turn_event_id INTEGER            -- -> events(id): the prompt that drove it
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    command_id  INTEGER REFERENCES commands(id),
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence    TEXT NOT NULL DEFAULT '',
    -- Client-report material (audit E1/E2): the impact, the remediation, and the
    -- affected asset the finding was proven on (host/port/url/parameter).
    impact         TEXT NOT NULL DEFAULT '',
    remediation    TEXT NOT NULL DEFAULT '',
    affected_host  TEXT NOT NULL DEFAULT '',
    affected_port  TEXT NOT NULL DEFAULT '',
    affected_url   TEXT NOT NULL DEFAULT '',
    affected_param TEXT NOT NULL DEFAULT '',
    -- CVSS v3.1, stored complete so a score reconstructs from (version, vector)
    -- alone -- no agent turn, no network. cvss_severity is the band derived from
    -- the vector; `severity` above stays the display/report value (derived from
    -- cvss_severity when a vector is present, else set directly for info findings).
    cvss_version       TEXT,
    cvss_vector        TEXT,
    cvss_base          REAL,
    cvss_temporal      REAL,
    cvss_environmental REAL,
    cvss_score         REAL,
    cvss_severity      TEXT,
    -- Review lifecycle. Every finding is born 'draft'; only 'approved' reaches a
    -- report. ``author`` is who recorded it ('agent' | 'operator'); a rejection
    -- carries its ``review_reason`` (also fed back to the agent so it stops
    -- re-asserting it), and ``reviewed_at`` stamps the last status change.
    author       TEXT NOT NULL DEFAULT 'agent',
    status       TEXT NOT NULL DEFAULT 'draft',
    review_reason TEXT NOT NULL DEFAULT '',
    reviewed_at  TEXT,
    -- Score provenance for the freeze/flag/rescore flow: which threat-model version
    -- the environmental score was computed under, and when. A finding is "outdated"
    -- when this version != the engagement's current threat-model version.
    cvss_tm_version INTEGER,
    cvss_scored_at  TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS threat_model_versions (
    version    INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot   TEXT NOT NULL,       -- the ThreatModel as JSON, or '' for none
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_refs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES findings(id),
    framework   TEXT NOT NULL,       -- wstg | attack | ptes
    ref_id      TEXT NOT NULL,       -- e.g. WSTG-ATHN-01, T1110, PTES-05
    title       TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL DEFAULT '',
    is_primary  INTEGER NOT NULL DEFAULT 0   -- the driver framework's id
);
CREATE TABLE IF NOT EXISTS finding_evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES findings(id),
    kind        TEXT NOT NULL,       -- request | response | screenshot | image | log
    content     TEXT NOT NULL DEFAULT '',  -- inline text (request/response/log)
    media_path  TEXT NOT NULL DEFAULT '',  -- workspace-confined path (screenshot/image)
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS coverage (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    framework   TEXT NOT NULL,       -- wstg | attack | ptes
    ref_id      TEXT NOT NULL,       -- e.g. WSTG-ATHN-01, T1110
    status      TEXT NOT NULL DEFAULT 'exercised',  -- exercised | skipped | n/a
    note        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    UNIQUE(session_id, framework, ref_id)
);
CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    host        TEXT NOT NULL DEFAULT '',
    service     TEXT NOT NULL DEFAULT '',
    username    TEXT NOT NULL DEFAULT '',
    secret_ref  TEXT NOT NULL DEFAULT '',   -- a vault placeholder, never plaintext
    source      TEXT NOT NULL DEFAULT '',
    validated   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    thread_id   TEXT,
    kind        TEXT NOT NULL,       -- prompt | response | command | finding
    ref_id      INTEGER,             -- -> commands(id) / findings(id) by kind
    text        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    kind        TEXT NOT NULL,       -- control | cli | review
    verb        TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
-- Forensics chain-of-custody. Only the forensics mode writes these (the `mode`
-- column on `sessions` is the discriminator); an offensive engagement ledger just
-- carries them empty. `evidence` is the acquisition record -- one row per evidence
-- artifact, pinned by its sha256; `procedure` is the ordered operation log -- one
-- row per examination step, citing the evidence it touched.
CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    source_path TEXT NOT NULL,       -- path, relative to the case evidence dir
    sha256      TEXT NOT NULL,       -- content hash at acquisition (integrity pin)
    size        INTEGER NOT NULL,
    media_type  TEXT NOT NULL DEFAULT '',
    acquired_at TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS procedure (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL REFERENCES sessions(session_id),
    step          INTEGER NOT NULL,  -- 1-based order within the session
    operation     TEXT NOT NULL,     -- e.g. 'hash', 'strings', 'exiftool'
    actor         TEXT NOT NULL,     -- 'in-process' | 'tool'
    argv          TEXT NOT NULL DEFAULT '',  -- the exact argv for a tool op, else ''
    input_sha256  TEXT NOT NULL DEFAULT '',  -- -> evidence.sha256 it operated on
    output_digest TEXT NOT NULL DEFAULT '',  -- sha256 of the captured output
    created_at    TEXT NOT NULL,
    note          TEXT NOT NULL DEFAULT ''
);
"""

# Indexes for the hot per-session reads (audit D5): without these the command,
# finding, event and ref lookups full-scan, so their cost grows with the whole
# ledger rather than one session. Run AFTER the column migrations (so a finding
# created before the ``status`` column can be upgraded first), and idempotent.
_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_session_status ON findings(session_id, status);
CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id, id);
CREATE INDEX IF NOT EXISTS idx_events_thread ON events(thread_id);
CREATE INDEX IF NOT EXISTS idx_finding_refs_finding ON finding_refs(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding ON finding_evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_coverage_session ON coverage(session_id);
CREATE INDEX IF NOT EXISTS idx_credentials_session ON credentials(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit(session_id);
CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id);
CREATE INDEX IF NOT EXISTS idx_procedure_session ON procedure(session_id);
"""

# Columns added to `commands` after the initial release; each is applied to an
# already-created table with ADD COLUMN when missing (a fresh DB gets them from
# the schema above). Kept plain (no REFERENCES) so ADD COLUMN is always legal.
_COMMAND_MIGRATIONS = (("turn_event_id", "INTEGER"),)

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
