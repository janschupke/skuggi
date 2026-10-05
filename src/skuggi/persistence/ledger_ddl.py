"""The ledger's SQL schema: table DDL and index DDL.

Split from :mod:`skuggi.persistence.ledger_schema` (the row dataclasses, column
tuples and SQL helpers) to keep each module under the file-size cap. These two
scripts are executed idempotently on every :class:`~skuggi.persistence.ledger.Ledger`
open (``CREATE TABLE/INDEX IF NOT EXISTS``), so an existing database gains a new
table or index automatically on next open. Column additions to existing tables are
handled separately by the ``_*_MIGRATIONS`` in ``ledger_schema``.
"""

from __future__ import annotations

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
    turn_event_id INTEGER,           -- -> events(id): the prompt that drove it
    risk_tier   TEXT NOT NULL DEFAULT '',  -- deterministic tier at decision time
    authority   TEXT NOT NULL DEFAULT '',  -- autonomous | operator | passthrough
    prev_hash   TEXT NOT NULL DEFAULT '',  -- tamper-evidence chain (integrity.py)
    row_hmac    TEXT NOT NULL DEFAULT ''
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
    created_at  TEXT NOT NULL,
    prev_hash   TEXT NOT NULL DEFAULT '',  -- tamper-evidence chain (integrity.py)
    row_hmac    TEXT NOT NULL DEFAULT ''
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
-- A compromised/jump host registered as a runtime execution channel (audit: pivot).
-- Scope stays the authorization boundary; a foothold layers reachability on top: it
-- names the networks/hosts it reaches and how a command is run through it (a command
-- template for an RCE/shell, or a proxy spec for a tunnel). Any secret is a vault
-- placeholder, never plaintext -- rehydrated at exec like a credential.
CREATE TABLE IF NOT EXISTS footholds (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL REFERENCES sessions(session_id),
    host          TEXT NOT NULL,              -- the foothold host (must be in scope)
    transport     TEXT NOT NULL DEFAULT 'command',  -- command | tunnel
    template      TEXT NOT NULL DEFAULT '',   -- cmd template ({cmd}) or proxy spec
    secret_ref    TEXT NOT NULL DEFAULT '',   -- a vault placeholder, never plaintext
    reachable_networks TEXT NOT NULL DEFAULT '',  -- comma-separated CIDRs
    reachable_hosts    TEXT NOT NULL DEFAULT '',  -- comma-separated hostnames
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS loot (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    kind        TEXT NOT NULL DEFAULT '',   -- token | hash | key | file | config | ...
    host        TEXT NOT NULL DEFAULT '',   -- the asset it was lifted from
    label       TEXT NOT NULL DEFAULT '',   -- redacted description; secrets are vaulted
    secret_ref  TEXT NOT NULL DEFAULT '',   -- a vault placeholder, never plaintext
    source      TEXT NOT NULL DEFAULT '',   -- operator | agent
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    subject     TEXT NOT NULL DEFAULT '',   -- a short category/topic for the note
    host        TEXT NOT NULL DEFAULT '',   -- the asset it concerns, if any
    text        TEXT NOT NULL DEFAULT '',   -- the redacted note body
    source      TEXT NOT NULL DEFAULT '',   -- operator | agent
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    thread_id   TEXT,
    kind        TEXT NOT NULL,       -- prompt | response | command | finding
    ref_id      INTEGER,             -- -> commands(id) / findings(id) by kind
    text        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    prev_hash   TEXT NOT NULL DEFAULT '',  -- tamper-evidence chain (integrity.py)
    row_hmac    TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    kind        TEXT NOT NULL,       -- control | cli | review
    verb        TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    prev_hash   TEXT NOT NULL DEFAULT '',  -- tamper-evidence chain (integrity.py)
    row_hmac    TEXT NOT NULL DEFAULT ''
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
    note        TEXT NOT NULL DEFAULT '',
    -- Tamper-evident chain (audit E20): row_hmac = HMAC(case_key, prev_hash||row);
    -- prev_hash links to the previous evidence row's row_hmac. Empty when no case
    -- key was set (an offensive-engagement ledger never writes these rows).
    prev_hash   TEXT NOT NULL DEFAULT '',
    row_hmac    TEXT NOT NULL DEFAULT ''
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
    note          TEXT NOT NULL DEFAULT '',
    -- Provenance (audit E21): who ran the step and the tool version, for the report.
    examiner      TEXT NOT NULL DEFAULT '',
    tool_version  TEXT NOT NULL DEFAULT '',
    -- Tamper-evident chain (audit E20), as on evidence.
    prev_hash     TEXT NOT NULL DEFAULT '',
    row_hmac      TEXT NOT NULL DEFAULT ''
);
-- Chain-of-custody is append-only (audit E20): reject any UPDATE/DELETE on the
-- evidence/procedure tables at the database layer, so a row cannot be silently
-- rewritten even by a direct SQL edit (the HMAC chain would also catch it).
CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT, 'chain of custody is append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_no_delete BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'chain of custody is append-only'); END;
CREATE TRIGGER IF NOT EXISTS procedure_no_update BEFORE UPDATE ON procedure
BEGIN SELECT RAISE(ABORT, 'chain of custody is append-only'); END;
CREATE TRIGGER IF NOT EXISTS procedure_no_delete BEFORE DELETE ON procedure
BEGIN SELECT RAISE(ABORT, 'chain of custody is append-only'); END;
-- Engagement timeline is tamper-evident (audit E22): commands/events/audit are
-- insert-only, so reject any UPDATE/DELETE. findings are DELETE-only-protected --
-- their review lifecycle (set_finding_status/rescore_finding) needs in-place
-- UPDATE, and the chain commits only to a finding's immutable substance, so those
-- edits are legitimate and leave the chain intact.
CREATE TRIGGER IF NOT EXISTS commands_no_update BEFORE UPDATE ON commands
BEGIN SELECT RAISE(ABORT, 'command log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS commands_no_delete BEFORE DELETE ON commands
BEGIN SELECT RAISE(ABORT, 'command log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'event timeline is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'event timeline is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS findings_no_delete BEFORE DELETE ON findings
BEGIN SELECT RAISE(ABORT, 'findings are append-only (status changes in place)'); END;
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
CREATE INDEX IF NOT EXISTS idx_footholds_session ON footholds(session_id);
CREATE INDEX IF NOT EXISTS idx_loot_session ON loot(session_id);
CREATE INDEX IF NOT EXISTS idx_notes_session ON notes(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit(session_id);
CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id);
CREATE INDEX IF NOT EXISTS idx_procedure_session ON procedure(session_id);
"""
