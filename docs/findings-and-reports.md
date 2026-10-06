# Findings, the ledger, and reports

## The ledger

The harness persists to a per-engagement SQLite **ledger**
([src/skuggi/persistence/ledger.py](../src/skuggi/persistence/ledger.py),
`<engagement root>/ledger.db`; schema in
[ledger_schema.py](../src/skuggi/persistence/ledger_schema.py) +
[ledger_ddl.py](../src/skuggi/persistence/ledger_ddl.py)), separate from the
LangGraph checkpointer. It keeps two logs, deliberately apart:

- **The engagement timeline** — an `events` spine records, in order, every operator
  prompt, agent response, command and finding, with timestamps; `commands` and
  `findings` (plus `finding_refs`/`finding_evidence`, `coverage`, `credentials`,
  `footholds`, `loot`, `notes`) hold the detail. A command links back to the prompt
  that drove it and a finding to its source command, so a finding is traceable
  prompt → command → finding. Free-typed shell commands are captured here too
  (status `passthrough`). Replaying the events reconstructs the session (`replay`;
  `replay list` enumerates sessions).
- **The harness-interaction audit** — the `audit` table logs control verbs, filtered
  CLI noise, and the private `review` critique. It is never part of a client-facing
  report.

### Tamper-evidence

The timeline is **hash-chained**. Each insert into `commands` / `events` / `audit`
(the full, insert-only row) and `findings` (its immutable substance only) is linked
into a per-table, per-session HMAC chain — `row_hmac = HMAC(key, prev_hash ||
canonical)` — under a per-session key, so a later edit, reorder, deletion or
truncation is detectable by re-walking the chain
([integrity.py](../src/skuggi/persistence/integrity.py),
[custody.py](../src/skuggi/persistence/custody.py)). `show integrity` verifies both
the timeline and the forensics custody chains. A finding's review/rescore fields
(`status`/`severity`/environmental score) are deliberately **not** chained, because
the review lifecycle mutates them in place by design.

## Findings and the review lifecycle

`add finding <severity|CVSS> <title>` records a finding by hand; the agent records
its own. Every finding — the agent's and the operator's — is born `draft` and
carries an `author` and a `status`. **Only approved findings reach a report.**
Review with `show findings` (the listing shows author and status), then `findings
approve <id>` or `findings reject <id> <reason>`. A rejected finding's reason is fed
back to the agent so it stops re-asserting it.

## Deterministic CVSS and framework classification

Findings are **scored, not guessed.** The agent proposes a CVSS v3.1 *vector* (it
assesses the metrics); [skuggi.frameworks.cvss](../src/skuggi/frameworks/cvss.py)
computes the base/temporal/environmental score deterministically — no model does the
arithmetic, and the stored `(version, vector)` reconstructs every number on its own.
Each finding can also carry classification IDs from the engagement's chosen
**taxonomies** — OWASP WSTG and MITRE ATT&CK ids, resolved to titles and links from a
vendored, version-pinned snapshot
([src/skuggi/frameworks/data/](../src/skuggi/frameworks/data/)) refreshed only by a
maintainer (`make frameworks`), so lookups stay offline and cannot drift.

Each engagement selects a driving **methodology** (built-in phases, PTES, or ATT&CK
adversary-emulation) and the classification **taxonomies** to tag with. See
[audit-llm-vs-mechanism.md](audit-llm-vs-mechanism.md) for why scoring and
classification moved from the LLM to deterministic code, and why ATT&CK is never
forced.

**Threat model.** An optional CVSS Environmental threat model (CR/IR/AR) tailors
scores to the asset. It can be set up front in the scope or during the engagement
with `engagement threat-model <conf> <int> <avail> [| note]` (the agent advises; the
operator applies). Each change is versioned (`threat_model_versions`) and logged;
findings scored under an earlier version are flagged ⚠ outdated in the listing, and
`findings rescore [all|<id>]` refreshes them from their stored base vector — recorded
scores change only on that explicit action.

## Reports

`report` writes a Markdown report into the workspace's `reports/` with the scope,
approved findings grouped by severity, and the timestamped command log
([reports.py](../src/skuggi/persistence/reports.py)). `report engagement` writes the
cumulative engagement report; `report note <text>` adds a line to the engagement's
`reports/CHANGELOG.md`.

**Revisions.** Reports are timestamped and never overwritten; each `report` is a new
revision that cites the previous one and writes a unified `.diff` beside it (the
revision notes).

### PDF reports

Markdown is the canonical artifact; a styled, client-ready PDF is derived from it.
`report pdf` writes a `.pdf` next to the `.md`, and the standalone `skuggi-pdf`
renders any Markdown file (a report, or anything under `docs/`):

```sh
skuggi-pdf <engagement root>/reports/<file>.md      # -> <file>.pdf
skuggi-pdf docs/architecture.md -o arch.pdf --html  # also emit the HTML
make pdf IN=docs/architecture.md
```

The pipeline is `Markdown -> HTML -> PDF`
([pdf.py](../src/skuggi/persistence/pdf.py)): markdown-it-py parses, Pygments
highlights fenced code, a Jinja2 shell wraps it in the print stylesheet
([report.css](../src/skuggi/templates/report.css)), and WeasyPrint paints the PDF.
Styling is pure CSS — edit `report.css` to restyle every report — and the
severity/method colours come from
[src/skuggi/common/palette.py](../src/skuggi/common/palette.py), the same source the
terminal uses. It needs the optional `pdf` dependency group (installed by `make
install`) and WeasyPrint's native Pango library:

```sh
brew install pango            # macOS
# apt install libpango-1.0-0 libpangoft2-1.0-0   # Debian/Ubuntu
uv sync --group pdf           # if you skipped `make install`
```

## The engagement dashboard

`visualize` (standalone `skuggi-visualize`) builds a single self-contained,
interactive HTML dashboard of the whole engagement — the scope, the findings by
severity, the command timeline and coverage — for an at-a-glance view alongside the
Markdown/PDF report.
