# Architecture

skuggi is a locally-hosted pentest-agent harness: a LangGraph
planner→worker→critic loop with two front-ends over one headless core. Deep
reference: [docs/architecture.md](../../docs/architecture.md).

## The shape

- **`agent/`** — the agent. `core.py` (`AgentCore`) owns a session (scope, tool
  registry, ledger, checkpointer, compiled graph) and streams `TurnEvent`s; it
  holds no rendering. `graph.py` is the planner→retriever→worker↔executor→critic
  graph; `state.py` its channels; `protocol.py`/`prompts.py` the structured
  exchange (see [protocol.md](protocol.md)). `requests.py` is the shared
  request-assembly + structured-`ask` egress seam, reused by the OSINT and research
  graphs so neither imports the turn graph.
- **`frontend/`** — the two renderers and dispatch. `tui.py` (Rich REPL),
  `daemon.py` + `shell.py` (wrapped-shell daemon), `client.py`. Dispatch is
  **verb-first** and every known verb comes from the one registry `verbs.py` —
  never hard-code a verb list in a front-end.
- **`osint/`** — the agentic OSINT reconnaissance loop: a second compiled graph
  (planner→collector↔scheduler→verifier→re-plan|respond) with its own `deps`,
  `state`, `prompts`, `scheduler` (pure DAG logic), `nodes`, `graph`, `runner`,
  `schema`, `store`, and a pluggable `collectors/` registry (HTTP + optional
  Playwright/Apify). It reuses the request seam (`agent/requests.py`) and the
  finding/report path, and imports *down* into `agent`/`engagement` — never the
  reverse. Driven by `AgentCore.osint_turn`; scoped by `engagement/osint_guard.py`.
- **`intel/`** — the shared core both intelligence loops build on: `schema`
  (`IntelItem`/`IntelResult`/`CollectTask`), `http` (the injectable fetch/collect-
  context seam), `scheduler` (pure dependency-DAG logic), `store` (the confined,
  redacted JSON writer), and `collectors/` (the `Collector` protocol + the two
  source handlers both loops share — web search and GitHub). A leaf under the two
  loops; it imports only `engagement`/`security`, never `osint`/`research`.
- **`research/`** — the agentic public-source research loop: a third compiled
  graph (planner→collector↔scheduler→verifier→re-plan|respond) built on `intel/`,
  with its own `deps`, `state`, `prompts`, `scope` (public-sources-only guard),
  `nodes`, `graph`, `runner`, `schema`, `report`, and a `collectors/` registry
  (CVE/Exploit-DB/versions + optional local searchsploit/metasploit). Engagement-
  *independent* and report-only (no ledger findings): it writes a structured
  briefing to the engagement's `research/` dir, or `./research` when none is
  loaded. Driven by `AgentCore.research_turn`.
- **`forensics/`** — the read-only, engagement-free forensics loop: a linear
  `collect→examine→respond` graph (collection is deterministic, so no planner). Its
  `analyzers/` are pure-Python, subprocess-free evidence transforms (hashes,
  strings, hexdump, entropy, magic, encoding, logparse, keyed-decrypt, OCR); `scope`
  is the built-in read-only tool allow-list + evidence-dir confinement (there is NO
  operator-editable scope). It is bound to a **case** (`engagement/case.py` +
  `agent/case_manager.py`), not an engagement, and records the chain of custody
  (evidence + procedure) and severity-only findings to the case's OWN ledger
  (`case.db`), then writes a cited Markdown/PDF report. The examiner's findings are
  grounded deterministically — an unresolved `evidence_ref` is forced speculative.
  Driven by `AgentCore.forensics_turn`; the `forensics` verb is available only in
  `forensics` mode. AI vision is the gated `agent/vision.py` seam (multimodal
  providers only), always marked speculative.
- **`config/`** `config.py` (typed `Settings`, no import-time singleton) +
  `configs.py` (JSON loaders). **`engagement/`** the scope boundary + workspace,
  plus `osint_guard.py` (the OSINT subject/source guard) and `case.py` (the
  forensics case metadata/probe/scaffold).
- **`persistence/`** ledger (+ `ledger_schema`/`ledger_ddl`), `custody`+`integrity`
  (hash-chained tamper-evidence), `review`, checkpointer (`memory.py`), preferences,
  FAISS (`vectorstore.py`), `documents`, transcript, `session_summary`, reports/pdf,
  `visualize`. **`providers/`** the LLM factory and codex/claude-cli adapters.
  **`tooling/`** registry, host probe, doctor.
- **`security/`** the deterministic data-plane boundary (`redaction`, `vault`,
  `policy`, `tripwire`, `boundaries`). **`frameworks/`** offline CVSS +
  WSTG/ATT&CK/PTES classification (`cvss`, `registry`, vendored `data/`).
  **`eval/`** the offline + provider eval tiers (`skuggi-eval`).
- **`common/`** cross-cutting leaves only (`paths`, `home`, `text`, `palette`,
  `execution`, `logs`, `clock`, `jwt`). **`install/`** first-run plumbing
  (`init`, `boot`, `envfile`, `ingest`, `update`).

## Rules

- **The import graph is a DAG; keep it one.** Lower layers never import higher.
  `common/` is leaf-only — never make it import a feature package (that is why
  `finding_line`, which renders a persistence row, stays in `persistence/`).
- **Keep lazy imports lazy.** `frontend.shell`→`daemon`/`core`/`boot`,
  `agent.core`→`providers.codex_login`, `providers.providers`→`codex_chat`,
  `persistence.reports`→`pdf`, `install.boot`→`codex_chat` are function-local on
  purpose — they break the doctor/shell/daemon triangle or keep a heavy SDK /
  optional native dep out of the core import graph. Promoting one re-creates a
  cycle or a boot cost.
- **One source of truth per concern.** Prompts live in `agent/prompts.py`; the
  verb set in `frontend/verbs.py`; timestamps in `common/clock.now_iso`; path
  creation in `common/paths`. Reach for the existing one before adding another.
- Entry points, `[tool.ruff.lint.per-file-ignores]` and the doc source links all
  hard-code module paths — **moving a module is a repo-wide sweep**, gated by
  `make check`.
