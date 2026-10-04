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
  request-assembly + structured-`ask` egress seam, reused by the OSINT graph so it
  never imports the turn graph.
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
- **`config/`** `config.py` (typed `Settings`, no import-time singleton) +
  `configs.py` (JSON loaders). **`engagement/`** the scope boundary + workspace,
  plus `osint_guard.py` (the OSINT subject/source guard).
- **`persistence/`** ledger, checkpointer (`memory.py`), preferences, FAISS
  (`vectorstore.py`), transcript, reports/pdf. **`providers/`** the LLM factory
  and codex OAuth. **`tooling/`** registry, host probe, doctor.
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
