# skuggi — Codex / Agent Instructions

This file is a pointer. All detailed rules and commands live in [`.ai/`](.ai/) — the single source of truth. It mirrors [`CLAUDE.md`](CLAUDE.md); keep them in sync.

## Project

**skuggi** is a locally-hosted **pentesting agent harness**: a LangGraph
planner→worker→critic loop with a headless `AgentCore` and two front-ends (a
Rich REPL and a wrapped-shell daemon). Python ≥3.12, uv, hatchling, `src/`
layout. The operator drives an authorized engagement; the agent advises,
proposes shell commands checked against a strict engagement boundary, or
summarizes, and every prompt/command/finding is written to a per-engagement
SQLite ledger.

### Source layout (`src/skuggi/`)

- `agent/` — `core` (the hub), `graph`, `state`, `protocol`, `prompts`, `modes`
  (pentest/redteam/blueteam/**forensics**), `requests` (the shared request/`ask`
  seam), `executor`, `vision` (the gated multimodal seam), `engagement_manager` +
  `case_manager` (the two context planes)
- `intel/` — shared core for both intelligence loops: `schema`, `http`,
  `scheduler` (DAG), `store`, `collectors/` (the `Collector` protocol + shared
  web-search/GitHub handlers)
- `osint/` — the agentic OSINT loop (its own graph, built on `intel/`): `deps`,
  `state`, `prompts`, `scheduler`, `nodes`, `graph`, `runner`, `schema`, `store`,
  `collectors/`
- `research/` — the agentic public-source research loop (its own graph, built on
  `intel/`): `deps`, `state`, `prompts`, `scope`, `nodes`, `graph`, `runner`,
  `schema`, `report`, `collectors/` (CVE/Exploit-DB/versions + local tools)
- `forensics/` — the strictly read-only, engagement-free forensics loop (its own
  linear `collect→examine→respond` graph): `deps`, `state`, `prompts`, `scope`
  (the read-only tool allow-list + evidence confinement), `collect`, `nodes`,
  `graph`, `runner`, `report`, `schema`, and `analyzers/` (pure-Python
  hash/strings/hex/entropy/magic/encoding/logparse/keyed-decrypt/OCR). Bound to a
  *case* (not an engagement), recording to a separate case ledger. See the
  `forensics` mode + the `case` verb.
- `frontend/` — `tui`, `daemon`, `shell`, `client` + dispatch (`verbs`,
  `commands`, `configflow`, `cmdflow`, `setup`, `wizard`, `menu`, `help`)
- `config/` — `config` (typed `Settings`), `configs` (JSON loaders)
- `engagement/` — `engagement` (re-export facade) over `scope` (the boundary model)
  + `guard` (parse + `check_command`), `workspace`, `risk`, `pivot`, `egress`,
  `runtime_env`, `datafiles`, `osint_guard`, `case` (the forensics case: metadata +
  probe + scaffold, no scope)
- `security/` — the data-plane boundary: `redaction`, `vault`, `policy`,
  `tripwire`, `boundaries` (deterministic, model-free)
- `frameworks/` — offline security-framework awareness: `cvss` (deterministic v3.1),
  `registry` + vendored `data/` (WSTG/ATT&CK/PTES, `scripts/sync_frameworks.py`)
- `persistence/` — `ledger` (+ `ledger_schema`/`ledger_ddl`), `custody` +
  `integrity` (hash-chained tamper-evidence), `review`, `memory` (checkpointer),
  `preferences`, `vectorstore`, `documents`, `transcript`, `session_summary`,
  `reports`, `pdf`, `visualize`
- `providers/` — `providers` (factory), `codex_chat`, `codex_login`,
  `claude_cli_chat`
- `tooling/` — `registry`, `probe`, `doctor`, `commands`, `websearch`
- `common/` — leaf utilities: `paths`, `home`, `text`, `palette`, `execution`,
  `logs`, `clock`, `jwt`
- `install/` — `init`, `boot`, `envfile`, `ingest`, `update`
- `eval/` — the offline + provider eval tiers (`skuggi-eval`)

## Rules

- [Architecture](.ai/rules/architecture.md) — the package layout, the DAG
  import graph, which imports must stay lazy, one-source-of-truth per concern
- [Gates](.ai/rules/gates.md) — `make check` is the whole gate (ruff format
  --check · ruff · mypy strict · pytest 90% branch), same order as CI
- [Storage & the three homes](.ai/rules/storage.md) — config/data XDG homes + the
  cwd-relative per-engagement root (the adopted directory itself, no
  `engagements/<name>/` wrapper); never resolve a storage path at import time
- [The structured protocol](.ai/rules/protocol.md) — every LLM call is a strict
  typed exchange; prompts live in `agent/prompts.py`
- [LLM providers](.ai/rules/providers.md) — five providers (incl. `claude-cli`),
  codex OAuth, and the lazy-import rule that keeps the OpenAI SDK out of the core
  import graph
- [Testing](.ai/rules/testing.md) — the offline/opt-in layers, credential
  isolation, and never automating against real homes
- [The practice range](.ai/rules/labs.md) — `labs/` is loopback-only via
  `labctl`; the vulnerable app code is not linted or typechecked

## Commands

[/plan](.ai/commands/plan.md) · [/audit](.ai/commands/audit.md) · [/bugfix](.ai/commands/bugfix.md) · [/refactor](.ai/commands/refactor.md)

## Critical rules (excerpt)

The most-violated. Full set in [`.ai/rules/`](.ai/rules/).

- **`make check` before done** — ruff format --check, ruff (incl. `C901` +
  `PLR09xx` size/complexity), the file-size cap (`scripts/check_file_size.py`),
  mypy strict, pytest (90% branch). Fix a finding at its root; don't widen a
  `per-file-ignores` entry or raise a cap — split along a real seam instead.
- **A green gate is not proof of isolation** — tests must redirect
  `SKUGGI_CONFIG_HOME`/`SKUGGI_DATA_HOME`; verify `ls ~/.config/skuggi
  ~/.local/share/skuggi` is unchanged after a run.
- **Never automate the harness against the operator's real homes or a live
  engagement** — tmp homes and the frozen `e2e` fixture only.
- **Never resolve a storage path at import time** — resolve under the homes at
  call time (`common/home.py`); no module-level `.expanduser()`.
- **Keep the lazy imports lazy** — they break the doctor/shell/daemon triangle
  and keep heavy/optional deps out of the core import graph.
- **Prompts live in `agent/prompts.py`; the verb set in `frontend/verbs.py`** —
  one source of truth; don't inline either.
- **Moving a module is a repo-wide sweep** — imports, entry points,
  `per-file-ignores`, doc links, gated by `make check`.
