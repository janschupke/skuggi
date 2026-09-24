# skuggi

A locally-hosted **pentesting agent harness**. You drive an authorized
engagement through a LangGraph agent; for each request it advises, **proposes a
shell command** (checked against a strict engagement boundary), or summarizes.
Every command and finding is written to a per-engagement SQLite ledger — each
finding traceable to the command that produced it — and exportable as a Markdown
report.

The default `skuggi` command wraps your **real shell**: you keep your prompt,
colours, completion, history and signals, and only `/skuggi <prompt>` reaches
the agent (a warm in-process daemon). `skuggi-repl` is the pure agent chat.

Four LLM providers, switchable at runtime:

| Provider    | Auth                                                        | Tools? |
|-------------|-------------------------------------------------------------|--------|
| `openai`    | `~/.codex/auth.json` (`OPENAI_API_KEY`) or `$OPENAI_API_KEY`| yes    |
| `chatgpt`   | `~/.codex/auth.json` ChatGPT-account OAuth tokens           | no¹    |
| `anthropic` | `$ANTHROPIC_API_KEY`                                        | yes    |
| `ollama`    | `$OLLAMA_BASE_URL` (default `http://localhost:11434`)       | yes    |

¹ The ChatGPT-account endpoint uses a codex-specific tool schema, so the worker
runs as a plain generator there. See [docs/codex-auth.md](docs/codex-auth.md).

## Install

Requires Python ≥3.12 and [uv](https://docs.astral.sh/uv/) (developed on 3.14;
CI covers 3.12–3.14).

```sh
uv sync --all-groups
cp .env.example .env
# edit .env: set ANTHROPIC_API_KEY (easiest), or arrange OpenAI/ChatGPT auth

# harness config (shared across engagements): the recognized-tool registry
cp configs/tools.example.json configs/tools.json

# one engagement: a workspace with its scope. Edit the scope to your targets.
mkdir -p engagements/acme-2026
cp configs/scope.example.json engagements/acme-2026/scope.json
export SKUGGI_ENGAGEMENT=acme-2026
```

With no `SKUGGI_ENGAGEMENT` set, skuggi runs agent-only (no scope, no ledger).

## Usage

```sh
uv run skuggi          # the native shell wrapper (🐐 prompt)
```

Inside the wrapped shell your normal commands run natively; `/skuggi` reaches
the agent:

```
🐐 ~ %  ls                            # your real shell, native colours
🐐 ~ %  /skuggi scan the web host     # → agent proposes an in-scope command
🐐 ~ %  /skuggi /findings             # → harness control
🐐 ~ %  /skuggi exit                  # → leave the harness
```

For the pure agent chat instead:

```sh
uv run skuggi-repl     # or: python -m skuggi
```

```
> what is exposed on the target?
> /provider anthropic
> /ingest docs
> /quit
```

## Commands

In `skuggi-repl` these are typed directly; in the wrapped `skuggi` shell they
are reached as `/skuggi <prompt>` and `/skuggi /findings`, etc. Anything not
starting with `/` goes to the agent.

| Command | Effect |
|---|---|
| `/help` | Command reference |
| `/provider <openai\|chatgpt\|anthropic\|ollama>` | Switch provider, recompile graph |
| `/model <name>` | Switch model on the current provider |
| `/mode <pentest\|redteam\|blueteam>` | Switch the prompt set (see below) |
| `/thread new\|list\|<id>` | Start / list / resume a conversation thread |
| `/history [n]` | Show the last `n` messages on the current thread |
| `/trace` | Show the worker's tool calls on the current thread |
| `/engagement` | Show the loaded engagement scope |
| `/doctor [install <tool>]` | Probe host tools; install a missing one on request |
| `/findings` | List findings recorded this session |
| `/report` | Write a Markdown engagement report |
| `/autonomous [on\|off]` | Toggle autonomous command execution |
| `/ingest <path>` | Index a file or directory of `*.md` / `*.txt` |
| `/clear` | Clear the screen |
| `/quit`, `/exit` | Close cleanly |

## The engagement boundary

The authorized scope for one engagement is its workspace's `scope.json`
(template: [configs/scope.example.json](configs/scope.example.json)), loaded at
start and never committed:

```json
{
  "name": "acme-external-2026",
  "timezone": "Europe/Helsinki",
  "authorized_start": "2026-09-01T00:00:00+03:00",
  "authorized_end": "2026-12-31T23:59:59+02:00",
  "daily_windows": [{ "start": "09:00:00", "end": "17:00:00" }],
  "target_networks": ["192.0.2.0/24"],
  "allowed_hosts": ["scanme.example.com"],
  "allowed_tools": ["nmap", "curl"],
  "allowed_methods": ["recon", "scan"],
  "autonomous": false
}
```

Every command the agent proposes is parsed and checked by a single guard
(`check_command` in [src/skuggi/engagement.py](src/skuggi/engagement.py)), in
order: recognized tool → authorized tool → authorized method → inside the date
window → inside the daily clock window → every extracted target inside an
allowed network/host. The rule is conservative: a target-requiring command with
no in-scope target is denied, and anything the guard cannot prove in scope is
denied.

`allowed_methods` is coarse by design: each registry entry declares one static
method (`nmap`→`scan`, `curl`→`recon`), so it gates tool *categories* and
largely reinforces `allowed_tools` — it does not distinguish `nmap -sn` from
`nmap -A`.

## run_command: suggest by default, autonomous on request

`run_command` never runs a blocked command. For an in-scope command:

- **suggest mode (default, `autonomous: false`)** — records the command as
  `proposed` and hands it back for you to run by hand.
- **autonomous mode (`autonomous: true` in the scope, or `/autonomous on`)** —
  executes it (`shell=False`, argv exec'd directly, output byte-capped,
  wall-clock timeout) in the workspace's `recon/` directory and records the
  result. The prompt shows `!` and the banner shows autonomous ON while armed.

Blocked, proposed and executed commands are all persisted with timestamps.

## Modes

`/mode pentest|redteam|blueteam` swaps the planner/worker/critic prompt set
([src/skuggi/modes.py](src/skuggi/modes.py)); the graph, tools and guard are
identical across modes. Set the default with `SKUGGI_MODE`.

## Tools and `skuggi-doctor`

Recognized tools live in the JSON registry
([configs/tools.example.json](configs/tools.example.json)): each tool's binary,
its engagement method, how to read its version, which flags carry targets, and
per-installer install commands. `skuggi-doctor` (or `/doctor`) probes the host
`PATH` and/or a skuggi-managed venv (per `SKUGGI_TOOL_SOURCE=host|managed|combine`),
captures versions, and reports what is missing with install hints filtered to
the package managers actually present on this host. It also reports the standard
runtimes/toolchains (ruby, python3, node, …) and net tools (dig, ssh, …) an
operator relies on. `/doctor install <tool>` installs a missing one — issuing
the subcommand is the confirmation.

## Findings, the ledger and reports

The harness persists to a per-engagement SQLite **ledger**
([src/skuggi/ledger.py](src/skuggi/ledger.py), `engagements/<name>/ledger.db`),
separate from the checkpointer, with `sessions`, `commands` and `findings`
tables. A finding links to its session and (by default) to the most recent
command, so it is always traceable. `/report` writes a Markdown report into the
workspace's `reports/` with the scope, findings grouped by severity, and the
timestamped command log.

## The per-engagement workspace

Each engagement operates in `engagements/<name>/`
([src/skuggi/workspace.py](src/skuggi/workspace.py)), created on startup:

```
engagements/<name>/
  scope.json            # the engagement boundary (the engagement setup)
  findings/  notes/
  recon/nmap/  recon/web/
  reports/              # /report output
  scripts/  tests/
  ledger.db             # this engagement's ledger
```

The layout is configurable
([configs/layout.example.json](configs/layout.example.json)). Everything under
`engagements/` is gitignored.

## Configuration

All settings are read from the environment (prefix `SKUGGI_`) or a `.env` file —
see [.env.example](.env.example) for the full list (providers/models,
embedding models, storage paths, graph bounds, mode, and the pentest-harness
paths). Two tiers:

- **Harness config** (shared, in `configs/`, gitignored except `.example`): the
  recognized-tool registry `tools.json` and the optional workspace-layout
  override `layout.json`.
- **Engagement setup** (per-case, in `engagements/<name>/scope.json`,
  gitignored): the boundary above.

Vendor credentials keep their conventional unprefixed names: `OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, `OLLAMA_BASE_URL`.

## Storage layout

- `./configs/*.json` — harness config (only `.example` templates are committed)
- `./engagements/<name>/` — per-engagement workspace (gitignored)
- `./data/sessions.db` — LangGraph checkpoint store
- `./data/faiss_index/` — FAISS retrieval index
- `./data/toolbox/` — the managed tool venv (`SKUGGI_TOOL_SOURCE=managed|combine`)
- `./data/.repl_history` — REPL input history
- `./data/ledger.db`, `./data/reports/` — agent-only fallback when no engagement
  is selected

## Entry points

- `skuggi` — the native shell wrapper (warm agent daemon + your real `$SHELL`)
- `skuggi-repl` — the pure agent REPL
- `skuggi-doctor` — probe the host for the registry's tools and report
- `skuggi-ingest` — index files/directories into the FAISS store
- `skuggi-client` — the thin client the shell's `/skuggi` hook calls (not run
  directly)

## Development

```sh
make install     # uv sync --all-groups, plus the git hooks
make check       # ruff format --check, ruff, mypy --strict, pytest — what CI runs
make eval        # the real-provider layer; costs money, needs credentials
```

`make check` is the gate. The test suite is four layers, three of them offline —
see [docs/testing.md](docs/testing.md).

## Further reading

- [docs/architecture.md](docs/architecture.md) — the agent graph, state channels
  and persistence, and a tour of the standalone modules.
- [docs/codex-auth.md](docs/codex-auth.md) — the `openai` / `chatgpt` providers,
  `~/.codex/auth.json`, OAuth refresh, and the model-name gotcha.
- [docs/testing.md](docs/testing.md) — the test layers.
