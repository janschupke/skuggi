# skuggi

A locally-hosted **pentesting agent harness**. You drive an authorized
engagement through a LangGraph agent; for each request it advises, **proposes a
shell command** (checked against a strict engagement boundary), or summarizes.
Every prompt, agent reply, command (including commands you free-type in the
shell) and finding is written, in order and with timestamps, to a per-engagement
SQLite ledger — each finding traceable prompt → command → finding. The session
is retrievable and replayable (`/skuggi replay`), exportable as a Markdown
report, and can be critiqued privately by the LLM (`/skuggi review`). Harness
chatter (control verbs, CLI noise) is kept in a separate audit log, out of the
client-facing report.

The default `skuggi` command wraps your **real shell**: you keep your prompt,
colours, completion, history and signals, and only `/skuggi <verb> …` reaches
the agent (a warm in-process daemon). Interaction is **verb-first** — the first
word is the action, the rest is its input (`/skuggi ask scan the web host`); a
bare `/skuggi` opens an interactive chat loop against the warm daemon and hands
the shell back when you leave it. `skuggi-repl` is the pure agent chat.

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

# app config (persisted, edited by the `config` verb); tune it freely
cp configs/config.example.json configs/config.json
# secrets stay in the environment, never in the JSON:
export ANTHROPIC_API_KEY=sk-ant-...      # easiest; or arrange OpenAI/ChatGPT auth

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

Inside the wrapped shell your normal commands run natively; `/skuggi <verb>`
reaches the agent:

```
🐐 ~ %  ls                              # your real shell, native colours
🐐 ~ %  /skuggi ask scan the web host   # → agent proposes an in-scope command
🐐 ~ %  /skuggi run nmap-host 10.0.0.5  # → resolve an alias, check scope, advise
🐐 ~ %  /skuggi findings                # → harness control
🐐 ~ %  /skuggi                         # → open the chat loop (blank line leaves)
🐐 ~ %  /skuggi exit                    # → leave the harness
```

For the pure agent chat instead:

```sh
uv run skuggi-repl     # or: python -m skuggi
```

```
> what is exposed on the target?     # bare text is an implicit `ask`
> /provider anthropic
> /ingest docs
> /quit
```

## Verbs

The first word after `/skuggi` (or after `/` in `skuggi-repl`) is the verb; the
rest is its input. In `skuggi-repl`, bare text with no leading `/` is an
implicit `ask`. The two front-ends share one registry
([src/skuggi/verbs.py](src/skuggi/verbs.py)), so `/help` always matches.

| Verb | Effect |
|---|---|
| `ask <prompt>` | Send a prompt to the agent |
| `run <alias> [args]` | Resolve a command alias, check scope, advise (never runs it) |
| `findings` | List findings recorded this session |
| `report [pdf]` | Write a Markdown engagement report (add `pdf` for a styled PDF too) |
| `replay [list \| <session>]` | Reconstruct & view a session transcript (`list` enumerates sessions) |
| `review [<session>]` | Private LLM critique of a session — feedback for you, never client-facing |
| `engagement [setup]` | Show the scope, or run the interactive setup wizard |
| `config [show \| <key> <value> \| <request>]` | Show or change app settings |
| `doctor [install <tool>]` | Probe host tools; install a missing one on request |
| `mode <pentest\|redteam\|blueteam>` | Switch the prompt set (see below) |
| `autonomous [on\|off]` | Toggle autonomous command execution |
| `provider <openai\|chatgpt\|anthropic\|ollama>` | Switch provider, recompile graph |
| `model <name>` | Switch model on the current provider |
| `thread new\|list\|<id>` | Start / list / resume a conversation thread |
| `history [n]` | Show the last `n` messages on the current thread |
| `trace` | Show the worker's tool calls on the current thread |
| `ingest <path>` | Index a file or directory of `*.md` / `*.txt` |
| `update` | Update skuggi in place (`git pull --ff-only` + `uv sync`) |
| `clear` | Clear the screen (`skuggi-repl` only) |
| `help` | Verb reference |
| `exit`, `quit` | Close cleanly |

**Interactive verbs need a loop.** `engagement setup` and a natural-language
`config <request>` prompt you back and forth, so they run in `skuggi-repl` or in
the wrapped shell's chat loop (a bare `/skuggi`). Invoked one-shot as
`/skuggi engagement setup`, they point you at the loop rather than half-running.

## run: command aliases (transparent, suggest-style)

`run <alias> [args]` maps a short name to a CLI invocation
([configs/commands.example.json](configs/commands.example.json)), resolves it,
**prints the fully-resolved raw command**, checks it against the engagement
scope, records it (`proposed` in scope, `blocked` out of scope), and has the
agent advise — it never executes. `run` / `run list` lists the aliases. Copy the
example to `configs/commands.json` and extend it. Shipped defaults:

| Alias | Command | Purpose |
|---|---|---|
| `nmap-network` | `nmap -sn` | host discovery (ping sweep) |
| `nmap-host` | `nmap -sV -sC` | service/version + default scripts |
| `nmap-full` | `nmap -p- -sV` | all TCP ports with service detection |
| `web-fetch` | `curl -sSIL` | response headers, following redirects |
| `web-dir` | `gobuster dir -u` | directory brute-force (append `-w <wordlist>`) |

## engagement setup: the scope wizard

`engagement setup` runs a field-by-field wizard (name, timezone, authorized
window, daily windows, target networks, allowed hosts/tools/methods,
autonomous), validates the answers, writes `engagements/<name>/scope.json`, and
**hot-reloads** the boundary into the running session — no restart. A blank
answer keeps the current value when editing; `Ctrl-D` cancels.

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

### PDF reports

Markdown is the canonical artifact; a styled, client-ready PDF is derived from
it. `/report pdf` writes a `.pdf` next to the `.md`, and the standalone
`skuggi-pdf` renders any Markdown file (a report, or anything under `docs/`):

```sh
skuggi-pdf data/reports/<file>.md            # -> <file>.pdf
skuggi-pdf docs/architecture.md -o arch.pdf --html   # also emit the HTML
make pdf IN=docs/architecture.md
```

The pipeline is `Markdown -> HTML -> PDF`
([src/skuggi/pdf.py](src/skuggi/pdf.py)): markdown-it-py parses the report,
Pygments highlights fenced code, a Jinja2 shell wraps it in the print
stylesheet ([src/skuggi/templates/report.css](src/skuggi/templates/report.css)),
and WeasyPrint paints the PDF. Styling is pure CSS — edit `report.css` to
restyle every report — and the severity/method colours are pulled from
[src/skuggi/palette.py](src/skuggi/palette.py), the same source the terminal
uses. It needs the optional `pdf` dependency group (installed by `make install`)
and WeasyPrint's native Pango library:

```sh
brew install pango            # macOS
# apt install libpango-1.0-0 libpangoft2-1.0-0   # Debian/Ubuntu
uv sync --group pdf           # if you skipped `make install`
```

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

App settings (providers/models, embedding models, storage paths, graph bounds,
mode, the pentest-harness paths) live in **`configs/config.json`** — copy it from
[configs/config.example.json](configs/config.example.json). Values resolve in
priority order: an environment variable (prefix `SKUGGI_*`, or the unprefixed
vendor names) overrides the JSON, which overrides the built-in defaults. So a
one-off `SKUGGI_PROVIDER=anthropic` still wins for a single run. Config tiers:

- **App config** (`configs/config.json`, gitignored except `.example`): the
  settings above; edit it directly or with the `config` verb.
- **Harness config** (shared, in `configs/`): the recognized-tool registry
  `tools.json`, the optional workspace-layout override `layout.json`, and the
  optional `run`-alias file `commands.json`.
- **Engagement setup** (per-case, in `engagements/<name>/scope.json`): the
  boundary above.

The **`config` verb** edits the app config in place: `config` (or `config show`)
prints every setting with credentials redacted; `config <key> <value>` validates
and persists one setting, applying `provider`/`mode` to the live session (other
keys take effect on restart); and `config <natural-language request>` asks the
LLM to propose `key=value` edits, shows them, and applies them on your
confirmation. It never writes a secret.

**Secrets never go in the JSON.** The API keys are read only from the
environment — `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` (or `~/.codex/auth.json`) —
and `OLLAMA_BASE_URL`; see [.env.example](.env.example). The JSON config source
drops these fields even if a file mistakenly contains one.

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
- `skuggi-pdf` — render a Markdown file to a styled PDF (needs the `pdf` group)
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
- [docs/lab.md](docs/lab.md) — the dockerized practice lab: a deliberately
  vulnerable target network (`192.0.2.0/24`) to point skuggi at, with its
  topology, credentials, vulnerability catalog, and WireGuard reachability.
