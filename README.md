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

| Provider    | Auth                                                        | Structured output |
|-------------|-------------------------------------------------------------|-------------------|
| `openai`    | `~/.codex/auth.json` (`OPENAI_API_KEY`) or `$OPENAI_API_KEY`| native            |
| `chatgpt`   | `~/.codex/auth.json` ChatGPT-account OAuth tokens           | JSON fallback¹    |
| `anthropic` | `$ANTHROPIC_API_KEY`                                        | native            |
| `ollama`    | `$OLLAMA_BASE_URL` (default `http://localhost:11434`)       | native            |

¹ Every LLM reply is a strict structured response (the request/response protocol
in [docs/architecture.md](docs/architecture.md)). Most providers get it natively
(`with_structured_output`); the ChatGPT-account endpoint has no native structured
output, so it uses a JSON contract with one repair retry. See
[docs/codex-auth.md](docs/codex-auth.md).

## Install

Requires Python ≥3.12 and [uv](https://docs.astral.sh/uv/) (developed on 3.14;
CI covers 3.12–3.14).

```sh
make install-cli
```

That installs `skuggi` (and every `skuggi-*` command) onto your `$PATH`, puts
uv's bin directory on `$PATH` if it is not already there, and seeds the harness
config. **Open a new shell**, then check it:

```sh
command -v skuggi        # → ~/.local/bin/skuggi
skuggi-doctor            # → the install table: both homes, config files, tools
```

If `skuggi: command not found` persists, uv's bin directory is not on your
`$PATH`; add it and reopen the shell:

```sh
export PATH="$HOME/.local/bin:$PATH"     # `uv tool dir --bin` prints the directory
```

Then give it a credential — any one of these:

```sh
printf 'ANTHROPIC_API_KEY=sk-ant-...\n' > ~/.config/skuggi/env && chmod 600 ~/.config/skuggi/env
export ANTHROPIC_API_KEY=sk-ant-...      # or just export it from your shell rc
codex login                              # or arrange OpenAI/ChatGPT auth
```

Now `skuggi` runs **from any directory**. Its config and databases live in two
fixed homes, so every invocation reads the same harness (see
[Configuration](#configuration)); only the engagement workspace is relative to
where you are, because that is where the client's data belongs.

To start an engagement, `cd` to where you want its workspace to live:

```sh
mkdir -p ~/work/acme-2026 && cd ~/work/acme-2026
cp ~/.config/skuggi/scope.example.json ./scope-draft.json   # or use the wizard
export SKUGGI_ENGAGEMENT=acme-2026
skuggi                                   # → /skuggi engagement setup
```

With no `SKUGGI_ENGAGEMENT` set, skuggi runs agent-only (no scope, no ledger).

Installing from an existing checkout moves any `configs/` and `data/` you already
had into the two homes, once — that state is gitignored, so it is not left behind.
It is a move, not a copy, so there is only ever one live copy of each database.
For the full story, and for troubleshooting, see [docs/install.md](docs/install.md).

## Usage

```sh
skuggi                 # the native shell wrapper (🐐 prompt), from anywhere
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
skuggi-repl            # or: python -m skuggi
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
| `memory [add <text> \| forget <id> \| clear]` | Show / add / forget remembered operator preferences |
| `engagement [setup]` | Show the scope, or run the interactive setup wizard |
| `config [show \| <key> <value> \| <request>]` | Show or change app settings |
| `doctor [install <tool>]` | Probe host tools; install a missing one on request |
| `mode <pentest\|redteam\|blueteam>` | Switch the prompt set (see below) |
| `autonomous [on\|off]` | Toggle autonomous command execution |
| `provider <openai\|chatgpt\|anthropic\|ollama>` | Switch provider, recompile graph |
| `model <name>` | Switch model on the current provider |
| `thread new\|list\|<id>` | Start / list / resume a conversation thread |
| `history [n]` | Show the last `n` messages on the current thread |
| `trace` | Show the command trail on the current thread |
| `ingest <path>` | Index a file or directory of `*.md` / `*.txt` |
| `update` | Update skuggi in place (`git pull --ff-only`, then refresh the install) |
| `clear` | Clear the screen (`skuggi-repl` only) |
| `help` | Verb reference |
| `exit`, `quit` | Close cleanly |

**Interactive verbs need a loop.** `engagement setup` and a natural-language
`config <request>` prompt you back and forth, so they run in `skuggi-repl` or in
the wrapped shell's chat loop (a bare `/skuggi`). Invoked one-shot as
`/skuggi engagement setup`, they point you at the loop rather than half-running.

## run: command aliases (transparent, suggest-style)

`run <alias> [args]` maps a short name to a CLI invocation
([src/skuggi/templates/commands.example.json](src/skuggi/templates/commands.example.json)), resolves it,
**prints the fully-resolved raw command**, checks it against the engagement
scope, records it (`proposed` in scope, `blocked` out of scope), and has the
agent advise — it never executes. `run` / `run list` lists the aliases. Copy the
example to `<config home>/commands.json` and extend it. Shipped defaults:

| Alias | Command | Purpose |
|---|---|---|
| `nmap-network` | `nmap -sn` | host discovery (ping sweep) |
| `nmap-host` | `nmap -sV -sC` | service/version + default scripts |
| `nmap-full` | `nmap -p- -sV` | all TCP ports with service detection |
| `web-fetch` | `curl -sSIL` | response headers, following redirects |
| `web-dir` | `gobuster dir -u` | directory brute-force (append `-w <wordlist>`) |

## memory: standing operator preferences

`memory` is the harness's durable memory of how *you* like to work — which tool
to prefer when several would do, the language to write helper scripts in, how
terse a reply should be, reporting conventions. Remembered preferences are
injected into the planner, worker and critic every turn, so the agent follows
your standing instructions across threads and sessions.

They fill two ways:

- **Automatically.** After a turn whose message reads like a standing directive
  (`always…`, `prefer…`, `from now on…`, `use X over Y`), the harness extracts
  the durable preference and saves it, announcing `remembered: … (forget N to
  undo)`. One-off requests and target-specific facts are ignored. Turn it off
  with `config memory_auto false` (or `SKUGGI_MEMORY_AUTO=0`).
- **Manually.** `memory add <text>` stores one; `memory` (or `memory list`)
  shows them with ids; `memory forget <id>` drops one; `memory clear` empties
  the store.

Memory is **global** across engagements — a preference is about the operator,
not a target — and lives in `./data/preferences.db`, separate from the ledger.

## engagement setup: the scope wizard

`engagement setup` runs a field-by-field wizard (name, timezone, authorized
window, daily windows, target networks, allowed hosts/tools/methods,
autonomous), validates the answers, writes `engagements/<name>/scope.json`, and
**hot-reloads** the boundary into the running session — no restart. A blank
answer keeps the current value when editing; `Ctrl-D` cancels.

## The engagement boundary

The authorized scope for one engagement is its workspace's `scope.json`
(template: [src/skuggi/templates/scope.example.json](src/skuggi/templates/scope.example.json)), loaded at
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

## Commands: suggest by default, autonomous on request

The worker returns a structured response; when it proposes a `command`, the
executor node sends it through the engagement guard and never runs a blocked one.
For an in-scope command:

- **suggest mode (default, `autonomous: false`)** — records the command as
  `proposed` and hands it back for you to run by hand.
- **autonomous mode (`autonomous: true` in the scope, or `/autonomous on`)** —
  executes it (`shell=False`, argv exec'd directly, output byte-capped,
  wall-clock timeout) in the workspace's `recon/` directory, records the result,
  and feeds it back to the worker for the next step (bounded by
  `max_tool_rounds`). The prompt shows `!` and the banner shows autonomous ON
  while armed.

Blocked, proposed and executed commands are all persisted with timestamps.

## Modes

`/mode pentest|redteam|blueteam` swaps the planner/worker/critic prompt set
([src/skuggi/prompts.py](src/skuggi/prompts.py)); the graph and guard are
identical across modes. Set the default with `SKUGGI_MODE`.

## Tools and `skuggi-doctor`

Recognized tools live in the JSON registry
([src/skuggi/templates/tools.example.json](src/skuggi/templates/tools.example.json)): each tool's binary,
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
([src/skuggi/templates/layout.example.json](src/skuggi/templates/layout.example.json)). Everything under
`engagements/` is gitignored.

## Configuration

skuggi is a command you run from anywhere, so its config does not live next to
your cwd. It lives in **two fixed homes**, seeded by `skuggi-init`:

| | Default | Overrides | Holds |
|---|---|---|---|
| **Config home** | `~/.config/skuggi` | `SKUGGI_CONFIG_HOME`, else `XDG_CONFIG_HOME/skuggi` | `config.json`, `tools.json`, `layout.json`, `commands.json`, `env` |
| **Data home** | `~/.local/share/skuggi` | `SKUGGI_DATA_HOME`, else `XDG_DATA_HOME/skuggi` | `sessions.db`, `preferences.db`, `faiss_index/`, `toolbox/`, `.repl_history` |

**`./engagements/<name>/` stays relative to your working directory.** That is the
one deliberate exception, and the reason for the split: an engagement's scope,
ledger, recon output and reports belong to the client directory you ran skuggi
in, not to a global dotdir. Harness config is about *you*; a workspace is about
*a case*. `skuggi-doctor` prints where every one of these resolved.

Values resolve in priority order, highest first:

1. an environment variable (prefix `SKUGGI_*`, or the unprefixed vendor names)
2. `<config home>/env` — same spelling as the environment, so
   `SKUGGI_PROVIDER=anthropic` and a bare `ANTHROPIC_API_KEY=...`
3. `<config home>/config.json`
4. the built-in defaults

So a one-off `SKUGGI_PROVIDER=anthropic` still wins for a single run. Config tiers:

- **App config** (`<config home>/config.json`): providers/models, embedding
  models, storage paths, graph bounds, mode, the pentest-harness paths. Edit it
  directly or with the `config` verb.
- **Harness config** (shared, same home): the recognized-tool registry
  `tools.json`, the optional workspace-layout override `layout.json`, and the
  optional `run`-alias file `commands.json`.
- **Engagement setup** (per-case, in `./engagements/<name>/scope.json`): the
  boundary above.

A path you set explicitly is taken as written, so a *relative* one still resolves
against the working directory — `SKUGGI_CONFIG_PATH=./configs/config.json` gives
you a project-local config if you want one.

The **`config` verb** edits the app config in place: `config` (or `config show`)
prints every setting with credentials redacted; `config <key> <value>` validates
and persists one setting, applying `provider`/`mode` to the live session (other
keys take effect on restart); and `config <natural-language request>` asks the
LLM to propose `key=value` edits, shows them, and applies them on your
confirmation. It never writes a secret.

**Secrets never go in `config.json`.** The API keys — `OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, plus `OLLAMA_BASE_URL` — are read from the environment, from
`<config home>/env`, or from `~/.codex/auth.json`; see
[.env.example](.env.example) for the `env` template. The JSON config source drops
these fields even if a file mistakenly contains one; the `env` file is *not*
filtered, because holding credentials is the only reason it exists. Keep it at
`chmod 600` — `skuggi-doctor` warns if it is group- or world-readable.

## Storage layout

Harness config, in the **config home** (`~/.config/skuggi`):

- `config.json` — app config (the `config` verb edits this)
- `tools.json` — the recognized-tool registry
- `layout.json`, `commands.json` — optional workspace layout and `run` aliases
- `env` — optional secrets file (`chmod 600`)
- `scope.example.json` — the template to copy for a new engagement

Harness state, in the **data home** (`~/.local/share/skuggi`):

- `sessions.db` — LangGraph checkpoint store
- `preferences.db` — harness memory (global operator preferences)
- `faiss_index/` — FAISS retrieval index
- `toolbox/` — the managed tool venv (`SKUGGI_TOOL_SOURCE=managed|combine`)
- `.repl_history` — REPL input history
- `ledger.db`, `reports/` — agent-only fallback when no engagement is selected

Per-case, **relative to your working directory**:

- `./engagements/<name>/` — the engagement workspace: its scope, ledger, recon
  output and reports (gitignored)

The templates themselves ship inside the package
([src/skuggi/templates/](src/skuggi/templates/)) so that an install with no
checkout can still seed a config home.

## Entry points

- `skuggi` — the native shell wrapper (warm agent daemon + your real `$SHELL`)
- `skuggi-repl` — the pure agent REPL
- `skuggi-init` — create the config/data homes and seed them from the templates
- `skuggi-doctor` — probe the host for the registry's tools and report
- `skuggi-ingest` — index files/directories into the FAISS store
- `skuggi-pdf` — render a Markdown file to a styled PDF (needs the `pdf` extra)
- `skuggi-client` — the thin client the shell's `/skuggi` hook calls (not run
  directly)

## Development

```sh
make install     # uv sync --all-groups --all-extras, plus the git hooks
make install-cli # put `skuggi` on $PATH (editable) and seed the homes
make check       # ruff format --check, ruff, mypy --strict, pytest — what CI runs
make eval        # the real-provider layer; costs money, needs credentials
make e2e         # the real pipeline against the docker lab (bring it up first)
make eval-det    # the deterministic eval gate, offline (also inside `make check`)
make bench       # the full eval benchmark across providers; costs money
```

`make check` is the gate. The test suite is five layers, three of them offline;
`make eval` (real providers) and `make e2e` (the [dockerized lab](docs/lab.md))
are opt-in — see [docs/testing.md](docs/testing.md). A committed, local-only
**eval system** (`skuggi-eval`) scores the agent across five dimensions — budget,
latency, factuality, host-system compatibility, and compliance with the
methodology and engagement constraints — and hard-gates on regression against
[evals/baseline.json](evals/baseline.json); see [evals/README.md](evals/README.md).

## Further reading

- [docs/install.md](docs/install.md) — installing the `skuggi` command, the two
  homes, how `update` behaves per install shape, and troubleshooting.
- [docs/architecture.md](docs/architecture.md) — the agent graph, state channels
  and persistence, and a tour of the standalone modules.
- [docs/codex-auth.md](docs/codex-auth.md) — the `openai` / `chatgpt` providers,
  `~/.codex/auth.json`, OAuth refresh, and the model-name gotcha.
- [docs/testing.md](docs/testing.md) — the test layers and the eval system.
- [evals/README.md](evals/README.md) — the local eval system: golden sets, the
  deterministic gate, the Braintrust quality benchmark, and the baseline.
- [docs/lab.md](docs/lab.md) — the dockerized practice lab: a deliberately
  vulnerable target network (`192.0.2.0/24`) to point skuggi at, with its
  topology, credentials, vulnerability catalog, and WireGuard reachability.
