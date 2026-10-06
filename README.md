# skuggi

A locally-hosted **pentesting agent harness**. You drive an authorized engagement
through a LangGraph agent; for each request it advises, **proposes a shell command**
(checked against a strict engagement boundary), or summarizes. Every prompt, agent
reply, command (including commands you free-type in the shell) and finding is
written, in order and with timestamps, to a per-engagement SQLite ledger — each
finding traceable prompt → command → finding. The session is retrievable and
replayable (`/skuggi replay`), exportable as a Markdown or PDF report, and can be
critiqued privately by the LLM (`/skuggi review`). Harness chatter (control verbs,
CLI noise) is kept in a separate audit log, out of the client-facing report.

Beyond the main turn loop it also runs autonomous **OSINT** and **research**
intelligence loops, and a strictly read-only **forensics** mode for examining local
evidence.

The default `skuggi` command wraps your **real shell**: you keep your prompt,
colours, completion, history and signals, and only `/skuggi <verb> …` reaches the
agent (a warm in-process daemon). Interaction is **verb-first** — the first word is
the action, the rest is its input (`/skuggi ask scan the web host`); a bare
`/skuggi` opens an interactive chat loop against the warm daemon and hands the shell
back when you leave it. `skuggi-repl` is the pure agent chat.

Five LLM providers, switchable at runtime:

| Provider     | Auth                                                        | Structured output |
|--------------|-------------------------------------------------------------|-------------------|
| `openai`     | `~/.codex/auth.json` (`OPENAI_API_KEY`) or `$OPENAI_API_KEY`| native            |
| `chatgpt`    | `~/.codex/auth.json` ChatGPT-account OAuth tokens           | JSON fallback¹    |
| `anthropic`  | `$ANTHROPIC_API_KEY`                                        | native            |
| `claude-cli` | the local `claude` binary's own login (your subscription)²  | JSON fallback¹    |
| `ollama`     | `$OLLAMA_BASE_URL` (default `http://localhost:11434`)       | native            |

¹ Every LLM reply is a strict structured response (the request/response protocol in
[docs/architecture.md](docs/architecture.md)). Most providers get it natively
(`with_structured_output`); the ChatGPT-account endpoint and the `claude-cli`
subprocess have no native structured output, so they use a JSON contract with one
repair retry. See [docs/codex-auth.md](docs/codex-auth.md).

² `claude-cli` shells out to a locally installed Claude Code CLI (`claude -p`), which
uses your own Claude Pro/Max subscription. Anthropic prohibits and blocks
third-party use of subscription OAuth tokens directly, so this is the supported way
to drive a Claude subscription from skuggi; for an API key, use `anthropic`.

## Status & legal

- **Early development.** skuggi is pre-1.0 and under active development. Interfaces,
  config formats, the ledger schema and the engagement boundary may change without
  notice, and bugs are expected. Do not treat the engagement guard as your only
  safeguard for staying in scope — review every proposed command yourself.
- **Authorized use only.** skuggi proposes, and in autonomous mode runs, real
  offensive-security tooling. Use it only against systems you own or are explicitly
  authorized in writing to test. You, the operator, are solely responsible for
  staying within your engagement scope and all applicable law.
- **No warranty, no liability.** skuggi is provided "as is", without warranty of any
  kind. The authors accept no liability for any damage, data loss, cost, legal
  consequence or misuse arising from its use. See [LICENSE](LICENSE).

## Install

Requires Python ≥3.12 and [uv](https://docs.astral.sh/uv/) (developed on 3.14; CI
covers 3.12–3.14).

Clone the repo to a **permanent** location — not a temp directory — then install
from it:

```sh
git clone <repo-url> ~/dev/skuggi     # keep this checkout; see the note below
cd ~/dev/skuggi
make install-cli
```

That installs `skuggi` (and every `skuggi-*` command) onto your `$PATH`, puts uv's
bin directory on `$PATH` if it is not already there, and seeds the harness config.
**Open a new shell**, then check it:

```sh
command -v skuggi        # → ~/.local/bin/skuggi
skuggi-doctor            # → the install table: both homes, config files, tools
```

If `skuggi: command not found` persists, uv's bin directory is not on your `$PATH`;
add it and reopen the shell:

```sh
export PATH="$HOME/.local/bin:$PATH"     # `uv tool dir --bin` prints the directory
```

Then give it a credential. The simplest path is to start skuggi (it boots with or
without a provider) and run the guided setup, which writes the key for you at mode
0600:

```sh
skuggi
/skuggi set provider            # pick a provider; writes the key / runs OAuth
```

Or set one by hand — any of these:

```sh
printf 'ANTHROPIC_API_KEY=sk-ant-...\n' > ~/.config/skuggi/env && chmod 600 ~/.config/skuggi/env
export ANTHROPIC_API_KEY=sk-ant-...      # or just export it from your shell rc
/skuggi login                            # ChatGPT-account OAuth (also: skuggi-login)
```

Now `skuggi` runs **from any directory**. Its config and databases live in two fixed
homes, so every invocation reads the same harness (see
[Configuration](#configuration-and-storage)); only the engagement workspace is
relative to where you are, because that is where the client's data belongs.

To start an engagement, point skuggi at a directory — that directory *is* the
engagement (its `scope.json`, ledger, recon output and reports live inside it):

```sh
mkdir -p ~/work/acme-2026 && cd ~/work/acme-2026
skuggi
/skuggi set engagement          # adopt the current directory (scaffolds a scope.json)
/skuggi engagement setup        # fill the scope in with the wizard
```

`set engagement <path>` adopts (and, if needed, creates + scaffolds) another
directory instead of the current one. With no engagement — no `scope.json` in the
current directory and no `SKUGGI_ENGAGEMENT_ROOT` override — skuggi runs agent-only
(no scope, no ledger). The adopted root is session-scoped and is not persisted; a
restart re-discovers it by probing the current directory.

Installing from an existing checkout moves any `configs/` and `data/` you already
had into the two homes, once — that state is gitignored, so it is not left behind.
It is a move, not a copy, so there is only ever one live copy of each database. For
the full story, and for troubleshooting, see [docs/install.md](docs/install.md).

## Usage

```sh
skuggi                 # the native shell wrapper (🐐 prompt), from anywhere
```

Inside the wrapped shell your normal commands run natively; `/skuggi <verb>` reaches
the agent:

```
🐐 ~ %  ls                              # your real shell, native colours
🐐 ~ %  /skuggi ask scan the web host   # → agent proposes an in-scope command
🐐 ~ %  /skuggi cmd nmap                # → search the cheatsheet; `cmd nmap-host` resolves one
🐐 ~ %  /skuggi show findings           # → harness control (inspect state)
🐐 ~ %  /skuggi                         # → open the chat loop (blank line leaves)
🐐 ~ %  /skuggi exit                    # → leave the harness
```

For the pure agent chat instead:

```sh
skuggi-repl            # or: python -m skuggi
```

```
> what is exposed on the target?     # bare text is an implicit `ask`
> /set provider anthropic
> /ingest docs
> /quit
```

## The verb grammar

The first word after `/skuggi` (or after `/` in `skuggi-repl`) is the **verb**; the
rest is its input. Four **grouping verbs** take a *noun* and route on it:

- `show <what>` — inspect state (`show findings`, `show engagement`, `show tools`, …)
- `set <what>` — change config / session state (`set mode redteam`, `set provider`,
  `set autonomous on`, `set target <host>`, …)
- `add <what>` — record engagement data (`add note`, `add loot`, `add finding`, …)
- `remove <what>` — delete records (`remove memory <id>`, …)

Plain verbs include `ask`, `cmd`, `osint`, `research`, `forensics`, `engagement`,
`findings`, `report`, `visualize`, `replay`, `review`, `doctor`, `login`, `ingest`,
`update`, `reconcile`, `help`, `exit`. `help` (or `help <verb>`) always lists what
is available in the current mode.

**The full verb/noun reference, the `cmd` command cheatsheet, and operator memory
are in [docs/usage.md](docs/usage.md).** In short:

- **`cmd`** (offensive modes) is a searchable cheatsheet of real CLI invocations
  (nmap, gobuster, sqlmap, …): `cmd <query>` searches it; `cmd <name>` renders one,
  prints the full command, scope-checks it and advises — it never executes.
- **memory** is the harness's durable record of how *you* like to work, injected
  into every turn. `add memory <text>` / `show memory` / `remove memory <id>`, plus
  an opt-in post-turn auto-capture that previews and asks before writing.

## The engagement boundary

The authorized scope for one engagement is its workspace's `scope.json` (template:
[src/skuggi/templates/scope.example.json](src/skuggi/templates/scope.example.json)),
loaded at start and never committed. Every command the agent proposes is parsed and
checked by a single guard (`check_command` in
[src/skuggi/engagement/guard.py](src/skuggi/engagement/guard.py)): exclusions deny
first, then the tool must be recognized and authorized, its method and (if scoped)
its ports allowed, the time inside the authorized windows, and every target inside
an allowed network/host. The rule is conservative — anything it cannot prove in
scope is denied.

Commands **suggest by default** (recorded `proposed` for you to run by hand). In
**autonomous mode** (`set autonomous on`, or `"autonomous": true`) the agent runs
in-scope commands itself — but only up to a **risk ceiling**: a command above
`autonomous_ceiling` is still held `proposed`. An agent-cleared command runs through
the host subprocess by default, or an isolated **container** backend
(`execution_backend: container`). The scope wizard (`engagement setup`), the full
field reference, the workspace tree and the forensics case plane are documented in
[docs/engagement.md](docs/engagement.md).

## Keeping secrets out of the model

skuggi feeds command output, retrieved documents and prior findings back to the
model, so a deterministic boundary ([src/skuggi/security/](src/skuggi/security/))
scrubs secrets and PII out of every model-bound request first — no model, no network,
just rule-based detectors. A discovered secret becomes a reversible `«KIND:id»`
placeholder backed by a per-engagement 0600 vault; the model reasons over the
placeholder, and the harness rehydrates the real value into the argv *just before
the tool runs*. Sensitive inputs (wordlists, credential lists) live as files under
`inputs/`; the agent sees only a metadata inventory and points a tool at one *by
path*. An egress tripwire re-scans the whole assembled request as a hard gate. The
full model: [docs/architecture.md](docs/architecture.md#the-data-plane-boundary).

## OSINT and research

Two autonomous intelligence loops run alongside the main turn graph:

- **`osint`** (offensive modes) — engagement-scoped reconnaissance over *subjects*
  (orgs, apex domains, people, GitHub orgs). It runs only when the scope has an
  `osint` block, and a dedicated OSINT guard denies any out-of-scope subject or
  disabled source.
- **`research`** — engagement-independent public-source research (CVEs, exploits,
  end-of-life/version data). Report-only; writes a briefing, no ledger findings.

Both are built on a shared `intel/` core and respect the same redaction boundary.
See [docs/osint-research.md](docs/osint-research.md).

## Modes

`set mode pentest|redteam|blueteam` swaps the planner/worker/critic prompt set; the
graph and guard are identical across the three. Set the default with `SKUGGI_MODE`.
`set mode forensics` is different — a strictly read-only, engagement-free discipline
bound to a **case** (`set case <path>`) with its own `case.db` ledger, an in-process
analyzer battery (strings, hexdump, entropy, magic, encoding, log parsing, OCR, AI
vision) and a chain-of-custody log. Offensive verbs drop out of forensics mode. See
[docs/engagement.md](docs/engagement.md#modes).

## Tools and `skuggi-doctor`

Recognized tools live in the JSON registry
([src/skuggi/templates/tools.example.json](src/skuggi/templates/tools.example.json)):
each tool's binary, its engagement method, how to read its version, which flags
carry targets/ports, and per-installer install commands. `skuggi-doctor` (or
`/skuggi doctor`) probes the host `PATH` and/or a skuggi-managed venv (per
`SKUGGI_TOOL_SOURCE=host|managed|combine`), captures versions, and reports what is
missing with install hints filtered to the package managers present on this host. It
also reports the standard runtimes/toolchains and net tools an operator relies on.
`doctor install <tool>` installs a missing one — issuing the subcommand is the
confirmation.

## Findings, the ledger and reports

The harness persists to a per-engagement SQLite **ledger**
([src/skuggi/persistence/ledger.py](src/skuggi/persistence/ledger.py), `<engagement
root>/ledger.db`), separate from the checkpointer, with an `events` timeline plus
`commands`, `findings` and the engagement-data tables. A finding links to its
session and source command, so it is always traceable. The timeline is
**hash-chained** for tamper-evidence (`show integrity` verifies it).

Findings are **scored, not guessed**: the agent proposes a CVSS v3.1 vector,
`skuggi.frameworks.cvss` computes the score deterministically, and findings can carry
WSTG/ATT&CK classification ids from a vendored, offline snapshot. Every finding is
born `draft`; only **approved** findings reach a report (`findings approve|reject`).
`/skuggi report` writes a revisioned Markdown report (add `pdf` for a styled PDF);
`/skuggi visualize` builds an interactive HTML dashboard. The full lifecycle, CVSS,
threat model and PDF pipeline: [docs/findings-and-reports.md](docs/findings-and-reports.md).

## Configuration and storage

skuggi follows the **XDG Base Directory** convention, seeded by `skuggi-init`.
Editable config lives under `~/.config/skuggi` (`config.json`, `tools.json`,
`layout.json`, `commands.json`, `env`); regenerable state lives under
`~/.local/share/skuggi` (`sessions.db`, `preferences.db`, `faiss_index/`, `toolbox/`,
`logs/`). Both honour the standard `XDG_*` variables, each with a `SKUGGI_*` override
in front of it. **The engagement root is the one deliberate exception** — it stays
relative to your working directory, because a workspace is about *a case*, not about
*you*.

Values resolve env → `<config home>/env` → `config.json` → defaults, so a one-off
`SKUGGI_PROVIDER=anthropic` wins for a single run. Secrets never go in `config.json`
(the JSON source drops them); they come from the environment, `env`, or
`~/.codex/auth.json`. `set config` edits the app config in place. The full key
surface, the homes, and the storage layout: [docs/configuration.md](docs/configuration.md).

## Entry points

- `skuggi` — the native shell wrapper (warm agent daemon + your real `$SHELL`)
- `skuggi-repl` — the pure agent REPL
- `skuggi-init` — create the config/data homes and seed them from the templates
- `skuggi-doctor` — probe the host for the registry's tools and report
- `skuggi-ingest` — index files/directories into the FAISS store
- `skuggi-login` — ChatGPT-account OAuth login for the `chatgpt` provider
- `skuggi-pdf` — render a Markdown file to a styled PDF (needs the `pdf` extra)
- `skuggi-visualize` — render the engagement dashboard HTML
- `skuggi-eval` — the local eval system (see [docs/testing.md](docs/testing.md))
- `skuggi-client` — the thin client the shell's `/skuggi` hook calls (not run
  directly)

## Development

```sh
make install     # uv sync --all-groups --all-extras, plus the git hooks
make install-cli # put `skuggi` on $PATH (editable) and seed the homes
make check       # ruff format --check, ruff, file-size cap, mypy --strict, pytest — what CI runs
make eval        # the real-provider layer; costs money, needs credentials
make e2e         # the real pipeline against the frozen e2e fixture target (bring it up first)
make lab-list    # the user-facing practice range (labs/): 10 tiered engagements
make eval-det    # the deterministic eval gate, offline (also inside `make check`)
make bench       # the full eval benchmark across providers; costs money
```

`make check` is the gate. The test suite is five layers, three of them offline;
`make eval` (real providers) and `make e2e` (the frozen [e2e fixture
target](docs/e2e-fixture.md)) are opt-in — see [docs/testing.md](docs/testing.md). A
committed, local-only **eval system** (`skuggi-eval`) scores the agent across seven
dimensions — four deterministic (`compliance`, `methodology`, `schema`,
`result_compat`) and three quality (`factuality`, `budget`, `latency`) — and
hard-gates on regression against [evals/baseline.json](evals/baseline.json); see
[evals/README.md](evals/README.md).

## Further reading

- [docs/usage.md](docs/usage.md) — the full verb/noun grammar, the `cmd` cheatsheet,
  and operator memory.
- [docs/engagement.md](docs/engagement.md) — the scope boundary, the guard, the setup
  wizard, autonomy (risk ceiling + container backend), the workspace, and modes.
- [docs/configuration.md](docs/configuration.md) — the two homes, resolution
  precedence, the config-key surface, and the storage layout.
- [docs/findings-and-reports.md](docs/findings-and-reports.md) — the ledger and its
  tamper-evidence, the finding lifecycle, deterministic CVSS, and the report/PDF
  pipeline.
- [docs/osint-research.md](docs/osint-research.md) — the autonomous OSINT and research
  loops and their configuration.
- [docs/install.md](docs/install.md) — installing the `skuggi` command, the two
  homes, how `update` behaves per install shape, and troubleshooting.
- [docs/architecture.md](docs/architecture.md) — the agent graph, state channels,
  persistence, and the data-plane boundary.
- [docs/frontend.md](docs/frontend.md) — the shell wrapper, socket dispatch, and the
  attach protocol.
- [docs/codex-auth.md](docs/codex-auth.md) — the `openai` / `chatgpt` providers,
  `~/.codex/auth.json`, OAuth refresh, and the model-name gotcha.
- [docs/audit-llm-vs-mechanism.md](docs/audit-llm-vs-mechanism.md) — why severity
  (CVSS) and finding classification (WSTG/ATT&CK) are deterministic code, not LLM
  judgement.
- [docs/testing.md](docs/testing.md) — the test layers and the eval system.
- [docs/labs.md](docs/labs.md) — the practice range: 10 tiered engagement exercises
  (`labs/`) with planted loot, and the `labctl` wipe/restore workflow.
- [docs/e2e-fixture.md](docs/e2e-fixture.md) — the frozen e2e fixture target that the
  L5 suite drives, and its pinned oracles.

## License

skuggi is released under the [MIT License](LICENSE) — © 2026 Jan Schupke.

## Contributing

Contributions are welcome.

- **Found a bug, or want to propose a change?** Open a GitHub issue first, so the
  problem or feature can be discussed before code is written.
- **Sending code?** Fork the repo, create a topic branch, and make `make check` green
  (the full gate — `ruff format --check`, `ruff`, `mypy --strict`, `pytest`; see
  [Development](#development)). Then open a pull request against `master` that
  references the issue. Keep each PR focused, and describe the mechanism and the
  reasoning in the body, matching the existing commit style (`git log`).
