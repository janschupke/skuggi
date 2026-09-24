# skuggi

A locally-hosted **pentesting harness** prototype, built on a LangChain +
LangGraph agent substrate: a multi-node `planner → worker → critic` graph,
SQLite-backed session history, FAISS retrieval, and a Rich + prompt_toolkit TUI.
You drive an engagement through skuggi; it evaluates each request and either
advises, **proposes a shell command** (gated by a strict engagement boundary),
or summarizes. Findings and commands are persisted to a file DB, traceable back
to the command that produced them, and exportable as Markdown reports.

See **[The pentest harness](#the-pentest-harness)** for modes, the engagement
boundary, `run_command`, the tool registry / `skuggi-doctor`, findings and
reports, and the shell wrapper. The sections after it document the agent
substrate the harness is built on.

Four LLM providers, switchable at runtime:

| Provider   | Auth path                                                      | Tools? |
|------------|----------------------------------------------------------------|--------|
| `openai`   | `~/.codex/auth.json` (`OPENAI_API_KEY`) → `$OPENAI_API_KEY`    | yes    |
| `chatgpt`  | `~/.codex/auth.json` (`tokens.access_token`, OAuth refresh)    | no¹    |
| `anthropic`| `$ANTHROPIC_API_KEY`                                           | yes    |
| `ollama`   | `$OLLAMA_BASE_URL` (default `http://localhost:11434`)          | yes    |

¹ The ChatGPT-account endpoint uses a codex-specific tool schema; we run the
  worker as a plain generator in that mode. See the "Codex auth" section.

## Quickstart

Requires Python >=3.12 and [uv](https://docs.astral.sh/uv/). Developed on
3.14; CI covers 3.12, 3.13 and 3.14. Exact versions come from `uv.lock`.

```sh
uv sync --all-groups
cp .env.example .env
# edit .env: set ANTHROPIC_API_KEY (easiest) or arrange OpenAI auth (below)
uv run skuggi
```

`python -m skuggi` also works once the package is installed.

In the REPL:

```
> What is 17 * 23?
> /provider anthropic
> /model claude-sonnet-4-5-20250929
> /ingest docs
> Who is the skuggi mascot?
> /thread list
> /quit
```

## Slash commands

| Command                                       | Effect                                            |
|-----------------------------------------------|---------------------------------------------------|
| `/help`                                       | Command reference                                 |
| `/provider <openai\|chatgpt\|anthropic\|ollama>` | Switch LLM provider, recompile graph            |
| `/model <name>`                               | Switch model on the current provider              |
| `/thread new`                                 | Start a fresh thread (uuid4)                      |
| `/thread list`                                | List thread ids stored in `sessions.db`           |
| `/thread <id>`                                | Resume a prior thread (state loaded by `SqliteSaver`) |
| `/history [n]`                                | Show the last `n` messages on the current thread  |
| `/mode <pentest\|redteam\|blueteam>`          | Switch operating mode (swaps the prompt set)      |
| `/engagement`                                 | Show the loaded engagement scope                  |
| `/doctor [install <tool>]`                    | Probe host tools; install a missing one on request |
| `/findings`                                   | List findings recorded this session               |
| `/report`                                     | Write a Markdown engagement report                |
| `/autonomous [on\|off]`                       | Toggle autonomous command execution               |
| `/clear`                                      | Clear the screen                                  |
| `/ingest <path>`                              | Index a file or directory of `*.md` / `*.txt`     |
| `/quit` / `/exit`                             | Close cleanly                                     |

Anything not starting with `/` is sent to the agent.

## The pentest harness

skuggi layers pentest concerns onto the agent graph below rather than forking
it. The worker gets two extra bounded tools -- `run_command` and
`record_finding` -- and everything they do passes through one guard.

### Modes

`/mode pentest|redteam|blueteam` swaps the planner/worker/critic prompt set
([src/skuggi/modes.py](src/skuggi/modes.py)); the graph, tools and guard are
identical across modes. Set the default with `SKUGGI_MODE`.

### The engagement boundary

The authorized scope for one engagement is a JSON *case file*
([configs/engagement.example.json](configs/engagement.example.json)), loaded at
start and never committed (real files are gitignored; only `.example` templates
are tracked):

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

Every command the agent proposes is parsed and checked against this by the
single guard `check_command` ([src/skuggi/engagement.py](src/skuggi/engagement.py)),
in order: recognized tool → authorized tool → authorized method → inside the
date window → inside the daily clock window → every extracted target inside an
allowed network/host. The rule is conservative: a target-requiring command with
no in-scope target is denied, and anything the guard cannot prove in scope is
denied. This mirrors the tool layer's discipline (*"every bound exists because
the model supplies the arguments"*) -- `parse_command` is the analogue of
`file_read`'s `_resolve_within`.

### run_command: suggest by default, autonomous on request

`run_command` never runs a blocked command. For an in-scope command:

- **suggest mode (default)** — it records the command as `proposed` and hands it
  back for you to run manually. This is `autonomous: false`.
- **autonomous mode** — enabled only by `autonomous: true` in the case file or
  `/autonomous on`, it executes the command (`shell=False`, argv exec'd
  directly, output byte-capped, wall-clock timeout) and records the captured
  result. The prompt shows a `!` and the banner shows `autonomous ON` while it
  is armed.

Blocked, proposed and executed commands are all persisted with timestamps.

### The tool registry and `skuggi-doctor`

Recognized tools live in a JSON registry
([configs/tools.example.json](configs/tools.example.json)): each tool's binary,
its engagement method, how to read its version, which flags carry targets, and
per-installer install commands. `skuggi-doctor` (or `/doctor`) probes the host
`PATH` and/or a skuggi-managed venv (per `SKUGGI_TOOL_SOURCE=host|managed|combine`),
captures versions, and reports what is missing with install hints.
`/doctor install <tool>` installs a missing one -- issuing the subcommand is the
confirmation; a pip tool goes into the managed venv, a system tool through the
detected OS package manager.

### Findings, the ledger and reports

The harness persists to its own SQLite **ledger**
([src/skuggi/ledger.py](src/skuggi/ledger.py), `./data/ledger.db`) -- separate
from the checkpointer -- with `sessions`, `commands` and `findings` tables. A
finding links to its session and, by default, to the most recent command, so it
is always traceable to the command and payload that produced it. `/report`
writes a Markdown report (`./data/reports/<engagement>-<session>-<ts>.md`) with
the scope, findings grouped by severity, and the timestamped command log.

### Shell wrapper (`skuggi-shell`)

`skuggi-shell` runs your `$SHELL` inside a pseudo-terminal, so its normal
coloured, prompted output is preserved verbatim; the prompt is prefixed with 🛡️
to mark that skuggi is active. A line beginning with `/skuggi ` is intercepted
and routed to the agent or a harness command; everything else passes through to
the shell and is logged to the ledger. Feasibility note: boundary *enforcement*
applies to agent-proposed commands (`run_command`); operator free-typed commands
in the wrapped shell are logged but not vetoed, because pre-exec interception of
a live interactive shell is not reliable across shells. The emoji-prompt
injection is best-effort per shell family (bash/zsh) and degrades otherwise.

## The graph

```
START → planner → retriever → worker ──┬── tools ──┐
                                       │           │ (loops back to worker)
                                       └── finalize ┴─→ critic ─┬─ APPROVED → respond → END
                                                                ├─ max revs → respond → END
                                                                └─ else → bump → planner
```

- **planner** — reads the conversation so far, the latest request and any prior
  critique, and emits a short numbered plan. It also resets the worker's
  scratch channel for this pass.
- **retriever** — for providers that *cannot* bind tools, inlines a top-k
  snippet into `state["context"]`. A no-op when tools are available, since the
  `retrieve` tool covers that case.
- **worker → tools → worker** — a real graph cycle, bounded by
  `max_tool_rounds`. Every intermediate assistant message and tool result is
  checkpointed, so a crash mid-loop is resumable and `/trace` can show the
  trail.
- **critic** — replies `APPROVED: <reason>` or `REVISE: <issue>`; anything that
  is not an approval is treated as a revision request.
- **respond** — the only node that writes to `messages`, so a revised turn
  leaves exactly one answer in the conversation rather than one per pass.

State (`src/skuggi/state.py`) has two message channels, deliberately separate:

```python
class _MessageChannels(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]  # the conversation
    scratch: Annotated[list[BaseMessage], add_messages]  # the worker's tool loop


class AgentState(_MessageChannels, total=False):
    plan: str
    context: str
    draft: str
    critique: str
    revision_count: int
    max_revisions: int
    tool_rounds: int
```

`messages` is what `/history` prints and what the planner and critic read as
context. `scratch` holds the worker's own prompt scaffolding and tool traffic --
kept apart because a seeded `HumanMessage` is otherwise indistinguishable from a
real user turn.

Persistence: every node update is checkpointed by
`langgraph.checkpoint.sqlite.SqliteSaver` into `./data/sessions.db`, keyed by
the current thread id. Killing the process and resuming a thread with
`/thread <id>` restores the full message history -- and, unlike earlier
versions, the agent actually reads it.

## Standalone modules

Files that can be read top-to-bottom in one sitting:

- [src/skuggi/config.py](src/skuggi/config.py) — every setting, in one typed
  `pydantic-settings` object.
- [src/skuggi/memory.py](src/skuggi/memory.py) — a `SqliteSaver` wrapper and
  thread enumeration through the checkpointer's own `list` API.
- [src/skuggi/vectorstore.py](src/skuggi/vectorstore.py) — a lazily-loaded FAISS
  index; nothing is embedded until the first `ingest`, so the TUI boots without
  embedding credentials.
- [src/skuggi/codex_chat.py](src/skuggi/codex_chat.py) — a `CodexTokenStore`
  (auth.json and the OAuth refresh) and a `CodexAuth` (`httpx.Auth`) under a
  thin `ChatOpenAI` subclass. The SDK owns SSE framing, streaming and retries.

## Codex auth (the `openai` and `chatgpt` providers)

`~/.codex/auth.json` is written by the OpenAI `codex` CLI after `codex login`.
It can be in one of two shapes:

1. After `codex login --with-api-key`:
   ```json
   { "OPENAI_API_KEY": "sk-...", "auth_mode": "ApiKey", ... }
   ```
   The `openai` provider reads this and routes through `api.openai.com` via
   `langchain_openai.ChatOpenAI`.

2. After the browser-based ChatGPT login:
   ```json
   {
     "auth_mode": "ChatGPT",
     "tokens": {
       "access_token": "...", "refresh_token": "...",
       "id_token": "...", "account_id": "..."
     },
     ...
   }
   ```
   These tokens **do not** authenticate against `api.openai.com`. They route
   to `https://chatgpt.com/backend-api/codex/responses` with the
   codex-specific `x-codex-*` headers. Use the `chatgpt` provider, which is a
   thin `ChatOpenAI` subclass over that endpoint and:
   - reads the tokens from auth.json (`CodexTokenStore`),
   - shapes the Responses body the way codex expects (`instructions` rather
     than a system entry in `input`; explicit `store`/`tools`/`tool_choice`),
   - on a 401 (or near-expiry id_token) POSTs an OAuth2 refresh to
     `https://auth.openai.com/oauth/token` with the codex client_id, writes the
     new tokens back to auth.json at mode 0600, and replays the request
     (`CodexAuth`).

   **Model names.** This endpoint accepts only *current* model names, and the
   error it gives for anything else is misleading:

   ```
   400 {"detail": "The 'gpt-5-codex' model is not supported when using Codex
        with a ChatGPT account."}
   ```

   That reads like an account-entitlement problem. It is not. Every
   `gpt-*-codex` name is refused this way -- `gpt-5-codex`, `gpt-5.1-codex`,
   `gpt-5.1-codex-max`, `gpt-5.1-codex-mini`, `gpt-5.2-codex`,
   `gpt-5.3-codex` -- while the current general model works fine. If you see
   this, set `SKUGGI_MODEL_CHATGPT` to a current model rather than going
   looking at your plan. A 404 instead of a 400 means the route is wrong.

If the `chatgpt` path stops working after an `OAuth refresh failed` error,
run `codex login` again.

## Development

```sh
make install     # uv sync --all-groups, plus the git hooks
make check       # ruff format --check, ruff, mypy --strict, pytest -- what CI runs
make eval        # the real-provider layer; costs money, needs credentials
```

`make check` is the gate. It uses `ruff format --check` and never the rewriting
formatter, because a target that rewrites files can never fail and so can never
gate anything; `make format` is the one that fixes things.

The test suite is four layers, three of them offline -- see
[docs/testing.md](docs/testing.md). CI runs lint, format and types once on 3.12
and the suite on 3.12, 3.13 and 3.14.

## Storage layout

- `./configs/*.json` — engagement + tool-registry case files (gitignored; only
  the `.example` templates are committed)
- `./data/ledger.db` — the harness's SQLite ledger (sessions, commands, findings)
- `./data/reports/*.md` — generated Markdown engagement reports
- `./data/toolbox/` — the managed tool venv (`SKUGGI_TOOL_SOURCE=managed|combine`)
- `./data/sessions.db` — LangGraph SqliteSaver checkpoint store
- `./data/faiss_index/` — FAISS index (`index.faiss` + `index.pkl`)
- `./data/.repl_history` — prompt_toolkit input history
- `./docs/*.md` — your knowledge base (you create this)

## Entry points

- `skuggi` — the REPL
- `skuggi-doctor` — probe the host for the registry's tools and report
- `skuggi-shell` — the PTY-backed wrapped shell
- `skuggi-ingest` — index files/directories into the FAISS store

## Known limitations

- The `chatgpt` provider does not bind LangChain tools (see the table above).
  It gets retrieval through the `retriever` node instead.
- The `chatgpt` provider needs a model your ChatGPT plan licenses for Codex;
  see the Codex auth section for how to tell that apart from a routing error.
- `text-embedding-3-small` (OpenAI) is the default embedding model and requires
  an OpenAI key. Without one, `get_embeddings` falls back to
  `OllamaEmbeddings("nomic-embed-text")` if Ollama is running.
- `langchain-community` supplies the FAISS vector store and is
  sunset-announced upstream. It is still released alongside langchain-core 1.x
  and there is no official standalone replacement yet, so it stays, with the
  deprecation warning ignored by name in `pyproject.toml`.
