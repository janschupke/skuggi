# skuggi

A locally-hosted agent harness exercise. LangChain + LangGraph, a multi-node
`planner → worker → critic` graph, SQLite-backed session history, FAISS
embeddings, and a small Rich + prompt_toolkit TUI with slash commands.

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
| `/clear`                                      | Clear the screen                                  |
| `/ingest <path>`                              | Index a file or directory of `*.md` / `*.txt`     |
| `/quit` / `/exit`                             | Close cleanly                                     |

Anything not starting with `/` is sent to the agent.

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
    messages: Annotated[list[BaseMessage], add_messages]   # the conversation
    scratch:  Annotated[list[BaseMessage], add_messages]   # the worker's tool loop

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

   **Model entitlement.** This endpoint accepts only models your ChatGPT
   account is licensed for through Codex, and rejects ordinary chat model
   names outright:

   ```
   400 {"detail": "The 'gpt-5' model is not supported when using Codex
        with a ChatGPT account."}
   ```

   A 400 like that means auth succeeded and only the model is wrong -- set
   `SKUGGI_MODEL_CHATGPT` to one your plan includes. A 404 instead means the
   route is wrong.

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

- `./data/sessions.db` — LangGraph SqliteSaver checkpoint store
- `./data/faiss_index/` — FAISS index (`index.faiss` + `index.pkl`)
- `./data/.repl_history` — prompt_toolkit input history
- `./docs/*.md` — your knowledge base (you create this)

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
