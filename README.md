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
START → planner → worker → critic ─┬─ APPROVED   → END
                                   ├─ max revs   → END
                                   └─ else → bump → planner
```

- **planner** — reads the latest user message and any prior critique, emits a
  short numbered plan into `state["plan"]`.
- **worker** — binds the tools (`retrieve`, `calculator`, `file_read`) and
  iterates a tool-calling loop until it produces a draft. With
  `provider=chatgpt`, tools are skipped and the worker generates directly.
- **critic** — replies `APPROVED: <reason>` or `REVISE: <issue>`. The edge
  function routes back through a `bump` node (which increments
  `revision_count`) until the critic approves or `max_revisions` is hit.

State (`src/skuggi/state.py`):

```python
class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    plan: str | None
    draft: str | None
    critique: str | None
    revision_count: int
    max_revisions: int
```

Persistence: every node update is checkpointed by
`langgraph.checkpoint.sqlite.SqliteSaver` into `./data/sessions.db`, keyed by
the current thread id. Killing the process and resuming a thread with
`/thread <id>` restores the full message history.

## Standalone modules

Two files were designed to be read top-to-bottom in one sitting:

- [src/skuggi/memory.py](src/skuggi/memory.py) — `SqliteSaver` wrapper plus a
  raw-sqlite `list_threads` helper. ~50 LoC.
- [src/skuggi/vectorstore.py](src/skuggi/vectorstore.py) — `load_or_create` /
  `ingest_paths` / `persist` over `langchain_community.vectorstores.FAISS`
  with a `RecursiveCharacterTextSplitter`. ~60 LoC.

A third self-contained module:

- [src/skuggi/codex_chat.py](src/skuggi/codex_chat.py) — a
  `CodexChatModel(BaseChatModel)` that speaks the codex ChatGPT-account
  Responses API directly, handles OAuth refresh, and parses SSE. ~200 LoC.

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

## Storage layout

- `./data/sessions.db` — LangGraph SqliteSaver checkpoint store
- `./data/faiss_index/` — FAISS index (`index.faiss` + `index.pkl`)
- `./data/.repl_history` — prompt_toolkit input history
- `./docs/*.md` — your knowledge base (you create this)

## Known limitations

- The `chatgpt` provider does not bind LangChain tools (see the table above).
- The Codex Responses API event schema may change; this scaffold parses the
  event types we know about (`response.output_text.delta`,
  `response.completed`). Other events are ignored. If you see no streaming
  output, run with `SKUGGI_PROVIDER=openai` to confirm the rest of the
  pipeline works, then check the codex source for new event names.
- `text-embedding-3-small` (OpenAI) is the default embedding model and
  requires an OpenAI key. Without one, `providers.get_embeddings()` falls back
  to `OllamaEmbeddings("nomic-embed-text")` if Ollama is running.
