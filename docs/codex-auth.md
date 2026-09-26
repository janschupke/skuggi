# Codex auth (the `openai` and `chatgpt` providers)

`~/.codex/auth.json` is written by the OpenAI `codex` CLI after `codex login`.
It can be in one of two shapes.

## API-key mode (`openai` provider)

After `codex login --with-api-key`:

```json
{ "OPENAI_API_KEY": "sk-...", "auth_mode": "ApiKey", ... }
```

The `openai` provider reads this and routes through `api.openai.com` via
`langchain_openai.ChatOpenAI`. A plain `$OPENAI_API_KEY` in the environment
works too.

## ChatGPT-account mode (`chatgpt` provider)

After the browser-based ChatGPT login:

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

These tokens **do not** authenticate against `api.openai.com`. They route to
`https://chatgpt.com/backend-api/codex/responses` with the codex-specific
`x-codex-*` headers. Use the `chatgpt` provider — a thin `ChatOpenAI` subclass
over that endpoint ([src/skuggi/codex_chat.py](../src/skuggi/codex_chat.py))
that:

- reads the tokens from auth.json (`CodexTokenStore`);
- shapes the Responses body the way codex expects (`instructions` rather than a
  system entry in `input`; explicit `store`/`tools`/`tool_choice`);
- on a 401 (or near-expiry id_token) POSTs an OAuth2 refresh to
  `https://auth.openai.com/oauth/token` with the codex client_id, writes the new
  tokens back to auth.json at mode 0600, and replays the request (`CodexAuth`).

This provider has no native structured output, so `protocol.structured_invoke`
falls back to a JSON contract (with one repair retry) instead of
`with_structured_output` here — see `Settings.supports_structured_output()`.
Retrieval reaches every provider through the graph's `retriever` node.

## The model-name gotcha

This endpoint accepts only *current* model names, and the error it gives for
anything else is misleading:

```
400 {"detail": "The 'gpt-5-codex' model is not supported when using Codex
     with a ChatGPT account."}
```

That reads like an account-entitlement problem. It is not: every `gpt-*-codex`
name is refused this way, while the current general model works fine. If you see
it, set `SKUGGI_MODEL_CHATGPT` to a current model rather than checking your plan.
A 404 (rather than a 400) means the route is wrong.

If the `chatgpt` path stops working after an `OAuth refresh failed` error, run
`codex login` again.

## Notes

- The two endpoint URLs are configurable via `SKUGGI_CODEX_RESPONSES_BASE` /
  `SKUGGI_CODEX_REFRESH_URL` (rarely needed); their defaults live once in
  [config.py](../src/skuggi/config.py).
- Embeddings default to `text-embedding-3-small` (OpenAI) and need an OpenAI
  key; without one, `get_embeddings` falls back to
  `OllamaEmbeddings("nomic-embed-text")` if Ollama is running.
- `langchain-community` supplies the FAISS vector store and is sunset-announced
  upstream, but still ships alongside langchain-core 1.x with no standalone
  replacement yet, so it stays (its deprecation warning is ignored by name in
  `pyproject.toml`).
