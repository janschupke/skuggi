# LLM providers

Four providers, switchable at runtime, built in `providers/`. Auth details:
[docs/codex-auth.md](../../docs/codex-auth.md).

| Provider    | Auth                                            | Structured output |
|-------------|-------------------------------------------------|-------------------|
| `openai`    | `~/.codex/auth.json` or `$OPENAI_API_KEY`       | native            |
| `chatgpt`   | `~/.codex/auth.json` ChatGPT-account OAuth      | JSON fallback     |
| `anthropic` | `$ANTHROPIC_API_KEY`                            | native            |
| `ollama`    | `$OLLAMA_BASE_URL`                              | native            |

## Rules

- **The OpenAI SDK is heavy — keep it out of the core import graph.**
  `providers.providers`→`codex_chat` and `agent.core`→`providers.codex_login`
  are lazy on purpose; the REPL must boot without embedding/chat credentials.
- **`providers.py` is the one factory** for both the chat model and embeddings.
  A new provider is added there, not at a call site.
- **`chatgpt` has no native structured output** — it must keep going through the
  JSON contract + repair retry (see [protocol.md](protocol.md)). Don't assume
  `with_structured_output`.
- Dependency bounds in `pyproject.toml` are capped at the next major on purpose
  (a breaking bump should be a resolver error, not a silent break).
