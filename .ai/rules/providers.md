# LLM providers

Five providers, switchable at runtime, built in `providers/`. Auth details:
[docs/codex-auth.md](../../docs/codex-auth.md).

| Provider     | Auth                                            | Structured output |
|--------------|-------------------------------------------------|-------------------|
| `openai`     | `~/.codex/auth.json` or `$OPENAI_API_KEY`       | native            |
| `chatgpt`    | `~/.codex/auth.json` ChatGPT-account OAuth      | JSON fallback     |
| `anthropic`  | `$ANTHROPIC_API_KEY`                            | native            |
| `claude-cli` | the local `claude` binary's own login           | JSON fallback     |
| `ollama`     | `$OLLAMA_BASE_URL`                              | native            |

## Rules

- **The OpenAI SDK is heavy — keep it out of the core import graph.**
  `providers.providers`→`codex_chat` and `agent.core`→`providers.codex_login`
  are lazy on purpose; the REPL must boot without embedding/chat credentials.
- **`providers.py` is the one factory** for both the chat model and embeddings.
  A new provider is added there, not at a call site.
- **`chatgpt` and `claude-cli` have no native structured output** — they must keep
  going through the JSON contract + repair retry (see [protocol.md](protocol.md)).
  Don't assume `with_structured_output` (`Settings.supports_structured_output()`).
- Dependency bounds in `pyproject.toml` are capped at the next major on purpose
  (a breaking bump should be a resolver error, not a silent break).
