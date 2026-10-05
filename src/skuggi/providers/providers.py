"""LLM and embeddings factory.

Provider routing:
    openai     -> init_chat_model("openai")      (api.openai.com)
    chatgpt    -> skuggi.codex_chat.CodexChatModel (ChatGPT-account OAuth)
    anthropic  -> init_chat_model("anthropic")   (Anthropic API key)
    claude-cli -> skuggi.claude_cli_chat.ClaudeCliChatModel (local `claude` binary)
    ollama     -> init_chat_model("ollama")

OpenAI key resolution order:
    1. top-level "OPENAI_API_KEY" in the codex auth.json
    2. the OPENAI_API_KEY environment variable (or .env)

A ChatGPT-account login writes ``tokens.{access_token,...}`` to auth.json
*without* a usable top-level OPENAI_API_KEY -- on such a file the key is present
but null, which is why the value is type-checked rather than just looked up.
Those tokens do not work against api.openai.com; use provider=chatgpt.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from langchain.chat_models import init_chat_model
from langchain_core.embeddings import Embeddings
from langchain_core.language_models import BaseChatModel

from skuggi.common.logs import get_logger
from skuggi.config.config import Provider, Settings
from skuggi.config.configs import ConfigError

log = get_logger(__name__)

# init_chat_model has no extension hook for a custom provider, so `chatgpt`
# stays a separate branch rather than joining this table.
_STANDARD_PROVIDERS: dict[Provider, str] = {
    "openai": "openai",
    "anthropic": "anthropic",
    "ollama": "ollama",
}

_NO_OPENAI_KEY = (
    "No OpenAI API key configured. Run `/setup` to add one (skuggi stores it in "
    "its own config, not your shell), or `/provider ollama` to use a local model."
)

# Shown at boot (as a warning) when no provider is credentialed. Descriptive
# only: the front-end appends a setup hint in its own command grammar (the
# wrapped shell, the chat loop and the REPL each invoke setup differently).
NO_MODEL_CONFIGURED = "no model provider configured"


def _key_from_auth_json(path: Path) -> str | None:
    """Read a usable top-level OPENAI_API_KEY out of a codex auth.json."""
    if not path.is_file():
        return None
    try:
        key = json.loads(path.read_text(encoding="utf-8")).get("OPENAI_API_KEY")
    except (OSError, json.JSONDecodeError) as exc:
        # A corrupt auth.json must not look identical to a missing key -- that is
        # the hardest credential problem to diagnose without a trace.
        log.warning("could not read a key from %s: %s", path, exc)
        return None
    if isinstance(key, str) and key.startswith("sk-"):
        return key
    return None


def resolve_openai_key(settings: Settings) -> str | None:
    """Resolve an OpenAI API key from auth.json, then the environment."""
    from_auth = _key_from_auth_json(settings.auth_json())
    if from_auth is not None:
        return from_auth
    if settings.openai_api_key is not None:
        return settings.openai_api_key.get_secret_value()
    return None


def is_configured(settings: Settings, provider: Provider) -> bool:
    """Whether `provider` has a usable credential (the readiness check).

    The single answer to "is this provider actually configured?", shared by the
    boot/readiness model and the doctor providers table so they cannot drift.
    ``ollama`` and ``claude-cli`` are local (no stored credential), so they are
    always considered configured.
    """
    if provider == "openai":
        return resolve_openai_key(settings) is not None
    if provider == "anthropic":
        return settings.anthropic_api_key is not None
    if provider == "chatgpt":
        # Lazy: reading the OAuth token store should not pull codex in at import.
        from skuggi.providers.codex_chat import CodexTokenStore  # noqa: PLC0415

        return CodexTokenStore(settings.auth_json()).is_logged_in()
    if provider == "claude-cli":
        # Lazy import: a which() check must not pull the provider module in at boot.
        from skuggi.providers.claude_cli_chat import is_available  # noqa: PLC0415

        return is_available()
    return True


def get_chat_model(settings: Settings, *, model: str | None = None) -> BaseChatModel:
    """Build the chat model for the configured provider.

    Credentials are checked here rather than at first invoke so that switching
    provider in the REPL reports a clear error instead of failing mid-stream.
    """
    provider = settings.provider
    name = model or settings.model_for(provider)

    if provider == "chatgpt":
        # Imported lazily: constructing a provider should not cost the import
        # of every other provider's SDK at startup.
        from skuggi.providers.codex_chat import build_codex_chat_model  # noqa: PLC0415

        return build_codex_chat_model(
            name,
            auth_path=settings.auth_json(),
            responses_base=settings.codex_responses_base,
            refresh_url=settings.codex_refresh_url,
            reasoning_effort=settings.reasoning_effort,
        )

    if provider == "claude-cli":
        # Shells out to the operator's local `claude` binary (their own Claude
        # subscription); lazy import keeps subprocess wiring off the hot path.
        from skuggi.providers.claude_cli_chat import (  # noqa: PLC0415
            build_claude_cli_chat_model,
        )

        return build_claude_cli_chat_model(name)

    kwargs: dict[str, Any] = {}
    if provider == "openai":
        key = resolve_openai_key(settings)
        if not key:
            raise ConfigError(_NO_OPENAI_KEY)
        kwargs = {"api_key": key, "streaming": True}
    elif provider == "anthropic":
        if settings.anthropic_api_key is None:
            msg = (
                "No Anthropic API key configured. Run `/setup` to add one, or "
                "`/provider ollama` to use a local model."
            )
            raise ConfigError(msg)
        kwargs = {
            "api_key": settings.anthropic_api_key.get_secret_value(),
            "streaming": True,
        }
    elif provider == "ollama":
        kwargs = {"base_url": settings.ollama_base_url}

    built = init_chat_model(
        name, model_provider=_STANDARD_PROVIDERS[provider], **kwargs
    )
    # init_chat_model's declared return includes a private configurable wrapper;
    # without configurable_fields it is always a concrete BaseChatModel.
    return cast("BaseChatModel", built)


def get_embeddings(settings: Settings) -> Embeddings:
    """Build embeddings, falling back to Ollama when there is no OpenAI key.

    The fallback is mandatory rather than cosmetic: the TUI must boot with no
    credentials, and the OpenAI embeddings client raises at construction.
    """
    key = resolve_openai_key(settings)
    if key:
        from langchain_openai import OpenAIEmbeddings  # noqa: PLC0415

        # api_key is OpenAIEmbeddings' documented (aliased) argument; the
        # pydantic mypy plugin synthesises __init__ from field names and so does
        # not know the alias exists.
        return OpenAIEmbeddings(
            model=settings.embedding_model,
            api_key=key,  # type: ignore[call-arg]
        )

    from langchain_ollama import OllamaEmbeddings  # noqa: PLC0415

    return OllamaEmbeddings(
        model=settings.embedding_model_ollama, base_url=settings.ollama_base_url
    )
