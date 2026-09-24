"""LLM and embeddings factory.

Provider routing:
    openai    -> init_chat_model("openai")      (api.openai.com)
    chatgpt   -> skuggi.codex_chat.CodexChatModel (ChatGPT-account OAuth)
    anthropic -> init_chat_model("anthropic")
    ollama    -> init_chat_model("ollama")

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
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from langchain.chat_models import init_chat_model
from langchain_core.embeddings import Embeddings
from langchain_core.language_models import BaseChatModel

from skuggi.config import Provider, Settings

# init_chat_model has no extension hook for a custom provider, so `chatgpt`
# stays a separate branch rather than joining this table.
_STANDARD_PROVIDERS: dict[Provider, str] = {
    "openai": "openai",
    "anthropic": "anthropic",
    "ollama": "ollama",
}

_NO_OPENAI_KEY = (
    "No OpenAI API key found. Options:\n"
    "  1. run `codex login --with-api-key` "
    "(writes OPENAI_API_KEY to ~/.codex/auth.json)\n"
    "  2. export OPENAI_API_KEY=sk-...\n"
    "  3. switch with `/provider chatgpt` (uses ChatGPT-account tokens)\n"
    "  4. switch with `/provider anthropic` or `/provider ollama`"
)


def _key_from_auth_json(path: Path) -> str | None:
    """Read a usable top-level OPENAI_API_KEY out of a codex auth.json."""
    if not path.is_file():
        return None
    with suppress(OSError, json.JSONDecodeError):
        key = json.loads(path.read_text(encoding="utf-8")).get("OPENAI_API_KEY")
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


def get_chat_model(settings: Settings, *, model: str | None = None) -> BaseChatModel:
    """Build the chat model for the configured provider.

    Credentials are checked here rather than at first invoke so that switching
    provider in the REPL reports a clear error instead of failing mid-stream.
    """
    provider = settings.provider
    name = model or settings.model_for(provider)

    if provider == "chatgpt":
        from skuggi.codex_chat import CodexChatModel

        return CodexChatModel(model=name, auth_path=settings.auth_json())

    kwargs: dict[str, Any] = {}
    if provider == "openai":
        key = resolve_openai_key(settings)
        if not key:
            raise RuntimeError(_NO_OPENAI_KEY)
        kwargs = {"api_key": key, "streaming": True}
    elif provider == "anthropic":
        if settings.anthropic_api_key is None:
            msg = "ANTHROPIC_API_KEY is not set."
            raise RuntimeError(msg)
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
        from langchain_openai import OpenAIEmbeddings

        return OpenAIEmbeddings(model=settings.embedding_model, api_key=key)

    from langchain_ollama import OllamaEmbeddings

    return OllamaEmbeddings(
        model=settings.embedding_model_ollama, base_url=settings.ollama_base_url
    )
