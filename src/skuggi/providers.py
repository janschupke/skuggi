"""LLM and embeddings factory.

Provider routing:
    openai    -> langchain_openai.ChatOpenAI    (api.openai.com)
    chatgpt   -> skuggi.codex_chat.CodexChatModel (ChatGPT-account OAuth)
    anthropic -> langchain_anthropic.ChatAnthropic
    ollama    -> langchain_ollama.ChatOllama

OpenAI key resolution order:
    1. top-level "OPENAI_API_KEY" in ~/.codex/auth.json (codex login --with-api-key)
    2. $OPENAI_API_KEY env var

Note: a ChatGPT-account login writes ``tokens.{access_token,...}`` to auth.json
*without* a top-level OPENAI_API_KEY. Those tokens are not usable against
api.openai.com -- use provider=chatgpt to route them through CodexChatModel.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from langchain_core.embeddings import Embeddings
from langchain_core.language_models import BaseChatModel

AUTH_JSON = Path("~/.codex/auth.json").expanduser()


def resolve_openai_key() -> str | None:
    if AUTH_JSON.is_file():
        try:
            data = json.loads(AUTH_JSON.read_text())
            key = data.get("OPENAI_API_KEY")
            if isinstance(key, str) and key.startswith("sk-"):
                return key
        except (OSError, json.JSONDecodeError):
            pass
    return os.environ.get("OPENAI_API_KEY")


def get_chat_model(provider: str, model: str | None = None) -> BaseChatModel:
    provider = provider.lower()

    if provider == "openai":
        from langchain_openai import ChatOpenAI

        key = resolve_openai_key()
        if not key:
            raise RuntimeError(
                "No OpenAI API key found. Options:\n"
                "  1. run `codex login --with-api-key` (writes OPENAI_API_KEY to ~/.codex/auth.json)\n"
                "  2. export OPENAI_API_KEY=sk-...\n"
                "  3. switch with `/provider chatgpt` (uses ChatGPT-account tokens)\n"
                "  4. switch with `/provider anthropic` or `/provider ollama`"
            )
        return ChatOpenAI(
            model=model or os.environ.get("SKUGGI_MODEL_OPENAI", "gpt-4o-mini"),
            api_key=key,
            streaming=True,
        )

    if provider == "chatgpt":
        from skuggi.codex_chat import CodexChatModel

        return CodexChatModel(
            model=model or os.environ.get("SKUGGI_MODEL_CHATGPT", "gpt-5"),
        )

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set.")
        return ChatAnthropic(
            model=model
            or os.environ.get(
                "SKUGGI_MODEL_ANTHROPIC", "claude-sonnet-4-5-20250929"
            ),
            api_key=key,
            streaming=True,
        )

    if provider == "ollama":
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=model or os.environ.get("SKUGGI_MODEL_OLLAMA", "llama3.2"),
            base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
        )

    raise ValueError(f"unknown provider: {provider!r}")


def get_embeddings() -> Embeddings:
    """Embeddings always use OpenAI (text-embedding-3-small by default).

    The codex/chatgpt provider doesn't expose embeddings; if you want a fully
    local pipeline, swap to OllamaEmbeddings here.
    """
    key = resolve_openai_key()
    if key:
        from langchain_openai import OpenAIEmbeddings

        return OpenAIEmbeddings(
            model=os.environ.get("SKUGGI_EMBEDDING_MODEL", "text-embedding-3-small"),
            api_key=key,
        )
    from langchain_ollama import OllamaEmbeddings

    return OllamaEmbeddings(
        model=os.environ.get("SKUGGI_EMBEDDING_MODEL_OLLAMA", "nomic-embed-text"),
        base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
    )
