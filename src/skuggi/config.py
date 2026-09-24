"""Typed configuration, replacing scattered os.environ.get calls.

Every setting is read from the environment with a ``SKUGGI_`` prefix, or from a
``.env`` file, or passed explicitly to the constructor. Vendor credentials keep
their conventional unprefixed names via ``validation_alias``.

Construct this at an entry point and pass it down; there is deliberately no
module-level singleton. A singleton would read ``.env`` at import time, making
``import skuggi.providers`` a filesystem side effect, and would turn every test
override into monkeypatching a global. ``Settings(provider="ollama")`` overrides
the environment cleanly, which keeps tests to one line.

Relative paths (including ``.env`` itself) resolve against the working
directory, so ``skuggi`` is cwd-sensitive by design -- the data directory
belongs to the project you run it from.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

Provider = Literal["openai", "chatgpt", "anthropic", "ollama"]


class Settings(BaseSettings):
    """Runtime configuration for one skuggi session."""

    model_config = SettingsConfigDict(
        env_prefix="SKUGGI_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    provider: Provider = "openai"
    model_openai: str = "gpt-4o-mini"
    # Codex-over-ChatGPT accepts only models the account is entitled to, and
    # rejects plain chat model names such as "gpt-5" outright.
    model_chatgpt: str = "gpt-5-codex"
    model_anthropic: str = "claude-sonnet-4-5-20250929"
    model_ollama: str = "llama3.2"

    embedding_model: str = "text-embedding-3-small"
    embedding_model_ollama: str = "nomic-embed-text"

    sqlite_path: Path = Path("./data/sessions.db")
    faiss_path: Path = Path("./data/faiss_index")
    history_path: Path = Path("./data/.repl_history")

    chunk_size: int = 800
    chunk_overlap: int = 120
    retrieve_k: int = 4

    max_revisions: int = 2
    max_tool_rounds: int = 4

    codex_auth_path: Path = Path("~/.codex/auth.json")
    codex_responses_base: str = "https://chatgpt.com/backend-api/codex"
    codex_refresh_url: str = "https://auth.openai.com/oauth/token"
    # Retreat switch: if the codex endpoint rejects the OpenAI SDK's payload,
    # flipping this is an env change rather than a revert.
    codex_use_openai_sdk: bool = True

    openai_api_key: SecretStr | None = Field(None, validation_alias="OPENAI_API_KEY")
    anthropic_api_key: SecretStr | None = Field(
        None, validation_alias="ANTHROPIC_API_KEY"
    )
    ollama_base_url: str = Field(
        "http://localhost:11434", validation_alias="OLLAMA_BASE_URL"
    )

    def model_for(self, provider: Provider) -> str:
        """Return the configured model name for `provider`."""
        names: dict[Provider, str] = {
            "openai": self.model_openai,
            "chatgpt": self.model_chatgpt,
            "anthropic": self.model_anthropic,
            "ollama": self.model_ollama,
        }
        return names[provider]

    def auth_json(self) -> Path:
        """The codex auth.json path, with `~` expanded."""
        return self.codex_auth_path.expanduser()

    def supports_tools(self) -> bool:
        """Whether the active provider can bind LangChain tools.

        The ChatGPT-account endpoint uses a codex-specific tool schema, so the
        worker runs as a plain generator there.
        """
        return self.provider != "chatgpt"
