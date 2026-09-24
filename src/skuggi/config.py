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

from skuggi.modes import Mode

Provider = Literal["openai", "chatgpt", "anthropic", "ollama"]
ToolSource = Literal["host", "managed", "combine"]

# The ChatGPT-account (codex) endpoints. Verified live: the responses route is
# under /codex (a bare /backend-api/responses 404s), and refresh is the OpenAI
# OAuth token endpoint. Single source: codex_chat imports these for its
# defaults so the two never drift.
CODEX_RESPONSES_BASE = "https://chatgpt.com/backend-api/codex"
CODEX_REFRESH_URL = "https://auth.openai.com/oauth/token"


class Settings(BaseSettings):
    """Runtime configuration for one skuggi session."""

    model_config = SettingsConfigDict(
        env_prefix="SKUGGI_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        populate_by_name=True,
    )

    provider: Provider = "openai"

    # Defaults are the small, cheap tier of each provider's *current* lineup --
    # a local agent harness should not open with a frontier-priced model. Every
    # one is overridable with SKUGGI_MODEL_<PROVIDER>.
    #
    # Verified live against each provider on 2026-09-24. The codex endpoint in
    # particular accepts only current model names: every gpt-*-codex name is
    # refused there with "not supported when using Codex with a ChatGPT
    # account", which reads like an entitlement problem but is a staleness one.
    model_openai: str = "gpt-6-luna"
    model_chatgpt: str = "gpt-6-luna"
    model_anthropic: str = "claude-haiku-4-5"
    # Ollama serves whatever you have pulled, so this one is a suggestion:
    # `ollama pull qwen3` first, or point it at a model you already have.
    model_ollama: str = "qwen3"

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

    # --- pentest harness ---
    # The operating mode selects the agent's prompt set (pentest/redteam/blueteam).
    mode: Mode = "pentest"
    # Harness config (shared across engagements): the recognized-tool registry and
    # the optional workspace-layout override. Committed only as `.example`.
    registry_path: Path = Path("./configs/tools.json")
    layout_path: Path = Path("./configs/layout.json")
    # Engagement setup lives in a per-engagement workspace under this root; the
    # active engagement selects the directory (engagements/<engagement>/). Its
    # scope.json, ledger and reports live inside that workspace. With no active
    # engagement the harness runs agent-only and falls back to ./data.
    engagements_dir: Path = Path("./engagements")
    engagement: str | None = None
    managed_tools_dir: Path = Path("./data/toolbox")
    # Where to look for / install tools: host PATH, the managed venv, or both.
    tool_source: ToolSource = "combine"
    # Wall-clock cap on any single autonomously executed command.
    command_timeout_s: float = 120.0

    codex_auth_path: Path = Path("~/.codex/auth.json")
    codex_responses_base: str = CODEX_RESPONSES_BASE
    codex_refresh_url: str = CODEX_REFRESH_URL

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
