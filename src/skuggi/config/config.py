"""Typed configuration for one skuggi session.

Values resolve in priority order: explicit constructor args, then environment
variables (``SKUGGI_*`` plus the unprefixed vendor aliases), then the optional
secrets file ``<config home>/env``, then the persisted JSON config file
(``<config home>/config.json``, path overridable with ``SKUGGI_CONFIG_PATH``),
then the field defaults. The ``config`` verb edits that JSON; an env var still
wins over it, which keeps CI and one-off overrides simple.

**Secrets never live in the JSON.** The API keys are read from the environment,
the ``env`` file beside the config, or ``~/.codex/auth.json``; the JSON source is
filtered to drop them even if a file mistakenly contains one. The ``env`` file is
deliberately *not* filtered -- holding credentials is the whole reason it exists.

Storage paths are **absolute by default**, resolved under the two homes in
``skuggi.home`` (see that module for the config/data split). ``skuggi`` is an
installed command run from anywhere, so a cwd-relative default would scatter a
fresh empty ``configs/`` and ``data/`` into whatever directory the operator
happened to be standing in. The one exception is ``engagements_dir``, which stays
relative on purpose: an engagement's workspace belongs to the client directory
you ran skuggi in. A relative path supplied explicitly -- by env var or by the
JSON -- is still honoured, and still resolves against the working directory.

Construct this at an entry point and pass it down; there is deliberately no
module-level singleton, so ``import skuggi.providers`` has no filesystem side
effect and a test override is one constructor arg.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    JsonConfigSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from skuggi.common import home, logs
from skuggi.common.modes import Mode
from skuggi.common.paths import ensure_parent

Provider = Literal["openai", "chatgpt", "anthropic", "ollama"]
# The provider names as a tuple, for validation and usage listings.
PROVIDERS: tuple[Provider, ...] = ("openai", "chatgpt", "anthropic", "ollama")
ToolSource = Literal["host", "managed", "combine"]

# The ChatGPT-account (codex) endpoints. Verified live: the responses route is
# under /codex (a bare /backend-api/responses 404s), and refresh is the OpenAI
# OAuth token endpoint. Single source: codex_chat imports these for its
# defaults so the two never drift.
CODEX_RESPONSES_BASE = "https://chatgpt.com/backend-api/codex"
CODEX_REFRESH_URL = "https://auth.openai.com/oauth/token"
# The OAuth authorize endpoint for the in-app ChatGPT login (codex_login).
CODEX_AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"

# The persisted, `config`-editable settings file, under the config home.
# Overridable so tests (and a multi-project user) can point elsewhere; env still
# overrides its values.
CONFIG_FILENAME = "config.json"
CONFIG_PATH_ENV = "SKUGGI_CONFIG_PATH"

# Field names that must never be sourced from (or written to) the JSON config:
# credentials belong in the environment only.
_SECRET_FIELDS = frozenset({"openai_api_key", "anthropic_api_key"})

log = logs.get_logger(__name__)


def config_path() -> Path:
    """The active config.json path (``SKUGGI_CONFIG_PATH`` or under the config home).

    Read from the environment on every call, never cached: the home it derives
    from is itself resolved per call (see ``skuggi.home``), and the test suite
    redirects both between tests.
    """
    override = os.environ.get(CONFIG_PATH_ENV)
    if override:
        return Path(override)
    return home.config_home() / CONFIG_FILENAME


def write_config(path: Path, updates: dict[str, object]) -> None:
    """Merge `updates` into the JSON config at `path` (read-modify-write).

    Credentials are refused -- they live only in the environment, never in the
    JSON (mirrors ``_NonSecretJsonSource`` on the read side). A missing file starts
    from an empty object; the parent directory is created.

    An *unreadable* existing file is NOT silently treated as empty: doing so would
    merge only the new keys over ``{}`` and write that back, clobbering every prior
    setting the operator could no longer read. Instead the corrupt file is logged
    and preserved, and the write is refused -- a failed edit must never destroy a
    config we merely failed to parse.
    """
    secret = {k for k in updates if k.lower() in _SECRET_FIELDS}
    if secret:
        msg = f"secrets are env-only, never config.json: {', '.join(sorted(secret))}"
        raise ValueError(msg)
    resolved = ensure_parent(path)
    current: dict[str, object] = {}
    if resolved.is_file():
        try:
            loaded = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.exception("refusing to overwrite unreadable config %s", resolved)
            msg = f"existing config at {resolved} is unreadable; not overwriting"
            raise ValueError(msg) from exc
        if isinstance(loaded, dict):
            current = loaded
    current.update(updates)
    resolved.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")


class _NonSecretJsonSource(JsonConfigSettingsSource):
    """A JSON settings source that refuses to supply credential fields."""

    def __call__(self) -> dict[str, object]:
        # Match case-insensitively: the source keys a secret by its env alias
        # (e.g. "OPENAI_API_KEY"), whose lower-case form is the field name.
        data = super().__call__()
        return {k: v for k, v in data.items() if k.lower() not in _SECRET_FIELDS}


class Settings(BaseSettings):
    """Runtime configuration for one skuggi session."""

    model_config = SettingsConfigDict(
        env_prefix="SKUGGI_",
        extra="ignore",
        frozen=True,
        populate_by_name=True,
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,  # noqa: ARG003 -- pydantic hook
        file_secret_settings: PydanticBaseSettingsSource,  # noqa: ARG003 -- pydantic hook
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Resolve init args > env > ``<config home>/env`` > config.json > defaults.

        The JSON source is secret-filtered; the ``env`` file is not (see the
        module docstring).

        The ``dotenv_settings`` argument pydantic hands us is unusable here: its
        path comes from ``model_config``, which is evaluated once at class
        definition and so would freeze whichever home was active at import time.
        We build our own against a freshly resolved path instead.
        ``only_existing`` filtering keeps unrelated keys in the operator's file
        from arriving as extra data, and a missing file is a silent no-op.
        """
        env_file_source = DotEnvSettingsSource(
            settings_cls,
            env_file=home.env_path(),
            dotenv_filtering="only_existing",
        )
        json_source = _NonSecretJsonSource(settings_cls, json_file=config_path())
        return (init_settings, env_settings, env_file_source, json_source)

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

    # USD per 1,000,000 tokens, as (input, output), keyed by model name. Read by
    # the eval budget dimension (skuggi.eval.cost) to turn a turn's token usage
    # into a cost; nothing on the live agent path reads it. A model absent here
    # is priced at 0 (a local Ollama model is genuinely free), so an unknown
    # name never manufactures a false budget failure -- see cost.price_for.
    # Overridable like any setting: SKUGGI_MODEL_PRICES='{"m":[1.0,2.0]}' or the
    # config.json. Rates are a committed snapshot; see evals/prices.json.
    model_prices: dict[str, tuple[float, float]] = Field(
        default_factory=lambda: {
            "gpt-6-luna": (0.15, 0.60),
            "claude-haiku-4-5": (1.00, 5.00),
            "qwen3": (0.0, 0.0),
        }
    )

    # Storage lives under the data home, absolute. `default_factory` and not a
    # computed constant: the factory runs per instantiation, so a test that
    # redirects SKUGGI_DATA_HOME between two Settings() gets two different paths.
    sqlite_path: Path = Field(default_factory=lambda: home.data_home() / "sessions.db")
    faiss_path: Path = Field(default_factory=lambda: home.data_home() / "faiss_index")
    history_path: Path = Field(
        default_factory=lambda: home.data_home() / ".repl_history"
    )
    # The diagnostic file log (skuggi.logs), distinct from the SQLite ledger/audit
    # logs. `log_level` is here for discoverability and the doctor table; the level
    # actually applied at startup is resolved from the environment by
    # `logs.setup_logging` (SKUGGI_LOG_LEVEL > SKUGGI_DEBUG > INFO), since logging
    # must initialise before (and even if) Settings construction fails.
    log_path: Path = Field(default_factory=logs.default_log_path)
    log_level: str = "INFO"

    chunk_size: int = 800
    chunk_overlap: int = 120
    retrieve_k: int = 4

    max_revisions: int = 2
    max_tool_rounds: int = 4
    # How much prior conversation the planner/worker/critic see, bounded by
    # both a message count and a character budget (see graph.render_history).
    history_messages: int = 8
    history_chars: int = 4_000

    # --- pentest harness ---
    # The operating mode selects the agent's prompt set (pentest/redteam/blueteam).
    mode: Mode = "pentest"
    # Harness config (shared across engagements, under the config home): the
    # recognized-tool registry and the optional workspace-layout override.
    # Committed only as `.example`; `skuggi-init` seeds the home from those.
    registry_path: Path = Field(
        default_factory=lambda: home.config_home() / "tools.json"
    )
    layout_path: Path = Field(
        default_factory=lambda: home.config_home() / "layout.json"
    )
    # Named command shorthands the `run` verb resolves (optional).
    commands_path: Path = Field(
        default_factory=lambda: home.config_home() / "commands.json"
    )
    # Engagement setup lives in a per-engagement workspace under this root; the
    # active engagement selects the directory (engagements/<engagement>/). Its
    # scope.json, ledger and reports live inside that workspace.
    #
    # The ONE path that stays relative to the working directory, and the reason
    # the config/data split in `skuggi.home` exists: an engagement's scope, ledger
    # and recon output belong to the client directory you ran skuggi in, not to a
    # global dotdir. With no active engagement the harness runs agent-only and
    # falls back to the data home.
    engagements_dir: Path = Path("./engagements")
    engagement: str | None = None
    managed_tools_dir: Path = Field(
        default_factory=lambda: home.data_home() / "toolbox"
    )
    # Where to look for / install tools: host PATH, the managed venv, or both.
    tool_source: ToolSource = "combine"
    # Wall-clock cap on any single autonomously executed command.
    command_timeout_s: float = 120.0

    # --- session logging & review ---
    # Free-typed shell commands whose first word is one of these are treated as
    # navigation/builtin noise: logged to the audit `cli` channel, never the
    # engagement timeline (see AgentCore.record_passthrough).
    passthrough_skip: tuple[str, ...] = (
        "cd",
        "ls",
        "pwd",
        "clear",
        "exit",
        "history",
        "echo",
    )
    # Model for `review` (the private session critique). None uses the active
    # model; set it to run reviews on a stronger model than the working one.
    review_model: str | None = None

    # --- harness memory ---
    # The operator's durable operational preferences (the `memory` verb + the
    # post-turn automatic capture). GLOBAL across engagements -- a preference is
    # about the operator, not a target -- so it is NOT under the workspace, and
    # the data home is what makes that true across working directories too.
    preferences_path: Path = Field(
        default_factory=lambda: home.data_home() / "preferences.db"
    )
    # Whether the harness automatically captures standing directives it detects
    # in your messages, post-turn. Manual `memory add` is unaffected by this.
    memory_auto: bool = True

    codex_auth_path: Path = Path("~/.codex/auth.json")
    codex_responses_base: str = CODEX_RESPONSES_BASE
    codex_refresh_url: str = CODEX_REFRESH_URL
    codex_authorize_url: str = CODEX_AUTHORIZE_URL

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

    def supports_structured_output(self) -> bool:
        """Whether the provider supports native ``with_structured_output``.

        The tool-less chatgpt endpoint cannot; ``protocol.structured_invoke``
        falls back to a JSON contract there. Every other provider gets the
        native, schema-enforced path.
        """
        return self.provider != "chatgpt"
