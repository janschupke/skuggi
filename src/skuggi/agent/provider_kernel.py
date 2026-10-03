"""The model plane: provider/credential setup and the live chat model.

A sibling of the other ``AgentCore`` sub-components, owning everything about *which*
model runs and its credentials -- the model name, the live ``llm``, the embeddings
and the FAISS store. It mutates the shared ``core.settings`` (the established
``model_copy`` seam) and signals ``core.rebuild_graph()`` after any change, but has
no engagement dependency, so the core builds it first (its ``_load_chat_model``
must run before the first graph build).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast, get_args

from pydantic import SecretStr

from skuggi.common.logs import get_logger
from skuggi.config.config import Provider, config_path, write_config
from skuggi.install import envfile
from skuggi.persistence.vectorstore import Store
from skuggi.providers import providers

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from langchain_core.language_models import BaseChatModel

    from skuggi.agent.core import AgentCore

log = get_logger(__name__)

_PROVIDERS = get_args(Provider)

# The API-key providers: provider name -> (env-file key, Settings field). The
# key persists to skuggi's own secret file; the field holds it on the live
# Settings. chatgpt (OAuth) and ollama (no key) are deliberately absent.
_API_KEY_FIELDS: dict[str, tuple[str, str]] = {
    "openai": ("OPENAI_API_KEY", "openai_api_key"),
    "anthropic": ("ANTHROPIC_API_KEY", "anthropic_api_key"),
}


class ProviderKernel:
    """Owns the model/credential state for one session."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core
        self.model: str | None = None
        self._embeddings = providers.get_embeddings(core.settings)
        self.store = Store.from_settings(core.settings, self._embeddings)
        self.llm: BaseChatModel | None = self._load_chat_model()

    # ----- session controls --------------------------------------------------

    def set_provider(self, name: str) -> None:
        """Switch provider (raises ValueError on an unknown name)."""
        if name not in _PROVIDERS:
            msg = f"unknown provider: {name!r}"
            raise ValueError(msg)
        self._core.settings = self._core.settings.model_copy(update={"provider": name})
        self.model = None
        self._rebuild_llm()

    def set_model(self, name: str) -> None:
        """Switch model on the current provider."""
        if not name:
            msg = "model name is required"
            raise ValueError(msg)
        self.model = name
        self._rebuild_llm()

    # ----- guided setup: app-owned credentials (the `setup`/`login` verbs) ----

    def set_api_key(self, provider: str, key: str) -> None:
        """Persist an API key to skuggi's own secret file and use its provider.

        The key goes into ``<config home>/env`` at mode 0600 (via envfile), never
        the environment; the provider goes into ``config.json``. Both are applied
        to the live session so the next turn uses them without a restart.
        """
        try:
            env_name, field = _API_KEY_FIELDS[provider]
        except KeyError:
            msg = f"{provider} is not an API-key provider"
            raise ValueError(msg) from None
        envfile.write_secret(env_name, key)
        write_config(config_path(), {"provider": provider})
        self._core.settings = self._core.settings.model_copy(
            update={field: SecretStr(key), "provider": provider}
        )
        self.model = None
        self._rebuild_llm()

    def use_ollama(self, base_url: str | None = None) -> None:
        """Switch to the local Ollama provider (no credential), setting its URL."""
        persist: dict[str, object] = {"provider": "ollama"}
        updates: dict[str, object] = {"provider": "ollama"}
        if base_url:
            persist["ollama_base_url"] = base_url
            updates["ollama_base_url"] = base_url
        write_config(config_path(), persist)
        self._core.settings = self._core.settings.model_copy(update=updates)
        self.model = None
        self._rebuild_llm()

    def use_claude_cli(self) -> None:
        """Switch to the local Claude CLI provider (uses the operator's own login).

        No key is stored: the ``claude`` binary carries its own credentials. The
        provider is persisted so the next session starts on it.
        """
        write_config(config_path(), {"provider": "claude-cli"})
        self._core.settings = self._core.settings.model_copy(
            update={"provider": "claude-cli"}
        )
        self.model = None
        self._rebuild_llm()

    def default_model(self, provider: str) -> str:
        """The persisted default model for `provider` (what setup pre-selects)."""
        return self._core.settings.model_for(cast("Provider", provider))

    def set_provider_model(self, provider: str, model: str) -> None:
        """Persist the default model for `provider` and apply it to this session.

        Writes the non-secret ``model_<provider>`` key to config.json (so it
        survives a restart) and rebuilds the live model. Resetting ``self.model``
        to ``None`` means the session now follows the persisted provider default.
        """
        if not model:
            msg = "model name is required"
            raise ValueError(msg)
        field = f"model_{provider.replace('-', '_')}"
        write_config(config_path(), {field: model})
        self._core.settings = self._core.settings.model_copy(update={field: model})
        self.model = None
        self._rebuild_llm()

    def login_chatgpt(
        self, notify: Callable[[str], None] = lambda _msg: None
    ) -> str | None:
        """Run the in-app ChatGPT OAuth login, then switch to the chatgpt provider.

        Writes ``auth.json`` (owned by codex_login/CodexTokenStore), persists the
        provider, and rebuilds the live model. Returns the account id, if any.
        """
        # lazy: pulls the OpenAI SDK, kept out of the module import graph.
        from skuggi.providers import codex_login  # noqa: PLC0415

        account = codex_login.login(
            auth_path=self._core.settings.auth_json(), notify=notify
        )
        write_config(config_path(), {"provider": "chatgpt"})
        self._core.settings = self._core.settings.model_copy(
            update={"provider": "chatgpt"}
        )
        self.model = None
        self._rebuild_llm()
        return account

    def _rebuild_llm(self) -> None:
        self.llm = providers.get_chat_model(self._core.settings, model=self.model)
        self._core.rebuild_graph()

    def _load_chat_model(self) -> BaseChatModel | None:
        """Build the chat model at boot, or degrade to a warning if uncredentialed.

        Boot must never die for lack of a model: the shell wrapper only needs one
        when the operator actually asks something, and the graph just holds the
        reference until a turn runs. A missing/unusable credential becomes a
        warning (the front-end shows it) and a ``None`` llm; `ensure_llm` builds
        it on first use, where the operator can fix it with `/setup` or
        `/provider`. Mirrors the credential-free boot of `providers.get_embeddings`.
        """
        try:
            return providers.get_chat_model(self._core.settings, model=self.model)
        except (RuntimeError, ImportError) as exc:
            log.warning("no chat model configured: %s", exc)
            self._core.warnings.append(providers.NO_MODEL_CONFIGURED)
            return None

    def ensure_llm(self) -> BaseChatModel:
        """Return the chat model, building it on first use.

        Deferred from construction so the session boots without credentials.
        Raises ``ConfigError`` (with the provider's specific guidance) when no
        usable credential is configured; callers on the turn path let that
        surface as a clean error event rather than a crash.
        """
        if self.llm is None:
            self.llm = providers.get_chat_model(self._core.settings, model=self.model)
            self._core.rebuild_graph()
        return self.llm

    def ingest(self, path: Path) -> int:
        """Index a file or directory into FAISS; returns chunks added."""
        added = self.store.ingest([path])
        self.store.persist()
        return added
