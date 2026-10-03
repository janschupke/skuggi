"""Guided provider + credential + model setup, front-end-agnostic.

Like ``wizard.py``, this drives the conversation through injected
``ask``/``choose``/``notify`` callables so the REPL's prompt_toolkit widgets and
the wrapped-shell attach loop's socket round-trip share one flow. It owns no
persistence: it calls back into the core (``set_api_key`` / ``use_ollama`` /
``login_chatgpt`` / ``use_claude_cli`` / ``set_provider_model``), which writes
skuggi's own config and secret files. Keys are validated by shape only (a wrong
key surfaces on first use) and never echoed back.

After a provider is configured the flow offers a model for it, from a curated
per-provider list (``config/models.json``) plus a custom entry.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from importlib.resources import files
from typing import Protocol

Ask = Callable[[str], str | None]
# (prompt, options, default) -> the chosen option, or None if the operator aborts.
Choose = Callable[[str, list[str], str | None], str | None]
Notify = Callable[[str], None]

# Provider id -> the human-readable menu label. The ids stay canonical (they must
# match config.Provider); only the label changes so "openai" vs "chatgpt" is no
# longer a guessing game.
_PROVIDER_LABELS: dict[str, str] = {
    "openai": "OpenAI — API key",
    "chatgpt": "ChatGPT — subscription login (OAuth)",
    "anthropic": "Anthropic — API key",
    "claude-cli": "Claude CLI — your Claude Code subscription (local `claude`)",
    "ollama": "Ollama — local models, no key",
}
_PROVIDERS = tuple(_PROVIDER_LABELS)
# The documented key shapes (providers._key_from_auth_json pins the openai one).
_KEY_PREFIX = {"openai": "sk-", "anthropic": "sk-ant-"}
_DEFAULT_OLLAMA_URL = "http://localhost:11434"
_CUSTOM = "custom…"


class SetupBackend(Protocol):
    """What the setup flow needs from the core (AgentCore satisfies it)."""

    @property
    def provider(self) -> str:
        """The currently active provider name."""

    def set_api_key(self, provider: str, key: str) -> None:
        """Persist an API key for `provider` and switch to it."""

    def use_ollama(self, base_url: str | None) -> None:
        """Switch to the local Ollama provider (optional base url)."""

    def use_claude_cli(self) -> None:
        """Switch to the local Claude CLI provider (no key stored)."""

    def login_chatgpt(self, notify: Notify) -> str | None:
        """Run the ChatGPT OAuth login; return the account id, if any."""

    def default_model(self, provider: str) -> str:
        """The persisted default model for `provider`."""

    def set_provider_model(self, provider: str, model: str) -> None:
        """Persist the default model for `provider` and apply it."""


def _models_catalog() -> dict[str, list[str]]:
    """The curated per-provider model lists bundled with the package."""
    raw = (files("skuggi.config") / "models.json").read_text(encoding="utf-8")
    loaded = json.loads(raw)
    return loaded if isinstance(loaded, dict) else {}


def run_setup(backend: SetupBackend, ask: Ask, choose: Choose, notify: Notify) -> bool:
    """Walk the operator through choosing and configuring a provider, then a model.

    Returns True when a provider was configured (the model step is best-effort
    and never fails the run), False on abort or failure.
    """
    provider = _choose_provider(backend, choose)
    if provider is None:
        notify("setup cancelled")
        return False
    try:
        configured = _configure_provider(backend, provider, ask, notify)
    except (RuntimeError, ValueError) as exc:
        notify(f"setup failed: {exc}")
        return False
    if not configured:
        return False
    run_model_select(backend, provider, ask, choose, notify)
    return True


def _choose_provider(backend: SetupBackend, choose: Choose) -> str | None:
    """Show the labelled provider menu; return the canonical provider id."""
    labels = [_PROVIDER_LABELS[p] for p in _PROVIDERS]
    default = _PROVIDER_LABELS.get(backend.provider)
    picked = choose("Choose a model provider:", labels, default)
    if picked is None:
        return None
    for provider, label in _PROVIDER_LABELS.items():
        if label == picked:
            return provider
    return None


def _configure_provider(
    backend: SetupBackend, provider: str, ask: Ask, notify: Notify
) -> bool:
    if provider in _KEY_PREFIX:
        return _setup_api_key(backend, provider, ask, notify)
    if provider == "ollama":
        return _setup_ollama(backend, ask, notify)
    if provider == "claude-cli":
        return _setup_claude_cli(backend, notify)
    return _setup_chatgpt(backend, notify)


def _setup_api_key(
    backend: SetupBackend, provider: str, ask: Ask, notify: Notify
) -> bool:
    prefix = _KEY_PREFIX[provider]
    while True:
        key = ask(f"paste your {provider} API key ({prefix}...): ")
        if key is None:
            notify("setup cancelled")
            return False
        key = key.strip()
        if key.startswith(prefix):
            break
        notify(f"that is not a {provider} key (expected it to start with {prefix})")
    backend.set_api_key(provider, key)
    notify(f"{provider} configured -- key saved to skuggi's config, not your shell")
    return True


def _setup_ollama(backend: SetupBackend, ask: Ask, notify: Notify) -> bool:
    url = ask(f"ollama base url [{_DEFAULT_OLLAMA_URL}]: ")
    if url is None:
        notify("setup cancelled")
        return False
    backend.use_ollama(url.strip() or None)
    notify("ollama configured -- local model, no key needed")
    return True


def _setup_claude_cli(backend: SetupBackend, notify: Notify) -> bool:
    from skuggi.providers import claude_cli_chat  # noqa: PLC0415 -- lazy

    if not claude_cli_chat.is_available():
        notify(
            "the 'claude' CLI is not installed. Install Claude Code and run "
            "`claude /login`, then re-run setup."
        )
        return False
    backend.use_claude_cli()
    notify("claude-cli configured -- uses your local `claude` login, no key stored")
    return True


def _setup_chatgpt(backend: SetupBackend, notify: Notify) -> bool:
    account = backend.login_chatgpt(notify)
    suffix = f" (account {account})" if account else ""
    notify(f"chatgpt configured{suffix}")
    return True


def run_model_select(
    backend: SetupBackend, provider: str, ask: Ask, choose: Choose, notify: Notify
) -> None:
    """Offer a model for `provider` from the curated list, or a custom id."""
    current = backend.default_model(provider)
    curated = _models_catalog().get(provider, [])
    options = list(dict.fromkeys([current, *curated, _CUSTOM]))
    picked = choose(f"model for {provider}:", options, current)
    if picked is None:
        notify("keeping the current model")
        return
    if picked == _CUSTOM:
        typed = ask(f"model id [{current}]: ")
        if typed is None or not typed.strip():
            notify("keeping the current model")
            return
        picked = typed.strip()
    if picked == current:
        notify(f"model stays {current}")
        return
    backend.set_provider_model(provider, picked)
    notify(f"model set to {picked}")
