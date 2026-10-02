"""Guided provider + credential setup, front-end-agnostic.

Like ``wizard.py``, this drives the conversation through an injected
``ask``/``notify`` pair so the REPL's ``PromptSession`` and the wrapped-shell
attach loop's socket round-trip share one flow. It owns no persistence: it calls
back into the core (``set_api_key`` / ``use_ollama`` / ``login_chatgpt``), which
writes skuggi's own config and secret files. Keys are validated by shape only
(a wrong key surfaces on first use) and never echoed back.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

Ask = Callable[[str], str | None]
Notify = Callable[[str], None]

_PROVIDERS = ("openai", "anthropic", "ollama", "chatgpt")
# The documented key shapes (providers._key_from_auth_json pins the openai one).
_KEY_PREFIX = {"openai": "sk-", "anthropic": "sk-ant-"}
_DEFAULT_OLLAMA_URL = "http://localhost:11434"


class SetupBackend(Protocol):
    """What the setup flow needs from the core (AgentCore satisfies it)."""

    @property
    def provider(self) -> str:
        """The currently active provider name."""

    def set_api_key(self, provider: str, key: str) -> None:
        """Persist an API key for `provider` and switch to it."""

    def use_ollama(self, base_url: str | None) -> None:
        """Switch to the local Ollama provider (optional base url)."""

    def login_chatgpt(self, notify: Notify) -> str | None:
        """Run the ChatGPT OAuth login; return the account id, if any."""


def run_setup(backend: SetupBackend, ask: Ask, notify: Notify) -> bool:
    """Walk the operator through choosing and configuring a provider.

    Returns True when a provider was configured, False on abort or failure.
    """
    notify(f"current provider: {backend.provider}")
    choice = ask(f"provider? [{'/'.join(_PROVIDERS)}] (blank keeps current): ")
    if choice is None:
        notify("setup cancelled")
        return False
    provider = choice.strip().lower() or backend.provider
    if provider not in _PROVIDERS:
        notify(f"unknown provider: {provider!r}")
        return False
    try:
        if provider in _KEY_PREFIX:
            return _setup_api_key(backend, provider, ask, notify)
        if provider == "ollama":
            return _setup_ollama(backend, ask, notify)
        return _setup_chatgpt(backend, notify)
    except (RuntimeError, ValueError) as exc:
        notify(f"setup failed: {exc}")
        return False


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


def _setup_chatgpt(backend: SetupBackend, notify: Notify) -> bool:
    account = backend.login_chatgpt(notify)
    suffix = f" (account {account})" if account else ""
    notify(f"chatgpt configured{suffix}")
    return True
