"""L1: the guided provider/credential/model setup flow (front-end-agnostic)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from skuggi.frontend import setup
from skuggi.providers import claude_cli_chat


class FakeBackend:
    """Records what the flow asked the core to persist."""

    def __init__(self, provider: str = "openai") -> None:
        self.provider = provider
        self.api_key: tuple[str, str] | None = None
        self.ollama_url: str | None = "unset"
        self.logged_in = False
        self.claude_cli = False
        self.model: tuple[str, str] | None = None

    def set_api_key(self, provider: str, key: str) -> None:
        self.api_key = (provider, key)

    def use_ollama(self, base_url: str | None) -> None:
        self.ollama_url = base_url

    def use_claude_cli(self) -> None:
        self.claude_cli = True

    def login_chatgpt(self, notify: setup.Notify) -> str | None:
        self.logged_in = True
        return "acct-7"

    def default_model(self, provider: str) -> str:
        return f"default-{provider}"

    def set_provider_model(self, provider: str, model: str) -> None:
        self.model = (provider, model)


def _ask_from(answers: list[str | None]) -> setup.Ask:
    stream: Iterator[str | None] = iter(answers)

    def ask(_prompt: str) -> str | None:
        return next(stream)

    return ask


def _choose(provider: str | None) -> setup.Choose:
    """A menu stub: the provider's label for the provider menu, default for model."""
    label = setup._PROVIDER_LABELS.get(provider) if provider is not None else None

    def choose(prompt: str, _options: list[str], default: str | None) -> str | None:
        if prompt.startswith("model"):
            return default  # keep the current model
        return label

    return choose


def _notes() -> tuple[setup.Notify, list[str]]:
    out: list[str] = []
    return out.append, out


def test_openai_key_rejected_then_accepted() -> None:
    backend = FakeBackend()
    notify, notes = _notes()
    ok = setup.run_setup(
        backend, _ask_from(["nope", "sk-good"]), _choose("openai"), notify
    )
    assert ok is True
    assert backend.api_key == ("openai", "sk-good")
    assert any("not a openai key" in n for n in notes)
    assert any("skuggi's config" in n for n in notes)


def test_anthropic_key_shape_enforced() -> None:
    backend = FakeBackend()
    notify, _ = _notes()
    ok = setup.run_setup(
        backend, _ask_from(["sk-ant-xyz"]), _choose("anthropic"), notify
    )
    assert ok is True
    assert backend.api_key == ("anthropic", "sk-ant-xyz")


def test_ollama_blank_url_uses_default() -> None:
    backend = FakeBackend()
    notify, _ = _notes()
    ok = setup.run_setup(backend, _ask_from([""]), _choose("ollama"), notify)
    assert ok is True
    assert backend.ollama_url is None  # blank -> backend applies its default


def test_chatgpt_runs_the_login() -> None:
    backend = FakeBackend()
    notify, notes = _notes()
    ok = setup.run_setup(backend, _ask_from([]), _choose("chatgpt"), notify)
    assert ok is True
    assert backend.logged_in
    assert any("acct-7" in n for n in notes)


def test_claude_cli_configures_when_binary_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(claude_cli_chat, "is_available", lambda: True)
    backend = FakeBackend()
    notify, notes = _notes()
    ok = setup.run_setup(backend, _ask_from([]), _choose("claude-cli"), notify)
    assert ok is True
    assert backend.claude_cli is True
    assert any("local `claude` login" in n for n in notes)


def test_claude_cli_without_binary_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(claude_cli_chat, "is_available", lambda: False)
    backend = FakeBackend()
    notify, notes = _notes()
    ok = setup.run_setup(backend, _ask_from([]), _choose("claude-cli"), notify)
    assert ok is False
    assert backend.claude_cli is False
    assert any("not installed" in n for n in notes)


def test_provider_label_maps_back_to_the_canonical_id() -> None:
    # The menu shows a friendly label; setup must persist the canonical id.
    backend = FakeBackend()
    notify, _ = _notes()
    setup.run_setup(backend, _ask_from(["sk-good"]), _choose("openai"), notify)
    assert backend.api_key is not None
    assert backend.api_key[0] == "openai"


def test_model_step_sets_a_custom_model() -> None:
    backend = FakeBackend()
    notify, notes = _notes()

    def choose(prompt: str, _options: list[str], _default: str | None) -> str | None:
        if prompt.startswith("model"):
            return setup._CUSTOM
        return setup._PROVIDER_LABELS["ollama"]

    # ollama url (blank), then the custom model id typed at the ask prompt.
    ok = setup.run_setup(backend, _ask_from(["", "qwen3:14b"]), choose, notify)
    assert ok is True
    assert backend.model == ("ollama", "qwen3:14b")
    assert any("model set to qwen3:14b" in n for n in notes)


def test_abort_at_the_provider_menu_returns_false() -> None:
    backend = FakeBackend()
    notify, _ = _notes()
    assert setup.run_setup(backend, _ask_from([]), _choose(None), notify) is False
    assert backend.api_key is None


def test_abort_at_the_key_prompt_returns_false() -> None:
    backend = FakeBackend()
    notify, _ = _notes()
    ok = setup.run_setup(backend, _ask_from([None]), _choose("openai"), notify)
    assert ok is False
    assert backend.api_key is None


def test_a_backend_failure_is_reported_not_raised() -> None:
    class Boom(FakeBackend):
        def set_api_key(self, provider: str, key: str) -> None:
            msg = "disk full"
            raise RuntimeError(msg)

    notify, notes = _notes()
    ok = setup.run_setup(Boom(), _ask_from(["sk-x"]), _choose("openai"), notify)
    assert ok is False
    assert any("setup failed: disk full" in n for n in notes)
