"""L1: settings resolution, and the isolation the whole suite depends on."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from skuggi.config import Settings


def test_defaults() -> None:
    settings = Settings()
    assert settings.provider == "openai"
    assert settings.max_revisions == 2
    assert settings.supports_tools() is True


def test_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SKUGGI_PROVIDER", "ollama")
    monkeypatch.setenv("SKUGGI_MAX_REVISIONS", "7")
    settings = Settings()
    assert settings.provider == "ollama"
    assert settings.max_revisions == 7


def test_constructor_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit values must win, so a test needs no env manipulation."""
    monkeypatch.setenv("SKUGGI_PROVIDER", "ollama")
    assert Settings(provider="anthropic").provider == "anthropic"


def test_unknown_provider_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(provider="nope")  # type: ignore[arg-type]


def test_frozen() -> None:
    with pytest.raises(ValidationError):
        Settings().provider = "ollama"  # type: ignore[misc]


def test_chatgpt_cannot_bind_tools() -> None:
    assert Settings(provider="chatgpt").supports_tools() is False


def test_model_for_each_provider() -> None:
    settings = Settings()
    assert settings.model_for("openai") == "gpt-4o-mini"
    assert settings.model_for("chatgpt") == "gpt-5-codex"
    assert settings.model_for("anthropic").startswith("claude-")
    assert settings.model_for("ollama") == "llama3.2"


def test_suite_does_not_see_real_credentials() -> None:
    """Guards the autouse isolation fixture itself.

    If this fails, the suite is reading the developer's real .env or auth.json
    and every credential-related assertion elsewhere is meaningless.
    """
    settings = Settings()
    assert settings.openai_api_key is None
    assert settings.anthropic_api_key is None
    assert not settings.auth_json().exists()
