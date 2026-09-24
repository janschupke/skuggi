"""L1: settings resolution, and the isolation the whole suite depends on."""

from __future__ import annotations

import re

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
    assert settings.model_for("openai") == "gpt-6-luna"
    assert settings.model_for("chatgpt") == "gpt-6-luna"
    assert settings.model_for("anthropic") == "claude-haiku-4-5"
    assert settings.model_for("ollama") == "qwen3"


def test_model_is_overridable_per_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SKUGGI_MODEL_ANTHROPIC", "claude-opus-5")
    assert Settings().model_for("anthropic") == "claude-opus-5"


def test_defaults_carry_no_date_suffixed_or_superseded_ids() -> None:
    """Guards against a stale pin quietly becoming the default again.

    The original scaffold shipped gpt-4o-mini and a date-suffixed Sonnet 4.5,
    both long superseded by the time anyone ran it.
    """
    settings = Settings()
    for provider in ("openai", "chatgpt", "anthropic", "ollama"):
        model = settings.model_for(provider)
        assert not re.search(r"-20\d{6}$", model), f"{model} pins a dated snapshot"
        assert "gpt-4" not in model, f"{model} is a superseded generation"


def test_suite_does_not_see_real_credentials() -> None:
    """Guards the autouse isolation fixture itself.

    If this fails, the suite is reading the developer's real .env or auth.json
    and every credential-related assertion elsewhere is meaningless.
    """
    settings = Settings()
    assert settings.openai_api_key is None
    assert settings.anthropic_api_key is None
    assert not settings.auth_json().exists()
