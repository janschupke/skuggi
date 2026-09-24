"""L1: credential resolution and provider construction, offline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skuggi import providers
from skuggi.config import Settings


def _auth(tmp_path: Path, payload: object) -> Path:
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _settings(tmp_path: Path, **kwargs: object) -> Settings:
    kwargs.setdefault("codex_auth_path", tmp_path / "absent.json")
    return Settings(**kwargs)  # type: ignore[arg-type]


# --- key resolution ---------------------------------------------------------


def test_key_from_auth_json_wins(tmp_path: Path) -> None:
    path = _auth(tmp_path, {"OPENAI_API_KEY": "sk-from-auth"})
    settings = Settings(codex_auth_path=path, openai_api_key="sk-from-env")
    assert providers.resolve_openai_key(settings) == "sk-from-auth"


def test_null_key_in_auth_json_falls_through(tmp_path: Path) -> None:
    """A ChatGPT-account login writes the key as null, not as a missing field.

    A naive `"OPENAI_API_KEY" in data` check would return None here and break
    the env fallback on every machine logged in through the browser flow.
    """
    path = _auth(tmp_path, {"auth_mode": "chatgpt", "OPENAI_API_KEY": None})
    settings = Settings(codex_auth_path=path, openai_api_key="sk-from-env")
    assert providers.resolve_openai_key(settings) == "sk-from-env"


def test_non_sk_value_is_ignored(tmp_path: Path) -> None:
    path = _auth(tmp_path, {"OPENAI_API_KEY": "not-a-key"})
    settings = Settings(codex_auth_path=path, openai_api_key="sk-good")
    assert providers.resolve_openai_key(settings) == "sk-good"


def test_malformed_auth_json_falls_back(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    path.write_text("{not json", encoding="utf-8")
    settings = Settings(codex_auth_path=path, openai_api_key="sk-env")
    assert providers.resolve_openai_key(settings) == "sk-env"


def test_missing_auth_json_falls_back(tmp_path: Path) -> None:
    assert (
        providers.resolve_openai_key(_settings(tmp_path, openai_api_key="sk-e"))
        == "sk-e"
    )


def test_no_key_anywhere(tmp_path: Path) -> None:
    assert providers.resolve_openai_key(_settings(tmp_path)) is None


def test_unreadable_auth_json_falls_back(tmp_path: Path) -> None:
    path = _auth(tmp_path, {"OPENAI_API_KEY": "sk-secret"})
    path.chmod(0o000)
    try:
        settings = Settings(codex_auth_path=path, openai_api_key="sk-env")
        assert providers.resolve_openai_key(settings) == "sk-env"
    finally:
        path.chmod(0o600)


# --- chat model construction ------------------------------------------------


def test_openai_without_a_key_names_every_remedy(tmp_path: Path) -> None:
    """This message is the project's main onboarding surface, so it is pinned."""
    with pytest.raises(RuntimeError) as excinfo:
        providers.get_chat_model(_settings(tmp_path, provider="openai"))

    message = str(excinfo.value)
    for remedy in ("codex login", "OPENAI_API_KEY", "/provider chatgpt", "ollama"):
        assert remedy in message


def test_anthropic_without_a_key_is_explicit(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        providers.get_chat_model(_settings(tmp_path, provider="anthropic"))


@pytest.mark.parametrize(
    ("provider", "extra", "expected"),
    [
        ("openai", {"openai_api_key": "sk-x"}, "ChatOpenAI"),
        ("anthropic", {"anthropic_api_key": "sk-ant-x"}, "ChatAnthropic"),
        ("ollama", {}, "ChatOllama"),
    ],
)
def test_standard_providers_construct(
    tmp_path: Path, provider: str, extra: dict[str, str], expected: str
) -> None:
    model = providers.get_chat_model(_settings(tmp_path, provider=provider, **extra))
    assert type(model).__name__ == expected


def test_explicit_model_overrides_the_configured_one(tmp_path: Path) -> None:
    settings = _settings(tmp_path, provider="ollama")
    model = providers.get_chat_model(settings, model="mistral")
    assert getattr(model, "model", None) == "mistral"


def test_ollama_uses_the_configured_base_url(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path, provider="ollama", ollama_base_url="http://elsewhere:1234"
    )
    model = providers.get_chat_model(settings)
    assert "elsewhere:1234" in str(getattr(model, "base_url", ""))


def test_chatgpt_builds_the_codex_model(tmp_path: Path) -> None:
    path = _auth(
        tmp_path,
        {"tokens": {"access_token": "t", "refresh_token": "r", "account_id": "a"}},
    )
    model = providers.get_chat_model(Settings(provider="chatgpt", codex_auth_path=path))
    assert model._llm_type == "codex-chatgpt"


# --- embeddings -------------------------------------------------------------


def test_embeddings_prefer_openai_when_a_key_exists(tmp_path: Path) -> None:
    settings = _settings(tmp_path, openai_api_key="sk-x")
    assert type(providers.get_embeddings(settings)).__name__ == "OpenAIEmbeddings"


def test_embeddings_fall_back_to_ollama(tmp_path: Path) -> None:
    """Mandatory: the TUI must boot with no credentials at all."""
    assert (
        type(providers.get_embeddings(_settings(tmp_path))).__name__
        == "OllamaEmbeddings"
    )
