"""L1: settings resolution, and the isolation the whole suite depends on."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from skuggi.config import Settings, write_config


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


# --- JSON config source -----------------------------------------------------


def _write_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, data: dict[str, object]
) -> None:
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setenv("SKUGGI_CONFIG_PATH", str(cfg))


def test_json_config_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_config(tmp_path, monkeypatch, {"provider": "ollama", "retrieve_k": 9})
    settings = Settings()
    assert settings.provider == "ollama"
    assert settings.retrieve_k == 9


def test_env_overrides_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_config(tmp_path, monkeypatch, {"provider": "ollama"})
    monkeypatch.setenv("SKUGGI_PROVIDER", "anthropic")
    assert Settings().provider == "anthropic"  # env wins over JSON


def test_missing_json_config_falls_back_to_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SKUGGI_CONFIG_PATH", str(tmp_path / "absent.json"))
    assert Settings().provider == "openai"


def test_secrets_are_never_read_from_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A key mistakenly placed in the JSON config must be ignored, not loaded."""
    _write_config(tmp_path, monkeypatch, {"openai_api_key": "sk-leaked-from-json"})
    assert Settings().openai_api_key is None


def test_example_config_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shipped configs/config.example.json validates against Settings."""
    example = Path(__file__).parents[2] / "configs" / "config.example.json"
    monkeypatch.setenv("SKUGGI_CONFIG_PATH", str(example))
    settings = Settings()
    assert settings.provider == "openai"
    assert settings.mode == "pentest"


# --- write_config -----------------------------------------------------------


def test_write_config_merges_into_existing(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    write_config(path, {"provider": "anthropic"})
    write_config(path, {"retrieve_k": 8})
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data == {"provider": "anthropic", "retrieve_k": 8}


def test_write_config_refuses_secrets(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="secret"):
        write_config(tmp_path / "config.json", {"openai_api_key": "sk-x"})


def test_write_config_creates_parent(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "config.json"
    write_config(path, {"mode": "blueteam"})
    assert path.is_file()


def test_write_config_survives_a_malformed_file(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text("{ not json", encoding="utf-8")
    write_config(path, {"provider": "ollama"})
    assert json.loads(path.read_text(encoding="utf-8")) == {"provider": "ollama"}
