"""L1: settings resolution, and the isolation the whole suite depends on."""

from __future__ import annotations

import json
import re
from importlib.resources import files
from pathlib import Path

import pytest
from pydantic import ValidationError

from skuggi import home
from skuggi.config import Settings, config_path, write_config


def test_defaults() -> None:
    settings = Settings()
    assert settings.provider == "openai"
    assert settings.max_revisions == 2
    assert settings.supports_structured_output() is True


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


def test_chatgpt_has_no_native_structured_output() -> None:
    assert Settings(provider="chatgpt").supports_structured_output() is False


def test_model_for_each_provider() -> None:
    settings = Settings()
    assert settings.model_for("openai") == "gpt-6-luna"
    assert settings.model_for("chatgpt") == "gpt-6-luna"
    assert settings.model_for("anthropic") == "claude-haiku-4-5"
    assert settings.model_for("ollama") == "qwen3"


def test_model_is_overridable_per_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SKUGGI_MODEL_ANTHROPIC", "claude-opus-5")
    assert Settings().model_for("anthropic") == "claude-opus-5"


def test_session_logging_defaults() -> None:
    settings = Settings()
    assert settings.review_model is None  # default: use the active model
    assert "cd" in settings.passthrough_skip  # navigation noise is filtered


def test_review_model_is_overridable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SKUGGI_REVIEW_MODEL", "claude-opus-5")
    assert Settings().review_model == "claude-opus-5"


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


def test_example_config_loads(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The packaged config.example.json validates against Settings.

    Located through the package, not a repo path: it is what `skuggi-init` seeds
    from, and it has to be readable from an installed wheel with no checkout.
    """
    template = files("skuggi") / "templates" / "config.example.json"
    example = tmp_path / "config.json"
    example.write_bytes(template.read_bytes())
    monkeypatch.setenv("SKUGGI_CONFIG_PATH", str(example))
    settings = Settings()
    assert settings.provider == "openai"
    assert settings.mode == "pentest"


# --- storage paths ----------------------------------------------------------


def test_storage_paths_default_under_the_homes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Absolute by default, so `skuggi` from any directory reads the same state."""
    monkeypatch.setenv(home.CONFIG_HOME_ENV, str(tmp_path / "c"))
    monkeypatch.setenv(home.DATA_HOME_ENV, str(tmp_path / "d"))
    settings = Settings()
    assert settings.sqlite_path == tmp_path / "d" / "sessions.db"
    assert settings.faiss_path == tmp_path / "d" / "faiss_index"
    assert settings.history_path == tmp_path / "d" / ".repl_history"
    assert settings.preferences_path == tmp_path / "d" / "preferences.db"
    assert settings.managed_tools_dir == tmp_path / "d" / "toolbox"
    assert settings.registry_path == tmp_path / "c" / "tools.json"
    assert settings.layout_path == tmp_path / "c" / "layout.json"
    assert settings.commands_path == tmp_path / "c" / "commands.json"
    assert config_path() == tmp_path / "c" / "config.json"


def test_engagements_dir_stays_relative_to_the_working_directory() -> None:
    """The one deliberate exception: a workspace belongs to the client directory."""
    assert not Settings().engagements_dir.is_absolute()
    assert Settings().engagements_dir == Path("engagements")


def test_the_homes_are_reread_per_instantiation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Two Settings() with a redirected home in between must not agree.

    This is what makes the suite's isolation fixture effective; if the defaults
    were computed once at import, every test would share one real home.
    """
    monkeypatch.setenv(home.DATA_HOME_ENV, str(tmp_path / "first"))
    assert Settings().sqlite_path == tmp_path / "first" / "sessions.db"
    monkeypatch.setenv(home.DATA_HOME_ENV, str(tmp_path / "second"))
    assert Settings().sqlite_path == tmp_path / "second" / "sessions.db"


def test_an_explicit_relative_path_is_still_relative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Overriding with a relative path keeps the old cwd-relative behaviour."""
    monkeypatch.setenv("SKUGGI_SQLITE_PATH", "./data/sessions.db")
    assert Settings().sqlite_path == Path("data/sessions.db")


# --- the <config home>/env secrets file -------------------------------------


def _write_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str) -> Path:
    config_dir = tmp_path / "config-home"
    config_dir.mkdir(exist_ok=True)
    env_file = config_dir / home.ENV_FILENAME
    env_file.write_text(text, encoding="utf-8")
    monkeypatch.setenv(home.CONFIG_HOME_ENV, str(config_dir))
    return env_file


def test_env_file_supplies_a_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of the file: keys reach a globally-launched skuggi without an rc."""
    _write_env_file(tmp_path, monkeypatch, "ANTHROPIC_API_KEY=sk-ant-from-file\n")
    key = Settings().anthropic_api_key
    assert key is not None
    assert key.get_secret_value() == "sk-ant-from-file"


def test_env_file_supplies_a_prefixed_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Non-secret settings need the SKUGGI_ prefix here, exactly as in the shell."""
    _write_env_file(tmp_path, monkeypatch, "SKUGGI_PROVIDER=ollama\n")
    assert Settings().provider == "ollama"


def test_shell_env_beats_the_env_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_env_file(tmp_path, monkeypatch, "SKUGGI_PROVIDER=ollama\n")
    monkeypatch.setenv("SKUGGI_PROVIDER", "anthropic")
    assert Settings().provider == "anthropic"


def test_env_file_beats_the_json_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_env_file(tmp_path, monkeypatch, "SKUGGI_RETRIEVE_K=7\n")
    _write_config(tmp_path, monkeypatch, {"retrieve_k": 3})
    assert Settings().retrieve_k == 7


def test_a_missing_env_file_is_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(home.CONFIG_HOME_ENV, str(tmp_path / "nothing-here"))
    assert Settings().provider == "openai"


def test_unrelated_keys_in_the_env_file_are_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An operator's file may hold anything; only declared settings are read."""
    _write_env_file(
        tmp_path, monkeypatch, "SOMETHING_ELSE=1\nEDITOR=vim\nSKUGGI_PROVIDER=ollama\n"
    )
    assert Settings().provider == "ollama"


def test_the_env_file_is_not_secret_filtered_but_the_json_still_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The asymmetry is deliberate, so state it as one test.

    A credential in the JSON is dropped (it is committed-adjacent, `config`-edited
    and readable); the same credential in the `env` file is honoured, because
    holding credentials is that file's only job.
    """
    _write_env_file(tmp_path, monkeypatch, "OPENAI_API_KEY=sk-from-env-file\n")
    _write_config(tmp_path, monkeypatch, {"anthropic_api_key": "sk-ant-from-json"})
    settings = Settings()
    assert settings.anthropic_api_key is None
    assert settings.openai_api_key is not None
    assert settings.openai_api_key.get_secret_value() == "sk-from-env-file"


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
