"""L1: the auth.json write must never widen the permissions of a token file."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from skuggi.providers import codex_chat
from skuggi.providers.codex_chat import CodexTokenStore


def _auth_file(tmp_path: Path, mode: int = 0o600) -> Path:
    # Its own directory, so the leftover-temp-file assertion sees only this file.
    home = tmp_path / "codex"
    home.mkdir(exist_ok=True)
    path = home / "auth.json"
    path.write_text(
        json.dumps({"auth_mode": "chatgpt", "tokens": {}}), encoding="utf-8"
    )
    path.chmod(mode)
    return path


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_save_preserves_0600(tmp_path: Path) -> None:
    """Writing a temp file at the process umask then replacing widens 0600 to 0644.

    That would make the user's real OAuth tokens world-readable on the first
    token refresh.
    """
    path = _auth_file(tmp_path)

    CodexTokenStore(path)._save({"tokens": {"access_token": "new"}})

    assert _mode(path) == 0o600, f"permissions widened to {oct(_mode(path))}"


def test_save_repairs_an_already_widened_file(tmp_path: Path) -> None:
    path = _auth_file(tmp_path, mode=0o644)

    CodexTokenStore(path)._save({"tokens": {"access_token": "new"}})

    assert _mode(path) == 0o600


def test_save_writes_content_and_leaves_no_temp_file(tmp_path: Path) -> None:
    path = _auth_file(tmp_path)

    CodexTokenStore(path)._save(
        {"auth_mode": "chatgpt", "tokens": {"access_token": "abc"}}
    )

    assert json.loads(path.read_text())["tokens"]["access_token"] == "abc"
    leftovers = [p.name for p in path.parent.iterdir() if p.name != "auth.json"]
    assert leftovers == [], f"temp files left behind: {leftovers}"


def test_save_creates_a_missing_directory(tmp_path: Path) -> None:
    path = tmp_path / "fresh" / "auth.json"

    CodexTokenStore(path)._save({"tokens": {}})

    assert path.is_file()
    assert _mode(path) == 0o600


def test_default_auth_path_resolved_at_call_time_from_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """S3: the fallback auth.json path honours the env var at *call* time.

    A module-level `Path(...).expanduser()` constant resolves at import, ignores
    the redirect, and leaks the developer's real ~/.codex -- the exact
    anti-pattern storage.md forbids and the suite's isolation depends on.
    """
    target = tmp_path / "elsewhere" / "auth.json"
    monkeypatch.setenv("SKUGGI_CODEX_AUTH_PATH", str(target))
    assert codex_chat._default_auth_path() == target
    assert CodexTokenStore().auth_path == target
    # The import-time-resolved constant must be gone.
    assert not hasattr(codex_chat, "_AUTH_PATH_DEFAULT")
