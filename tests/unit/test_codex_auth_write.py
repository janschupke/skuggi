"""L1: the auth.json write must never widen the permissions of a token file."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from skuggi.codex_chat import CodexChatModel


def _auth_file(tmp_path: Path, mode: int = 0o600) -> Path:
    path = tmp_path / "auth.json"
    path.write_text(json.dumps({"auth_mode": "chatgpt", "tokens": {}}), encoding="utf-8")
    path.chmod(mode)
    return path


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_save_auth_preserves_0600(tmp_path: Path) -> None:
    """Writing a temp file at the process umask then replacing widens 0600 to 0644.

    That would make the user's real OAuth tokens world-readable on the first
    token refresh.
    """
    path = _auth_file(tmp_path)
    model = CodexChatModel(auth_path=path)

    model._save_auth({"auth_mode": "chatgpt", "tokens": {"access_token": "new"}})

    assert _mode(path) == 0o600, f"permissions widened to {oct(_mode(path))}"


def test_save_auth_repairs_an_already_widened_file(tmp_path: Path) -> None:
    path = _auth_file(tmp_path, mode=0o644)
    model = CodexChatModel(auth_path=path)

    model._save_auth({"tokens": {"access_token": "new"}})

    assert _mode(path) == 0o600


def test_save_auth_writes_content_and_leaves_no_temp_file(tmp_path: Path) -> None:
    path = _auth_file(tmp_path)
    model = CodexChatModel(auth_path=path)

    model._save_auth({"auth_mode": "chatgpt", "tokens": {"access_token": "abc"}})

    assert json.loads(path.read_text())["tokens"]["access_token"] == "abc"
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "auth.json"]
    assert leftovers == [], f"temp files left behind: {leftovers}"
