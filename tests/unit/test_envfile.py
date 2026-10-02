"""L1: the app-owned secret writer (`<config home>/env`)."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from skuggi.install import envfile


def test_creates_the_file_owner_only(tmp_path: Path) -> None:
    target = tmp_path / "env"
    envfile.write_secret("OPENAI_API_KEY", "sk-abc", path=target)
    assert target.read_text(encoding="utf-8") == "OPENAI_API_KEY=sk-abc\n"
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode & 0o077 == 0  # no group/other bits -- a secret stays private


def test_upsert_replaces_in_place_and_keeps_other_lines(tmp_path: Path) -> None:
    target = tmp_path / "env"
    target.write_text(
        "# my keys\nOPENAI_API_KEY=sk-old\nANTHROPIC_API_KEY=sk-ant-keep\n",
        encoding="utf-8",
    )
    envfile.write_secret("OPENAI_API_KEY", "sk-new", path=target)
    assert target.read_text(encoding="utf-8") == (
        "# my keys\nOPENAI_API_KEY=sk-new\nANTHROPIC_API_KEY=sk-ant-keep\n"
    )


def test_appends_a_new_key(tmp_path: Path) -> None:
    target = tmp_path / "env"
    target.write_text("ANTHROPIC_API_KEY=sk-ant-x\n", encoding="utf-8")
    envfile.write_secret("OPENAI_API_KEY", "sk-y", path=target)
    assert target.read_text(encoding="utf-8") == (
        "ANTHROPIC_API_KEY=sk-ant-x\nOPENAI_API_KEY=sk-y\n"
    )


def test_narrows_a_previously_widened_file(tmp_path: Path) -> None:
    target = tmp_path / "env"
    target.write_text("OPENAI_API_KEY=sk-old\n", encoding="utf-8")
    target.chmod(0o644)  # a file an earlier version left world-readable
    envfile.write_secret("OPENAI_API_KEY", "sk-new", path=target)
    assert stat.S_IMODE(target.stat().st_mode) & 0o077 == 0


# --- S10: a secret value/name must not inject extra dotenv lines ------------


def test_rejects_a_newline_in_the_value(tmp_path: Path) -> None:
    target = tmp_path / "env"
    with pytest.raises(ValueError, match="newline"):
        envfile.write_secret("API_KEY", "a\nINJECTED=b", path=target)
    assert not target.exists()  # nothing written on rejection


def test_rejects_an_invalid_key(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid env key"):
        envfile.write_secret("bad name", "x", path=tmp_path / "env")
