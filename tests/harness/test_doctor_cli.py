"""L3: the skuggi-doctor console script."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from rich.console import Console

from skuggi import doctor, home
from skuggi import probe as probe_mod
from skuggi.config import Settings


def test_probe_statuses_reads_the_registry(
    pentest_configs: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    pentest_configs()
    monkeypatch.setattr(probe_mod, "probe", lambda *_a, **_k: [])
    assert doctor.probe_statuses(Settings()) == []


def test_main_returns_zero_with_configs(
    pentest_configs: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    pentest_configs()
    monkeypatch.setattr(probe_mod, "probe", lambda *_a, **_k: [])
    monkeypatch.setattr(probe_mod, "probe_runtimes", lambda *_a, **_k: [])
    monkeypatch.setattr(probe_mod, "probe_net_tools", lambda *_a, **_k: [])
    assert doctor.main() == 0


def test_main_reports_missing_registry() -> None:
    # No configs written; the default registry path does not exist.
    assert doctor.main() == 1


# --- the install table ------------------------------------------------------
#
# `skuggi` is a command run from any directory, so "which config am I actually
# using?" stops being obvious. This table is the answer, and the first thing to
# read when the harness behaves as though it were unconfigured.


def _render(settings: Settings) -> str:
    console = Console(force_terminal=False, width=200)
    with console.capture() as capture:
        console.print(doctor.install_table(settings))
    return capture.get()


def test_install_table_names_both_homes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(home.CONFIG_HOME_ENV, str(tmp_path / "chome"))
    monkeypatch.setenv(home.DATA_HOME_ENV, str(tmp_path / "dhome"))
    body = _render(Settings())
    assert "chome" in body
    assert "dhome" in body


def test_install_table_flags_a_missing_registry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The one file whose absence breaks the harness outright gets MISSING."""
    monkeypatch.setenv(home.CONFIG_HOME_ENV, str(tmp_path / "empty"))
    assert "MISSING" in _render(Settings())


def test_install_table_reports_a_present_registry(
    pentest_configs: Callable[..., Path],
) -> None:
    pentest_configs()
    body = _render(Settings())
    assert "MISSING" not in body
    assert "present" in body


def test_install_table_warns_about_a_group_readable_env_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Nothing else in the harness ever complains about this, so the doctor must."""
    config_dir = tmp_path / "chome"
    config_dir.mkdir()
    env_file = config_dir / home.ENV_FILENAME
    env_file.write_text("ANTHROPIC_API_KEY=sk-ant-x\n", encoding="utf-8")
    env_file.chmod(0o644)
    monkeypatch.setenv(home.CONFIG_HOME_ENV, str(config_dir))
    assert "chmod 600" in _render(Settings())


def test_install_table_accepts_a_locked_down_env_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config_dir = tmp_path / "chome"
    config_dir.mkdir()
    env_file = config_dir / home.ENV_FILENAME
    env_file.write_text("ANTHROPIC_API_KEY=sk-ant-x\n", encoding="utf-8")
    env_file.chmod(0o600)
    monkeypatch.setenv(home.CONFIG_HOME_ENV, str(config_dir))
    body = _render(Settings())
    assert "chmod 600" not in body
    assert "0600" in body


def test_install_table_reports_the_engagement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SKUGGI_ENGAGEMENT", "acme-2026")
    assert "acme-2026" in _render(Settings())
    monkeypatch.delenv("SKUGGI_ENGAGEMENT")
    assert "agent-only" in _render(Settings())


def test_missing_registry_still_prints_the_install_table(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A fresh install is the likeliest reason to run the doctor at all."""
    assert doctor.main() == 1
    out = capsys.readouterr().out
    assert "skuggi install" in out
    assert "skuggi-init" in out
