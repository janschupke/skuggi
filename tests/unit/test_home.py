"""The config/data home resolver (`skuggi.home`)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.common import home


@pytest.fixture(autouse=True)
def _clear_home_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every case from "nothing set" -- the conftest sets both overrides."""
    for name in (
        home.CONFIG_HOME_ENV,
        home.DATA_HOME_ENV,
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    ):
        monkeypatch.delenv(name, raising=False)


def test_defaults_follow_the_conventional_locations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert home.config_home() == tmp_path / ".config" / "skuggi"
    assert home.data_home() == tmp_path / ".local" / "share" / "skuggi"


def test_xdg_bases_are_honoured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xc"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xd"))
    assert home.config_home() == tmp_path / "xc" / "skuggi"
    assert home.data_home() == tmp_path / "xd" / "skuggi"


def test_skuggi_overrides_beat_xdg_and_are_used_verbatim(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The direct override is a full path -- no `skuggi` leaf is appended."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xc"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xd"))
    monkeypatch.setenv(home.CONFIG_HOME_ENV, str(tmp_path / "direct-c"))
    monkeypatch.setenv(home.DATA_HOME_ENV, str(tmp_path / "direct-d"))
    assert home.config_home() == tmp_path / "direct-c"
    assert home.data_home() == tmp_path / "direct-d"


def test_tilde_is_expanded_in_an_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv(home.CONFIG_HOME_ENV, "~/elsewhere")
    assert home.config_home() == tmp_path / "elsewhere"


@pytest.mark.parametrize("value", ["", "   "])
def test_an_empty_override_counts_as_unset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str
) -> None:
    """An exported-but-empty var must not resolve to a bare `/skuggi`."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv(home.CONFIG_HOME_ENV, value)
    monkeypatch.setenv("XDG_CONFIG_HOME", value)
    assert home.config_home() == tmp_path / ".config" / "skuggi"


def test_a_relative_xdg_base_is_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """XDG requires absolute; a relative one would reintroduce cwd-sensitivity."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", "relative/share")
    assert home.data_home() == tmp_path / ".local" / "share" / "skuggi"


def test_resolution_is_not_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Load-bearing for the test suite: each call re-reads the environment.

    If this ever caches, the autouse isolation fixture stops working and the
    suite reads the developer's real config -- silently, with everything green.
    """
    monkeypatch.setenv(home.DATA_HOME_ENV, str(tmp_path / "first"))
    assert home.data_home() == tmp_path / "first"
    monkeypatch.setenv(home.DATA_HOME_ENV, str(tmp_path / "second"))
    assert home.data_home() == tmp_path / "second"


def test_env_path_sits_in_the_config_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(home.CONFIG_HOME_ENV, str(tmp_path / "c"))
    assert home.env_path() == tmp_path / "c" / home.ENV_FILENAME
