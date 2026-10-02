"""L1: the startup guard that turns setup failures into a clean exit."""

from __future__ import annotations

import pytest

from skuggi.config.configs import ConfigError
from skuggi.install.boot import guard_boot


def test_returns_the_built_value_on_success() -> None:
    assert guard_boot(lambda: 42) == 42


def test_setup_error_prints_one_line_and_exits_1(
    capsys: pytest.CaptureFixture[str],
) -> None:
    msg = "No OpenAI API key found. Options: ..."

    def build() -> None:
        raise ConfigError(msg)

    with pytest.raises(SystemExit) as excinfo:
        guard_boot(build)

    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    # One actionable line on stderr, with the project's prefix -- no traceback.
    assert captured.err == f"skuggi: {msg}\n"


def test_debug_env_restores_the_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SKUGGI_DEBUG", "1")
    msg = "boom"

    def build() -> None:
        raise ConfigError(msg)

    with pytest.raises(ConfigError, match="boom"):
        guard_boot(build)


def test_an_unexpected_error_is_re_raised_untouched() -> None:
    """A genuine bug is not a setup error; it must still surface as itself."""
    msg = "a real bug"

    def build() -> None:
        raise ValueError(msg)

    with pytest.raises(ValueError, match="a real bug"):
        guard_boot(build)
