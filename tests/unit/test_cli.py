"""L1: the guarded console-entry shims and their integrity against pyproject.

``skuggi.cli`` is the stable indirection every ``skuggi*`` wrapper imports. These
tests pin it to ``[project.scripts]`` so a module move can never again leave the
installed commands importing a vanished path without CI going red, and prove the
guard turns a missing implementation into one actionable line, not a traceback.
"""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

import pytest

from skuggi import cli

_PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def _scripts() -> dict[str, str]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    scripts = data["project"]["scripts"]
    assert isinstance(scripts, dict)
    return scripts


def test_every_console_script_routes_through_cli() -> None:
    """Each [project.scripts] entry points at a real ``skuggi.cli`` shim."""
    for name, target in _scripts().items():
        module, _, attr = target.partition(":")
        assert module == "skuggi.cli", f"{name} should route through skuggi.cli"
        assert hasattr(cli, attr), f"skuggi.cli has no shim {attr!r} for {name}"


def test_cli_shim_set_matches_targets() -> None:
    """The script attrs and ``_TARGETS`` keys describe the same command set."""
    attrs = {t.split(":", 1)[1] for t in _scripts().values()}
    expected = {("eval_" if k == "eval" else k) for k in cli._TARGETS}
    assert attrs == expected


def test_every_target_module_imports_and_has_main() -> None:
    """Every implementation module resolves and exposes ``main`` -- the drift guard.

    This is the test that would have failed the moment the 2026-10 refactor moved
    a module out from under an entry point.
    """
    for name, module_path in cli._TARGETS.items():
        module = importlib.import_module(module_path)
        assert callable(module.main), f"{module_path} (for {name}) has no main()"


def test_run_guides_instead_of_crashing_on_a_moved_module(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A vanished target degrades to the reinstall hint + exit 1, not a traceback."""
    monkeypatch.delenv("SKUGGI_DEBUG", raising=False)

    def _boom(_name: str) -> object:
        msg = "No module named 'skuggi.frontend.shell'"
        raise ModuleNotFoundError(msg)

    monkeypatch.setattr(importlib, "import_module", _boom)
    with pytest.raises(SystemExit) as exc:
        cli.shell()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "make install-cli" in err
    assert "could not load" in err


def test_run_reraises_under_debug(monkeypatch: pytest.MonkeyPatch) -> None:
    """With SKUGGI_DEBUG set the real import error surfaces for debugging."""
    monkeypatch.setenv("SKUGGI_DEBUG", "1")

    def _boom(_name: str) -> object:
        msg = "boom"
        raise ModuleNotFoundError(msg)

    monkeypatch.setattr(importlib, "import_module", _boom)
    with pytest.raises(ModuleNotFoundError):
        cli.doctor()
