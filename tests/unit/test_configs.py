"""L1: the JSON config loaders."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from skuggi import home
from skuggi.configs import (
    ConfigError,
    load_commands,
    load_layout,
    load_registry,
    load_scope,
)
from tests.support import template


def test_loads_a_valid_scope(pentest_configs: Callable[..., Path]) -> None:
    workspace = pentest_configs()
    eng = load_scope(workspace / "scope.json")
    assert eng.name == "test-eng"
    assert "nmap" in eng.allowed_tools


def test_loads_a_valid_registry(pentest_configs: Callable[..., Path]) -> None:
    pentest_configs()
    registry = load_registry(home.config_home() / "tools.json")
    assert registry.method_for("nmap") == "scan"


def test_missing_scope_raises_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_scope(tmp_path / "nope.json")


def test_invalid_scope_json_raises_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "scope.json"
    bad.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid scope"):
        load_scope(bad)


def test_invalid_registry_raises_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "tools.json"
    bad.write_text('{"tools": [{"binary": "x"}]}', encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid tool registry"):
        load_registry(bad)


def test_missing_layout_returns_defaults(tmp_path: Path) -> None:
    layout = load_layout(tmp_path / "absent.json")
    assert layout.scope_file == "scope.json"
    assert layout.recon_subdirs == ("nmap", "web")


def test_layout_override_is_loaded(tmp_path: Path) -> None:
    path = tmp_path / "layout.json"
    path.write_text('{"reports": "out", "recon_subdirs": ["dns"]}', encoding="utf-8")
    layout = load_layout(path)
    assert layout.reports == "out"
    assert layout.recon_subdirs == ("dns",)


def test_invalid_layout_raises_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "layout.json"
    bad.write_text('{"recon_subdirs": "not-a-list"', encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid workspace layout"):
        load_layout(bad)


def test_example_registry_includes_the_new_tools() -> None:
    """The shipped tools.example.json parses and carries the extended set."""
    example = template("tools.example.json")
    registry = load_registry(example)
    assert registry.method_for("hydra") == "bruteforce"
    assert registry.method_for("nxc") == "bruteforce"
    assert registry.method_for("hashcat") == "crack"
    assert registry.method_for("john") == "crack"
    assert registry.method_for("msfconsole") == "exploit"
    assert registry.method_for("ldapsearch") == "enumerate"
    assert registry.method_for("tcpdump") == "recon"
    assert registry.method_for("cewl") == "recon"
    assert registry.method_for("burpsuite") == "scan"
    assert registry.method_for("wireshark") == "recon"
    assert registry.method_for("bloodhound") == "enumerate"
    # File/interface tools do not require a network target.
    john = registry.spec_for("john")
    hydra = registry.spec_for("hydra")
    assert john is not None
    assert hydra is not None
    assert john.requires_target is False
    assert hydra.requires_target is True


# --- command aliases --------------------------------------------------------


def test_missing_commands_returns_empty(tmp_path: Path) -> None:
    assert load_commands(tmp_path / "absent.json").commands == ()


def test_commands_loaded(tmp_path: Path) -> None:
    cfg = tmp_path / "commands.json"
    cfg.write_text(
        '{"commands": [{"name": "x", "argv": ["nmap", "-sn"]}]}', encoding="utf-8"
    )
    reg = load_commands(cfg)
    assert reg.alias_for("x") is not None


def test_invalid_commands_raises_config_error(tmp_path: Path) -> None:
    cfg = tmp_path / "commands.json"
    cfg.write_text('{"commands": [{"argv": 5}]}', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_commands(cfg)
