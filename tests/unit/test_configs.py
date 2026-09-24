"""L1: the JSON config loaders."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from skuggi.configs import ConfigError, load_engagement, load_registry


def test_loads_a_valid_engagement(pentest_configs: Callable[..., Path]) -> None:
    configs = pentest_configs()
    eng = load_engagement(configs / "engagement.json")
    assert eng.name == "test-eng"
    assert "nmap" in eng.allowed_tools


def test_loads_a_valid_registry(pentest_configs: Callable[..., Path]) -> None:
    configs = pentest_configs()
    registry = load_registry(configs / "tools.json")
    assert registry.method_for("nmap") == "scan"


def test_missing_engagement_raises_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_engagement(tmp_path / "nope.json")


def test_invalid_engagement_json_raises_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "engagement.json"
    bad.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid engagement"):
        load_engagement(bad)


def test_invalid_registry_raises_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "tools.json"
    bad.write_text('{"tools": [{"binary": "x"}]}', encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid tool registry"):
        load_registry(bad)
