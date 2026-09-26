"""Fixtures for the deterministic eval tier.

This tier runs in the *default* collection (no ``eval`` marker), so it is subject
to the autouse ``isolate_credentials`` fixture that chdirs each test into a temp
directory. The committed corpora and the shipped registry therefore have to be
addressed by absolute path -- which is what ``EVALS_ROOT`` / ``REGISTRY`` provide.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.configs import load_registry
from skuggi.engagement import EngagementConfig
from skuggi.eval.goldens import load_scopes
from skuggi.registry import ToolRegistry

REPO_ROOT = Path(__file__).resolve().parents[2]
EVALS_ROOT = REPO_ROOT / "evals"
REGISTRY_PATH = REPO_ROOT / "configs" / "tools.example.json"


@pytest.fixture(scope="session")
def evals_root() -> Path:
    """Absolute path to the committed ``evals`` directory."""
    return EVALS_ROOT


@pytest.fixture(scope="session")
def registry_path() -> Path:
    """Absolute path to the shipped tool registry."""
    return REGISTRY_PATH


@pytest.fixture(scope="session")
def registry() -> ToolRegistry:
    """The shipped tool registry, loaded once."""
    return load_registry(REGISTRY_PATH)


@pytest.fixture(scope="session")
def scopes() -> dict[str, EngagementConfig]:
    """The committed engagement scopes, loaded once."""
    return load_scopes(EVALS_ROOT)
