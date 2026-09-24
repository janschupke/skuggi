"""JSON config loaders for the engagement boundary and the tool registry.

Kept apart from ``config.py``: that module owns *environment* settings (paths,
switches, credentials) via pydantic-settings, while these are *case files* --
the target data for one engagement -- committed only as ``.example`` templates
and gitignored otherwise. Both loaders are pure (no import-time side effects,
the discipline ``config.py`` already insists on) and validate through the
frozen pydantic models, so a malformed scope file fails loudly at load rather
than mid-engagement.
"""

from __future__ import annotations

from pathlib import Path

from skuggi.engagement import EngagementConfig
from skuggi.registry import ToolRegistry


class ConfigError(RuntimeError):
    """A config file is missing or does not validate."""


def _read(path: Path, *, what: str) -> str:
    resolved = path.expanduser()
    try:
        return resolved.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read {what} config at {resolved}: {exc}"
        raise ConfigError(msg) from exc


def load_engagement(path: Path) -> EngagementConfig:
    """Load and validate the engagement boundary from JSON."""
    try:
        return EngagementConfig.model_validate_json(_read(path, what="engagement"))
    except ValueError as exc:
        msg = f"invalid engagement config at {path}: {exc}"
        raise ConfigError(msg) from exc


def load_registry(path: Path) -> ToolRegistry:
    """Load and validate the tool registry from JSON."""
    try:
        return ToolRegistry.model_validate_json(_read(path, what="tool registry"))
    except ValueError as exc:
        msg = f"invalid tool registry at {path}: {exc}"
        raise ConfigError(msg) from exc
