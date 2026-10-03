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

from skuggi.common.paths import ensure_parent
from skuggi.engagement.engagement import EngagementConfig
from skuggi.engagement.workspace import WorkspaceLayout
from skuggi.tooling.commands import CommandRegistry
from skuggi.tooling.registry import ToolRegistry


class ConfigError(RuntimeError):
    """A config file is missing or does not validate."""


class InvalidScopeError(ConfigError):
    """An engagement scope failed validation, with the offending field keys.

    Subclasses ``ConfigError`` so existing ``except ConfigError`` callers keep
    working; the engagement wizard catches the richer type to re-ask only the
    fields that failed instead of restarting the whole questionnaire.
    """

    def __init__(self, summary: str, field_keys: frozenset[str]) -> None:
        super().__init__(summary)
        self.summary = summary
        self.field_keys = field_keys


def _read(path: Path, *, what: str) -> str:
    resolved = path.expanduser()
    try:
        return resolved.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read {what} config at {resolved}: {exc}"
        raise ConfigError(msg) from exc


def load_scope(path: Path) -> EngagementConfig:
    """Load and validate one engagement's scope (``scope.json``) from JSON."""
    try:
        return EngagementConfig.model_validate_json(_read(path, what="scope"))
    except ValueError as exc:
        msg = f"invalid scope config at {path}: {exc}"
        raise ConfigError(msg) from exc


def load_registry(path: Path) -> ToolRegistry:
    """Load and validate the tool registry from JSON."""
    try:
        return ToolRegistry.model_validate_json(_read(path, what="tool registry"))
    except ValueError as exc:
        msg = f"invalid tool registry at {path}: {exc}"
        raise ConfigError(msg) from exc


def load_commands(path: Path) -> CommandRegistry:
    """Load the command-alias registry, or return an empty one when absent.

    Optional like the workspace layout: a missing file just means no aliases,
    not an error. A present-but-malformed file fails loudly like the others.
    """
    resolved = path.expanduser()
    if not resolved.is_file():
        return CommandRegistry()
    try:
        return CommandRegistry.model_validate_json(resolved.read_text(encoding="utf-8"))
    except ValueError as exc:
        msg = f"invalid command registry at {path}: {exc}"
        raise ConfigError(msg) from exc


def write_commands(path: Path, registry: CommandRegistry) -> None:
    """Persist the command-alias registry to `path` as pretty JSON.

    The write-side counterpart to ``load_commands`` (round-trips through it),
    used by the guided ``cmd`` editor. Mirrors ``config.write_config``'s
    parent-dir discipline and trailing newline so a hand-edit and a guided edit
    produce byte-identical files.
    """
    resolved = ensure_parent(path)
    resolved.write_text(registry.model_dump_json(indent=2) + "\n", encoding="utf-8")


def load_layout(path: Path) -> WorkspaceLayout:
    """Load the workspace layout override, or return defaults when absent.

    The layout is harness-level and optional: a missing file is not an error,
    it just means the default folder structure. A present-but-malformed file
    fails loudly like the other loaders.
    """
    resolved = path.expanduser()
    if not resolved.is_file():
        return WorkspaceLayout()
    try:
        return WorkspaceLayout.model_validate_json(resolved.read_text(encoding="utf-8"))
    except ValueError as exc:
        msg = f"invalid workspace layout at {path}: {exc}"
        raise ConfigError(msg) from exc
