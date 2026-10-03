"""The ``update`` and ``reconcile`` verbs: keep the install and its config fresh.

A sibling of the other ``AgentCore`` sub-components (see e.g.
``config_controller.py``): it holds a back-ref and reads live state through the
public seam, never caching. ``reconcile`` overwrites a drifted config from its
packaged template (saving a timestamped backup), then asks the core to reload the
registries and graph so a running session reflects it without a restart.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from skuggi.install import reconcile
from skuggi.install import update as updater

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from skuggi.agent.core import AgentCore
    from skuggi.install import configdiff


class ReconcileController:
    """Drives ``self_update`` and the ``reconcile`` family for one session."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core

    @property
    def _config_dir(self) -> Path:
        """The config home holding tools.json/commands.json/… (per settings)."""
        return self._core.settings.registry_path.parent

    def self_update(self, runner: updater.UpdateRunner | None = None) -> Iterator[str]:
        """Update the install in place: ``git pull --ff-only`` then a dependency sync.

        Delegates to :func:`skuggi.install.update.perform_update` (``runner`` is
        forwarded so the subprocess path stays injectable and testable), then
        notes any config drift -- a pulled template may have moved ahead of the
        installed copy, and an update is exactly the moment to surface that.
        """
        yield from updater.perform_update(runner)
        behind = reconcile.drifted(self._config_dir)
        if behind:
            yield "\n"
            yield (
                f"{len(behind)} config file(s) differ from the packaged templates: "
                + ", ".join(behind)
                + "\n"
            )
            yield (
                "  review with `reconcile diff <file>`, update with "
                "`reconcile <file>` or `reconcile all` (a timestamped backup is "
                "saved).\n"
            )

    def reconcile_status(self) -> tuple[reconcile.FileStatus, ...]:
        """How each installed config compares to its packaged template."""
        return reconcile.status(self._config_dir)

    def stale_configs(self) -> tuple[str, ...]:
        """The installed config files that have fallen behind their template."""
        return reconcile.drifted(self._config_dir)

    def reconcile_structured_diff(self, name: str) -> configdiff.StructuredDiff:
        """What an overwrite of `name` would change, per file type (empty = in sync)."""
        return reconcile.structured_diff(self._config_dir, name)

    def reconcile_overwrite(self, name: str) -> Path | None:
        """Overwrite `name` from its template (backing up), then reload config.

        The in-memory registries are rebuilt from disk so a subsequent ``cmd``
        reflects the updated tool/alias output conventions without a restart;
        the graph is rebuilt because it carries the tool registry.
        """
        backup = reconcile.overwrite(self._config_dir, name)
        self._core.reload_registries()
        return backup

    def reconcile_overwrite_all(self) -> tuple[tuple[str, Path | None], ...]:
        """Overwrite every drifted config from its template, reloading once.

        Returns ``(name, backup)`` for each file updated (empty when nothing had
        drifted). The in-memory registries/graph are rebuilt a single time.
        """
        results = tuple(
            (name, reconcile.overwrite(self._config_dir, name))
            for name in reconcile.drifted(self._config_dir)
        )
        if results:
            self._core.reload_registries()
        return results
