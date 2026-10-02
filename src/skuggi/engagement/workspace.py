"""Per-engagement workspace: the on-disk directory one engagement operates in.

Each engagement is a directory under ``engagements/<name>/`` with a fixed but
*configurable* layout -- ``scope.json`` (the engagement setup), plus ``findings``,
``notes``, ``recon`` (with ``nmap``/``dirs``/``domains``/``web`` subdirs),
``reports``, ``scripts``, ``tests`` and ``loot``. Keeping outputs inside the
workspace is what makes a session
self-contained and traceable: the ledger, the Markdown reports and any tool
output all land next to the scope that authorized them.

``WorkspaceLayout`` is a frozen model so the folder names can be overridden from
``configs/layout.json`` (harness-level) without touching code; ``Workspace``
turns a layout plus an engagement name into concrete paths and creates the tree.
This is the analogue of ``open_ledger``'s parent-dir discipline: ``ensure`` is
idempotent and the only thing that writes directories.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from skuggi.common.paths import ensure_dir


class WorkspaceLayout(BaseModel):
    """The configurable folder structure of an engagement workspace."""

    model_config = ConfigDict(frozen=True)

    scope_file: str = "scope.json"
    ledger_file: str = "ledger.db"
    notes_log: str = "notes.md"
    loot_log: str = "loot.md"
    findings: str = "findings"
    notes: str = "notes"
    recon: str = "recon"
    recon_subdirs: tuple[str, ...] = ("nmap", "dirs", "domains", "web")
    reports: str = "reports"
    scripts: str = "scripts"
    tests: str = "tests"
    loot: str = "loot"

    def dirs(self) -> tuple[str, ...]:
        """Every directory (relative to the workspace root) ``ensure`` creates."""
        recon_subs = tuple(f"{self.recon}/{sub}" for sub in self.recon_subdirs)
        return (
            self.findings,
            self.notes,
            self.recon,
            *recon_subs,
            self.reports,
            self.scripts,
            self.tests,
            self.loot,
        )


@dataclass(frozen=True, slots=True)
class Workspace:
    """The resolved paths for one engagement's workspace."""

    root: Path
    layout: WorkspaceLayout

    @classmethod
    def for_engagement(
        cls, engagements_dir: Path, name: str, *, layout: WorkspaceLayout | None = None
    ) -> Workspace:
        """The workspace for `name` under `engagements_dir`."""
        return cls(
            root=engagements_dir.expanduser() / name,
            layout=layout or WorkspaceLayout(),
        )

    @property
    def scope_path(self) -> Path:
        """The engagement setup file (``scope.json``)."""
        return self.root / self.layout.scope_file

    @property
    def ledger_path(self) -> Path:
        """The SQLite ledger for this engagement."""
        return self.root / self.layout.ledger_file

    @property
    def reports_dir(self) -> Path:
        """Where Markdown reports are written."""
        return self.root / self.layout.reports

    @property
    def recon_dir(self) -> Path:
        """The working directory for autonomously executed recon commands."""
        return self.root / self.layout.recon

    @property
    def notes_dir(self) -> Path:
        """Free-form operator notes."""
        return self.root / self.layout.notes

    @property
    def notes_file(self) -> Path:
        """The appended operator-notes journal (``notes/notes.md``)."""
        return self.notes_dir / self.layout.notes_log

    @property
    def findings_dir(self) -> Path:
        """Per-finding artefacts (the ledger holds the structured records)."""
        return self.root / self.layout.findings

    @property
    def scripts_dir(self) -> Path:
        """Engagement-specific scripts."""
        return self.root / self.layout.scripts

    @property
    def tests_dir(self) -> Path:
        """Engagement-specific proof-of-concept tests."""
        return self.root / self.layout.tests

    @property
    def loot_dir(self) -> Path:
        """Harvested credentials, cracked hashes and other captured artefacts."""
        return self.root / self.layout.loot

    @property
    def loot_file(self) -> Path:
        """The appended captured-loot journal (``loot/loot.md``)."""
        return self.loot_dir / self.layout.loot_log

    def ensure(self) -> None:
        """Create the workspace tree if it does not already exist (idempotent)."""
        ensure_dir(self.root)
        for rel in self.layout.dirs():
            ensure_dir(self.root / rel)
