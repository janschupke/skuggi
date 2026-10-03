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

import re
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from skuggi.common.paths import ensure_dir

# An engagement name becomes a directory under ``engagements/``. It is an
# identity, not free text: restrict it to one path segment of safe characters so
# a name like ``../../tmp/x`` or ``/etc/skuggi`` cannot escape the workspace
# root (``engagements_dir / name`` would otherwise traverse, and an absolute
# name makes ``/`` discard the base entirely).
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def safe_engagement_name(name: str) -> str:
    """Return `name` if it is a single safe path segment, else raise ValueError."""
    if ".." in name or not _SAFE_NAME.match(name):
        msg = f"invalid engagement name: {name!r}"
        raise ValueError(msg)
    return name


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
    # Operator-supplied data the agent feeds to tools *by path* (wordlists, user
    # and credential lists, email lists); the agent references the file, a tool
    # reads it, and the contents never enter the model's context.
    inputs: str = "inputs"
    # Files pulled from a target (downloads, exfil, dropped documents). Parsed
    # read-only, never executed; parsed text is redacted before it reaches the
    # model (see skuggi.persistence.documents).
    evidence: str = "evidence"

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
            self.inputs,
            self.evidence,
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
        """The workspace for `name` under `engagements_dir`.

        `name` is validated as a single safe path segment so it cannot traverse
        out of ``engagements_dir`` -- this is the one choke point both
        ``create_engagement`` and ``skuggi-visualize`` route through.
        """
        return cls(
            root=engagements_dir.expanduser() / safe_engagement_name(name),
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
    def vault_path(self) -> Path:
        """The per-engagement secret vault (reversible redaction placeholders).

        A dotfile at the workspace root, deliberately not a ``layout`` field: it
        is harness security plumbing, not an engagement artefact the operator
        browses, and it must never be swept into a report or the dashboard.
        """
        return self.root / ".vault.db"

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

    @property
    def inputs_dir(self) -> Path:
        """Operator-supplied tool inputs (wordlists, user/credential lists)."""
        return self.root / self.layout.inputs

    @property
    def evidence_dir(self) -> Path:
        """Files pulled from a target (downloads, dropped documents)."""
        return self.root / self.layout.evidence

    def _reserved_files(self) -> set[Path]:
        """Control files a tool must never be pointed at (scope, ledger, vault)."""
        return {
            self.scope_path.resolve(),
            self.ledger_path.resolve(),
            self.vault_path.resolve(),
        }

    def confine_datafile(self, relpath: str, *, cwd: Path) -> Path:
        """Resolve a tool data-file path the way the tool will, and confine it.

        The autonomously-run command's path is interpreted by the tool relative
        to its working directory (`cwd`), so this resolves it the same way and
        requires the result to stay inside the workspace root and not be one of
        the harness control files (``scope.json``/ledger/vault). A symlink or
        ``..`` that climbs out, an absolute ``/etc/shadow``, or a reserved file
        all raise ``ValueError`` -- so a wordlist reaches the tool by path while
        nothing outside the engagement's own data can.
        """
        root = self.root.resolve()
        candidate = (cwd / relpath).resolve()
        if root != candidate and not candidate.is_relative_to(root):
            msg = f"data-file path escapes the workspace: {relpath!r}"
            raise ValueError(msg)
        if candidate in self._reserved_files():
            msg = f"data-file path targets a harness control file: {relpath!r}"
            raise ValueError(msg)
        return candidate

    def resolve_within(self, subdir: Path, relpath: str) -> Path:
        """Resolve `relpath` under `subdir`, refusing any escape from `subdir`.

        The confinement guard for every path the agent can influence: a tool
        input or evidence file it names by a workspace-relative path. The result
        is fully resolved (so a symlink pointing out, or a ``..`` climb, is
        caught) and must stay inside the resolved `subdir`; otherwise this raises
        ``ValueError``. Confining to the specific directory -- not merely the
        workspace root -- keeps the agent from pointing a tool at a sibling such
        as ``scope.json`` or ``.vault.db`` via ``../``. ``subdir`` is one of this
        workspace's own directories (``inputs_dir``/``evidence_dir``/``loot_dir``).

        A prefix check would be fooled by a sibling like ``<subdir>-secrets``;
        ``is_relative_to`` on the resolved paths is not.
        """
        base = subdir.resolve()
        candidate = (subdir / relpath).resolve()
        if base != candidate and not candidate.is_relative_to(base):
            msg = f"path escapes the workspace: {relpath!r}"
            raise ValueError(msg)
        return candidate

    def ensure(self) -> None:
        """Create the workspace tree if it does not already exist (idempotent)."""
        ensure_dir(self.root)
        for rel in self.layout.dirs():
            ensure_dir(self.root / rel)
