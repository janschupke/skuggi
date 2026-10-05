"""Per-engagement workspace: the on-disk directory one engagement operates in.

An engagement *is* a directory -- the root you point skuggi at -- with a fixed but
*configurable* layout: ``scope.json`` (the engagement setup) living directly
inside it, plus ``findings``, ``notes``, ``recon`` (with
``nmap``/``dirs``/``domains``/``web`` subdirs), ``reports``, ``scripts``,
``tests`` and ``loot``. There is no ``engagements/<name>/`` wrapper; the root is
chosen per engagement (``set engagement [<path>]``, or the current directory).
Keeping outputs inside the workspace is what makes a session self-contained and
traceable: the ledger, the Markdown reports and any tool output all land next to
the scope that authorized them.

``WorkspaceLayout`` is a frozen model so the folder names can be overridden from
``configs/layout.json`` (harness-level) without touching code; ``Workspace``
turns a layout plus a root path into concrete paths and creates the tree. This is
the analogue of ``open_ledger``'s parent-dir discipline: ``ensure`` is idempotent
and the only thing that writes directories.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from skuggi.common.paths import ensure_dir

# The engagement's display name is free text (``Lab 01``) and is validated into a
# safe token so it can label the ledger/session/report without surprises. It is NO
# LONGER a path segment (the engagement root is chosen directly), so this only
# rejects a name that reduces to nothing usable -- it never names a directory.
_SAFE_SLUG = re.compile(r"[a-z0-9][a-z0-9._-]*")


def safe_engagement_name(name: str) -> str:
    """Normalise `name` into one safe token (``Lab 01`` -> ``lab-01``).

    Used to validate the scope ``name`` label (ledger/session/report slug), not to
    name a directory. Raises ``ValueError`` only when the name reduces to nothing
    usable (empty, all-punctuation, or a bare ``..``) -- the caller surfaces that
    as a re-ask.
    """
    slug = re.sub(r"[^a-z0-9._-]+", "-", name.strip().lower())
    slug = re.sub(r"-{2,}", "-", slug).strip("-._")
    if ".." in slug or not _SAFE_SLUG.fullmatch(slug):
        msg = f"invalid engagement name: {name!r}"
        raise ValueError(msg)
    return slug


def has_engagement(root: Path, layout: WorkspaceLayout | None = None) -> bool:
    """Whether `root` is an engagement directory (holds a scope file).

    The single-directory probe behind cwd discovery and the explicit-override
    check: an empty or half-created folder (no ``scope.json``) is not an
    engagement. A missing `root` yields ``False``.
    """
    resolved = layout or WorkspaceLayout()
    return (root.expanduser() / resolved.scope_file).is_file()


class WorkspaceLayout(BaseModel):
    """The configurable folder structure of an engagement workspace."""

    model_config = ConfigDict(frozen=True)

    scope_file: str = "scope.json"
    # The per-engagement runtime variables (target/lhost/lport/wordlist) the
    # operator plugs into commands -- separate from the scope boundary. See
    # skuggi.engagement.runtime_env.
    env_file: str = "env.json"
    ledger_file: str = "ledger.db"
    notes_log: str = "notes.md"
    loot_log: str = "loot.md"
    findings: str = "findings"
    notes: str = "notes"
    recon: str = "recon"
    recon_subdirs: tuple[str, ...] = ("nmap", "nuclei", "dirs", "domains", "web")
    # The agentic OSINT loop's structured output: one JSON artifact per
    # (subject, source) under ``osint/<subject>/<source>.json``. Separate from
    # ``recon`` (active network output) because OSINT is passive, subject-keyed,
    # and machine-readable. See skuggi.osint.store.
    osint: str = "osint"
    # The public-source research loop's output: a structured Markdown briefing plus
    # one JSON artifact per (subject, source) under ``research/``. Engagement-
    # independent, so research also writes here when run inside an engagement; a
    # run with no engagement falls back to ``./research`` in the cwd. See
    # skuggi.research.report / skuggi.intel.store.
    research: str = "research"
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
    # model (see skuggi.persistence.documents). In a forensics *case* this is also
    # the input directory: the evidence under examination lives here.
    evidence: str = "evidence"
    # The forensics loop's output: a Markdown case report plus one JSON artifact per
    # evidence item under ``forensics/``. Written only in forensics mode, inside a
    # *case* directory (see skuggi.engagement.case); a run with no case falls back to
    # ``./forensics`` in the cwd. Part of the case tree, not the engagement tree.
    forensics: str = "forensics"
    # A forensics case's metadata (``case.json``) and its own SEPARATE ledger
    # (``case.db``) -- kept out of any offensive engagement's ledger. Both live at
    # the case root; a case has no ``scope.json`` and no offensive dirs.
    case_file: str = "case.json"
    case_ledger_file: str = "case.db"

    def dirs(self) -> tuple[str, ...]:
        """Every directory (relative to the workspace root) ``ensure`` creates."""
        recon_subs = tuple(f"{self.recon}/{sub}" for sub in self.recon_subdirs)
        return (
            self.findings,
            self.notes,
            self.recon,
            *recon_subs,
            self.osint,
            self.research,
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
    def at(cls, root: Path, *, layout: WorkspaceLayout | None = None) -> Workspace:
        """The workspace rooted at `root` -- the engagement directory itself.

        `root` *is* the engagement: its ``scope.json``, ledger, recon output and
        reports live directly inside it. The one constructor both
        ``adopt_engagement`` and ``skuggi-visualize`` route through.
        """
        return cls(
            root=root.expanduser(),
            layout=layout or WorkspaceLayout(),
        )

    @property
    def scope_path(self) -> Path:
        """The engagement setup file (``scope.json``)."""
        return self.root / self.layout.scope_file

    @property
    def env_path(self) -> Path:
        """The per-engagement runtime variables file (``env.json``)."""
        return self.root / self.layout.env_file

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
    def osint_dir(self) -> Path:
        """Where the OSINT loop writes its structured JSON artifacts."""
        return self.root / self.layout.osint

    @property
    def research_dir(self) -> Path:
        """Where the public-source research loop writes reports + JSON artifacts."""
        return self.root / self.layout.research

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
        """Files pulled from a target, or the evidence under examination in a case."""
        return self.root / self.layout.evidence

    @property
    def forensics_dir(self) -> Path:
        """Where the forensics loop writes its case report + JSON artifacts."""
        return self.root / self.layout.forensics

    @property
    def case_path(self) -> Path:
        """A forensics case's metadata file (``case.json``)."""
        return self.root / self.layout.case_file

    @property
    def case_ledger_path(self) -> Path:
        """The case's SEPARATE ledger (``case.db``), never an engagement's ledger."""
        return self.root / self.layout.case_ledger_file

    @property
    def custody_key_path(self) -> Path:
        """The per-case chain-of-custody HMAC key (0600 dotfile, not in the DB)."""
        return self.root / ".custody.key"

    def _reserved_files(self) -> set[Path]:
        """Control files a tool must never be pointed at (scope, env, ledger, vault)."""
        return {
            self.scope_path.resolve(),
            self.env_path.resolve(),
            self.ledger_path.resolve(),
            self.vault_path.resolve(),
        }

    def confine_datafile(
        self, relpath: str, *, cwd: Path, extra_roots: tuple[Path, ...] = ()
    ) -> Path:
        """Resolve a tool data-file path the way the tool will, and confine it.

        The autonomously-run command's path is interpreted by the tool relative
        to its working directory (`cwd`), so this resolves it the same way and
        requires the result to stay inside the workspace root -- or one of
        ``extra_roots`` (the operator's standard wordlist directories) -- and not
        be one of the harness control files (``scope.json``/ledger/vault). A
        symlink or ``..`` that climbs out of every allowed root, an absolute
        ``/etc/shadow``, or a reserved file all raise ``ValueError`` -- so a
        wordlist reaches the tool by path while nothing sensitive can.
        """
        candidate = (cwd / relpath).resolve()
        roots = [self.root.resolve(), *(r.expanduser().resolve() for r in extra_roots)]
        if not any(
            candidate == root or candidate.is_relative_to(root) for root in roots
        ):
            msg = f"data-file path escapes the workspace: {relpath!r}"
            raise ValueError(msg)
        if candidate in self._reserved_files():
            msg = f"data-file path targets a harness control file: {relpath!r}"
            raise ValueError(msg)
        return candidate

    def confine_evidence(self, relpath: str, *, cwd: Path) -> Path:
        """Resolve a forensic tool's positional path and confine it to ``evidence/``.

        A read-only forensic tool (``strings``/``file``/``exiftool``) takes the
        artifact as a bare positional argument, which the tool resolves relative to
        its working directory (`cwd`). This resolves it the same way and requires
        the result to stay inside the case ``evidence/`` dir -- so the tool can only
        ever READ evidence, never ``/etc/shadow``, the case ``case.db``, or a
        sibling outside the case reached by a symlink or ``..``. Raises
        ``ValueError`` on any escape. The forensics analogue of
        ``confine_datafile``, but pinned to the one input directory.
        """
        base = self.evidence_dir.resolve()
        candidate = (cwd / relpath).resolve()
        if candidate != base and not candidate.is_relative_to(base):
            msg = f"evidence path escapes the case evidence dir: {relpath!r}"
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

    def case_dirs(self) -> tuple[str, ...]:
        """The directories a forensics *case* uses (no offensive recon/loot tree)."""
        return (self.layout.evidence, self.layout.forensics, self.layout.reports)

    def ensure_case(self) -> None:
        """Create the forensics case tree (evidence/forensics/reports), idempotent.

        A case is engagement-free: it deliberately does NOT create the offensive
        recon/scripts/loot directories ``ensure`` makes, only the read-only
        evidence input dir plus the forensics output and reports dirs.
        """
        ensure_dir(self.root)
        for rel in self.case_dirs():
            ensure_dir(self.root / rel)
