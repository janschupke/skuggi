"""Detect and reconcile config drift against the packaged templates.

``init`` seeds a config file only when it is *missing* and never overwrites one
that already exists (see its "nothing is ever overwritten" guarantee). That is
right for an operator's edits, but it also means a *newer* packaged template --
say ``tools.json`` gaining an ``-oA`` output convention for nmap -- never reaches
an install that already has the file. The installed copy silently falls behind
the shipped one, and a ``cmd`` rendered from it is missing the newer behaviour.

This module closes that gap without ever destroying an operator's edits:

- :func:`status` / :func:`drifted` compare each installed config against its
  packaged template by *normalised* JSON (so a reformat or a key reorder is not
  reported as drift), classifying each file ``up_to_date`` / ``drifted`` /
  ``missing``.
- :func:`diff_text` shows exactly what an overwrite would change.
- :func:`overwrite` replaces the installed file with the packaged template, but
  only after copying the current file into a timestamped backup first.

The operator drives all of this explicitly (the ``reconcile`` verb); the banner
and ``skuggi-init`` only *note* that drift exists.
"""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from skuggi.common.paths import ensure_dir, packaged_template
from skuggi.install.init import SEEDED

State = Literal["up_to_date", "drifted", "missing"]

# Installed filename -> packaged template filename, taken from init's seed map so
# the two can never diverge. ``scope.example.json`` is deliberately absent: a
# scope is per-engagement case data seeded via ``set engagement``, not
# harness config.
_PAIRS: dict[str, str] = {installed: template for template, installed in SEEDED}

# Where overwrite stashes the pre-update copy of a file (under the config home).
BACKUP_DIRNAME = "backups"


@dataclass(frozen=True, slots=True)
class FileStatus:
    """One installed config file compared to its packaged template."""

    name: str  # installed filename, e.g. "tools.json"
    template: str  # packaged template filename, e.g. "tools.example.json"
    state: State


def known_names() -> tuple[str, ...]:
    """The installed config filenames this module can reconcile."""
    return tuple(_PAIRS)


def is_known(name: str) -> bool:
    """Whether `name` is a reconcilable config filename."""
    return name in _PAIRS


def _normalise(raw: bytes) -> str:
    """Canonical form for comparison: sorted-key JSON, else the raw text.

    Normalising means whitespace or key-order differences (a hand reformat, a
    re-serialise) are not mistaken for a genuine content change; a file that
    fails to parse as JSON falls back to a byte-for-byte text comparison.
    """
    try:
        return json.dumps(json.loads(raw), sort_keys=True, indent=2)
    except (ValueError, TypeError):
        return raw.decode("utf-8", "replace")


def _packaged(template: str) -> bytes:
    return packaged_template(template).read_bytes()


def status(config_dir: Path) -> tuple[FileStatus, ...]:
    """Classify every reconcilable config file in `config_dir`."""
    out: list[FileStatus] = []
    for name, template in _PAIRS.items():
        dest = config_dir / name
        if not dest.exists():
            out.append(FileStatus(name, template, "missing"))
            continue
        same = _normalise(dest.read_bytes()) == _normalise(_packaged(template))
        out.append(FileStatus(name, template, "up_to_date" if same else "drifted"))
    return tuple(out)


def drifted(config_dir: Path) -> tuple[str, ...]:
    """The names of installed config files that differ from their template."""
    return tuple(s.name for s in status(config_dir) if s.state == "drifted")


def diff_text(config_dir: Path, name: str) -> str:
    """Unified diff from the installed file to the packaged template.

    Empty when the two are identical (nothing to apply). Both sides are the
    normalised form, so the diff shows real content changes, not reformatting.
    """
    template = _PAIRS[name]
    dest = config_dir / name
    current = _normalise(dest.read_bytes()) if dest.exists() else ""
    packaged = _normalise(_packaged(template))
    if current == packaged:
        return ""
    return "".join(
        difflib.unified_diff(
            current.splitlines(keepends=True),
            packaged.splitlines(keepends=True),
            fromfile=f"installed/{name}",
            tofile=f"packaged/{template}",
        )
    )


def _stamp() -> str:
    """A filesystem-safe timestamp (no colons, unlike an ISO instant)."""
    return datetime.now().strftime("%Y-%m-%d_%H%M%S")  # noqa: DTZ005 -- local wall clock for a human-named backup


def overwrite(config_dir: Path, name: str) -> Path | None:
    """Replace the installed file with the packaged template, backing up first.

    Returns the backup path, or ``None`` when there was no existing file to back
    up (a ``missing`` file, which this simply seeds). Nothing is destroyed: the
    previous contents are always recoverable from the returned backup.
    """
    template = _PAIRS[name]
    dest = config_dir / name
    backup: Path | None = None
    if dest.exists():
        backup = ensure_dir(config_dir / BACKUP_DIRNAME) / f"{name}.{_stamp()}.bak"
        backup.write_bytes(dest.read_bytes())
    dest.write_bytes(_packaged(template))
    return backup
