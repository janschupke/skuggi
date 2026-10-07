"""The lab manifest: the machine-readable contract for one practice lab.

Every ``labs/<id>/manifest.json`` declares what the lab publishes, how to bring
its target back to a pristine planted state, and the loot a completed engagement
should recover. ``labctl`` reads only this file to orchestrate a lab, and the
offline ``tests/unit/test_labs_static.py`` validates every manifest against this
schema so a malformed lab is caught by ``make check`` without booting docker.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Tier = Literal["trivial", "easy", "medium", "hard"]
LootKind = Literal["http_contains", "file_in_container", "container_exec", "tcp_banner"]
RestoreStrategy = Literal["recreate", "reseed"]


class PortMap(BaseModel):
    """One loopback-published port for a lab service."""

    model_config = ConfigDict(frozen=True)

    service: str
    container: int
    published: int
    proto: str = "http"


class Health(BaseModel):
    """How to tell the lab has finished booting."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["http", "tcp"] = "http"
    url: str | None = None
    host: str | None = None
    port: int | None = None


class Restore(BaseModel):
    """How ``labctl restore`` reverts the target to its pristine planted state.

    ``recreate`` drops the volumes and brings the stack back up (a fresh
    first-boot seed). ``reseed`` execs ``exec`` inside ``service`` to re-seed in
    place, keeping the containers running -- faster, and it never disturbs an
    engagement mid-flight.
    """

    model_config = ConfigDict(frozen=True)

    strategy: RestoreStrategy = "recreate"
    service: str | None = None
    exec: tuple[str, ...] = ()


class Loot(BaseModel):
    """One piece of planted data a finished engagement should recover.

    The ``fingerprint`` is the stable oracle -- a hash, a sentinel string, or a
    filename -- that ``labctl verify`` looks for, proving a restore seeded the
    target correctly (and letting a future scoring harness auto-grade).
    """

    model_config = ConfigDict(frozen=True)

    id: str
    kind: LootKind
    fingerprint: str
    description: str = ""
    # http_contains: the URL to GET. file_in_container: {service, path}.
    # container_exec: {service, cmd} (a query, e.g. a mongosh/psql eval).
    # tcp_banner: {host, port}.
    where: str | None = None
    service: str | None = None
    path: str | None = None
    cmd: tuple[str, ...] = ()
    host: str | None = None
    port: int | None = None


class LabManifest(BaseModel):
    """The full contract for one lab, loaded from ``labs/<id>/manifest.json``."""

    model_config = ConfigDict(frozen=True)

    id: str
    tier: Tier
    title: str
    summary: str = ""
    networks: tuple[str, ...] = ()
    ports: tuple[PortMap, ...] = ()
    health: Health | None = None
    restore: Restore = Field(default_factory=Restore)
    loot: tuple[Loot, ...] = ()

    # Both set by the loader; never present in the JSON on disk. ``category`` is
    # derived from layout -- "base" for a flat ``labs/<id>`` lab, otherwise the
    # name of the one grouping subdirectory it lives under (e.g. "webapp" for
    # ``labs/webapp/<id>``).
    root: Path = Field(default=Path(), exclude=True)
    category: str = Field(default="base", exclude=True)

    @property
    def compose_file(self) -> Path:
        """The lab's docker-compose file."""
        return self.root / "docker-compose.yml"

    @property
    def scope_file(self) -> Path:
        """The drop-in skuggi engagement scope for this lab."""
        return self.root / "scope.json"


def _is_lab_dir(p: Path) -> bool:
    """Whether ``p`` is a numbered lab directory (not ``_lib``/``_common``/dotdir)."""
    return p.is_dir() and not p.name.startswith(("_", ".")) and p.name[0].isdigit()


def _lab_dirs(labs_dir: Path) -> list[tuple[str, Path]]:
    """Every lab under ``labs_dir`` as ``(category, dir)``, sorted by category then id.

    Discovery is one level deep. A numbered directory directly under ``labs_dir``
    is a ``base`` lab; a numbered directory one level inside a non-underscore
    grouping subdirectory (e.g. ``labs/webapp/01-...``) belongs to the category
    named by that subdirectory. Underscore/dot entries (``_lib``, ``_common``)
    are skipped at both levels.
    """
    found: list[tuple[str, Path]] = []
    for p in sorted(labs_dir.iterdir()):
        if p.name.startswith(("_", ".")) or not p.is_dir():
            continue
        if p.name[0].isdigit():
            found.append(("base", p))
        else:
            found.extend((p.name, q) for q in sorted(p.iterdir()) if _is_lab_dir(q))
    return sorted(found, key=lambda cd: (cd[0] != "base", cd[0], cd[1].name))


def load_manifest(lab_dir: Path, category: str = "base") -> LabManifest:
    """Load and validate one lab's manifest, binding its ``root`` and ``category``."""
    raw = json.loads((lab_dir / "manifest.json").read_text(encoding="utf-8"))
    return LabManifest.model_validate({**raw, "root": lab_dir, "category": category})


def discover_labs(labs_dir: Path) -> list[LabManifest]:
    """Every lab under ``labs_dir``, validated, sorted by category then id."""
    return [load_manifest(d, category) for category, d in _lab_dirs(labs_dir)]


def resolve_lab(labs_dir: Path, lab_id: str) -> LabManifest:
    """Load one lab by id from any category, raising ``KeyError`` if unknown.

    Searches the flat ``base`` root and every grouping subdirectory so a webapp
    lab (``labs/webapp/<id>``) resolves by its bare id, just like a base lab.
    """
    for category, d in _lab_dirs(labs_dir):
        if d.name == lab_id:
            return load_manifest(d, category)
    msg = f"unknown lab: {lab_id!r} (no manifest.json under {labs_dir})"
    raise KeyError(msg)
