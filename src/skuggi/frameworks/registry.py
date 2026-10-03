"""Offline lookups over the vendored framework taxonomies.

Reads the version-pinned JSON that ``scripts/sync_frameworks.py`` produced and
shipped under ``data/``. Never fetches -- resolution and validation are pure reads
of the committed snapshot, so classifying a finding is deterministic and works with
no network, exactly like the CVSS engine.

- ``wstg``   -- OWASP Web Security Testing Guide test IDs (WSTG-XXXX-NN)
- ``attack`` -- MITRE ATT&CK Enterprise technique IDs (Txxxx[.nnn])
- ``ptes``   -- PTES engagement phases (PTES-NN)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from typing import Final, Literal, cast

Framework = Literal["wstg", "attack", "ptes"]
FRAMEWORKS: Final[tuple[Framework, ...]] = ("wstg", "attack", "ptes")


class FrameworkError(KeyError):
    """Raised when an unknown framework is requested."""


@dataclass(frozen=True, slots=True)
class FrameworkRef:
    """One resolved taxonomy entry: the id, its human title, and a link."""

    framework: Framework
    id: str
    title: str
    url: str


def _load(framework: Framework) -> dict[str, object]:
    resource = files("skuggi.frameworks") / "data" / f"{framework}.json"
    return cast("dict[str, object]", json.loads(resource.read_text(encoding="utf-8")))


@cache
def _index(framework: Framework) -> dict[str, FrameworkRef]:
    """Id-to-:class:`FrameworkRef` map for one framework, cached after first read."""
    if framework not in FRAMEWORKS:
        msg = f"unknown framework {framework!r}; known: {', '.join(FRAMEWORKS)}"
        raise FrameworkError(msg)
    entries = cast("list[dict[str, str]]", _load(framework)["entries"])
    return {
        e["id"]: FrameworkRef(
            framework=framework, id=e["id"], title=e["title"], url=e["url"]
        )
        for e in entries
    }


def resolve(framework: Framework, ref_id: str) -> FrameworkRef | None:
    """The entry for ``ref_id`` in ``framework``, or None if there is no such id."""
    return _index(framework).get(ref_id)


def validate_id(framework: Framework, ref_id: str) -> bool:
    """Whether ``ref_id`` is a real id in ``framework`` (the classification guard)."""
    return ref_id in _index(framework)


def entries(framework: Framework) -> tuple[FrameworkRef, ...]:
    """Every entry in ``framework``, id-sorted."""
    return tuple(_index(framework).values())


def provenance(framework: Framework) -> dict[str, object]:
    """The vendored snapshot's provenance (source, pin, version, fetch date)."""
    if framework not in FRAMEWORKS:
        msg = f"unknown framework {framework!r}; known: {', '.join(FRAMEWORKS)}"
        raise FrameworkError(msg)
    return cast("dict[str, object]", _load(framework)["provenance"])
