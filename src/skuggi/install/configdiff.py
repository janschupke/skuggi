"""Semantic, per-file-type diff between an installed config and its template.

:mod:`skuggi.install.reconcile` detects *that* a file drifted, by normalised-JSON
equality. This module says *what* drifted, in terms meaningful to the file rather
than as a line-by-line JSON text diff:

- **keyed lists** (``tools.json`` / ``commands.json``) are lists of objects each
  identified by a ``name``. Drift is reported as whole entries added or removed,
  plus a per-field change for entries present on both sides.
- **objects** (``config.json`` / ``layout.json``) are flat-ish maps. Drift is
  reported as dotted-path properties: a key added, removed, or changed value.

Direction is installed -> packaged, i.e. what an overwrite would do: ``added`` is
in the template but not the install, ``removed`` is in the install but not the
template, ``changed`` is present on both and differing. Everything here is a pure
function over already-parsed JSON, so the whole thing is unit-tested without
touching disk.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import cast

# A parsed JSON object. The public entry points accept any ``Mapping`` (so a
# caller's narrower dict type is fine); indexed entries are concrete dicts.
JsonMap = Mapping[str, object]
JsonObj = dict[str, object]

# A field present on only one side of a comparison; rendered as an em dash.
_MISSING = object()
_ABSENT = "\N{EM DASH}"


@dataclass(frozen=True, slots=True)
class Change:
    """One property that differs: ``path`` changed from ``old`` to ``new``."""

    path: str
    old: str
    new: str


@dataclass(frozen=True, slots=True)
class StructuredDiff:
    """What an overwrite (installed -> packaged) would add, remove and change.

    ``added``/``removed`` are rendered entry (or property) strings; ``changed`` is
    the per-property deltas. ``empty`` is the semantic "nothing to apply".
    """

    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[Change, ...]

    @property
    def empty(self) -> bool:
        """Whether the two sides are semantically identical."""
        return not (self.added or self.removed or self.changed)


def _render_value(value: object) -> str:
    """A compact, deterministic rendering of a JSON value (``—`` when absent)."""
    if value is _MISSING:
        return _ABSENT
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _render_command(entry: JsonObj) -> str:
    """A command alias as ``name  (argv …)``."""
    name = str(entry.get("name", "?"))
    argv = entry.get("argv", [])
    joined = " ".join(str(a) for a in argv) if isinstance(argv, list) else str(argv)
    return f"{name}  ({joined})"


def _render_tool(entry: JsonObj) -> str:
    """A tool entry as ``name [binary]``."""
    name = str(entry.get("name", "?"))
    binary = str(entry.get("binary", name))
    return f"{name} [{binary}]"


# Installed filename -> (list key, identity field, entry renderer).
_KEYED: dict[str, tuple[str, str, Callable[[JsonObj], str]]] = {
    "tools.json": ("tools", "name", _render_tool),
    "commands.json": ("commands", "name", _render_command),
}


def _index(items: object, id_field: str) -> dict[str, JsonObj]:
    """Index a list of objects by their ``id_field`` (insertion order preserved)."""
    out: dict[str, JsonObj] = {}
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, dict) and id_field in item:
            out[str(item[id_field])] = cast("JsonObj", item)
    return out


def _field_changes(name: str, old: JsonObj, new: JsonObj) -> list[Change]:
    """A ``Change`` per field that differs between two entries of the same name."""
    changes: list[Change] = []
    for field in dict.fromkeys([*old, *new]):
        before = old.get(field, _MISSING)
        after = new.get(field, _MISSING)
        if before != after:
            changes.append(
                Change(f"{name}.{field}", _render_value(before), _render_value(after))
            )
    return changes


def _diff_keyed(
    installed: JsonMap,
    packaged: JsonMap,
    list_key: str,
    id_field: str,
    render_entry: Callable[[JsonObj], str],
) -> StructuredDiff:
    """Diff a list of objects keyed by ``id_field`` (tools / commands)."""
    inst = _index(installed.get(list_key), id_field)
    pack = _index(packaged.get(list_key), id_field)
    added = tuple(render_entry(pack[k]) for k in pack if k not in inst)
    removed = tuple(render_entry(inst[k]) for k in inst if k not in pack)
    changed: list[Change] = []
    for k in pack:
        if k in inst:
            changed.extend(_field_changes(k, inst[k], pack[k]))
    return StructuredDiff(added, removed, tuple(changed))


def _flatten(obj: JsonMap, prefix: str = "") -> dict[str, object]:
    """Flatten nested dicts to dotted paths; lists and scalars are leaves."""
    out: dict[str, object] = {}
    for key, value in obj.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_flatten(cast("JsonObj", value), f"{path}."))
        else:
            out[path] = value
    return out


def _diff_object(installed: JsonMap, packaged: JsonMap) -> StructuredDiff:
    """Diff a flat-ish object by dotted property path (config / layout)."""
    inst = _flatten(installed)
    pack = _flatten(packaged)
    added = tuple(f"{k}: {_render_value(pack[k])}" for k in pack if k not in inst)
    removed = tuple(f"{k}: {_render_value(inst[k])}" for k in inst if k not in pack)
    changed = tuple(
        Change(k, _render_value(inst[k]), _render_value(pack[k]))
        for k in pack
        if k in inst and inst[k] != pack[k]
    )
    return StructuredDiff(added, removed, changed)


def diff(name: str, installed: JsonMap, packaged: JsonMap) -> StructuredDiff:
    """A semantic diff from `installed` to `packaged`, dispatched by filename.

    `name` is the installed filename (e.g. ``tools.json``); the keyed-list files
    route through :func:`_diff_keyed`, everything else through :func:`_diff_object`.
    A missing-file install is passed as ``{}`` by the caller, so everything the
    template has shows up as ``added``.
    """
    keyed = _KEYED.get(name)
    if keyed is not None:
        return _diff_keyed(installed, packaged, *keyed)
    return _diff_object(installed, packaged)
