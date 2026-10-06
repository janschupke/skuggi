"""The shared Tab-completion vocabulary for every front-end.

One ``NestedCompleter``-shaped tree (``{verb: {noun: {value: None} | None} | ...}``)
built from the one verb registry plus the live command/config/provider/model
names, so the chat loop (over the socket), the standalone REPL, and the host-shell
``--complete`` hook all offer the same candidates and cannot drift from what
dispatch accepts. Crucially the tree now descends past the noun to the VALUE level
(``set mode <TAB>`` -> the four modes), which it previously did not -- every noun
leaf was a dead ``None``.
"""

from __future__ import annotations

from collections.abc import Iterable

from skuggi.common.modes import MODES
from skuggi.frontend import verbs

# Noun leaves whose argument is a fixed, enumerable set. Dynamic leaves (provider,
# model, cmd, reconcile files) are injected from the live core by the caller.
_STATIC_VALUES: dict[tuple[str, str], tuple[str, ...]] = {
    ("set", "mode"): MODES,
    ("set", "autonomous"): ("on", "off"),
    ("set", "thread"): ("new",),
    ("remove", "memory"): ("all",),
    ("show", "tools"): ("all", "scoped", "installed", "missing"),
}


def _values_node(values: Iterable[str]) -> dict[str, object]:
    return dict.fromkeys(values)


def provider_model_names(provider: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The provider names and the curated models for `provider`, for the tree.

    Lazily imported so the completion vocabulary can be built without eagerly
    pulling the config/setup layers on cold paths.
    """
    from skuggi.config.config import PROVIDERS  # noqa: PLC0415
    from skuggi.frontend.setup import curated_models  # noqa: PLC0415

    return PROVIDERS, tuple(curated_models(provider))


def completion_tree(
    cmd_names: Iterable[str],
    reconcile_names: Iterable[str],
    *,
    provider_names: Iterable[str] = (),
    model_names: Iterable[str] = (),
) -> dict[str, object]:
    """Build the nested verb/noun/value vocabulary for a ``NestedCompleter``.

    Grouping verbs expand to their nouns; a noun with a known value set expands to
    those values (``set mode`` -> the modes, ``set provider`` -> `provider_names`)
    rather than dead-ending at ``None``. ``cmd`` expands to the cheatsheet names and
    ``reconcile`` to the config files. The dynamic leaves come from the live core so
    they stay current.
    """
    dynamic: dict[tuple[str, str], tuple[str, ...]] = {
        ("set", "provider"): tuple(provider_names),
        ("set", "model"): tuple(model_names),
    }
    tree: dict[str, object] = {}
    for verb in verbs.VERBS:
        nouns = verbs.nouns_of(verb.name)
        if not nouns:
            tree[verb.name] = None
            continue
        node: dict[str, object] = {}
        for n in nouns:
            values = _STATIC_VALUES.get((verb.name, n.name)) or dynamic.get(
                (verb.name, n.name)
            )
            node[n.name] = _values_node(values) if values else None
        tree[verb.name] = node
    tree["cmd"] = dict.fromkeys(cmd_names)
    files: dict[str, object] = dict.fromkeys(reconcile_names)
    tree["reconcile"] = {"diff": dict(files), "all": None, **files}
    return tree
