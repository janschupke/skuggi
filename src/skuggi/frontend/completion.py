"""The shared Tab-completion vocabulary for every front-end.

One ``NestedCompleter``-shaped tree (``{verb: {noun: None, ...} | None}``) built
from the one verb registry plus the live command/config names, so the chat loop
(over the socket), the standalone REPL, and the host-shell ``--complete`` hook
all offer the same candidates and cannot drift from what dispatch accepts.
"""

from __future__ import annotations

from collections.abc import Iterable

from skuggi.frontend import verbs


def completion_tree(
    cmd_names: Iterable[str], reconcile_names: Iterable[str]
) -> dict[str, object]:
    """Build the nested verb/noun vocabulary for a ``NestedCompleter``.

    Grouping verbs expand to their nouns; ``cmd`` to the cheatsheet names;
    ``reconcile`` to the config files (plus ``diff``/``all``). A plain verb maps
    to ``None`` (no further completion). `cmd_names`/`reconcile_names` come from
    the live core so the dynamic leaves stay current.
    """
    tree: dict[str, object] = {}
    for verb in verbs.VERBS:
        nouns = verbs.nouns_of(verb.name)
        tree[verb.name] = {n.name: None for n in nouns} if nouns else None
    tree["cmd"] = dict.fromkeys(cmd_names)
    files: dict[str, object] = dict.fromkeys(reconcile_names)
    tree["reconcile"] = {"diff": dict(files), "all": None, **files}
    return tree
