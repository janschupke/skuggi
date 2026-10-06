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

import re
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from prompt_toolkit.completion import CompleteEvent, Completer, Completion
    from prompt_toolkit.document import Document
    from prompt_toolkit.key_binding import KeyBindings, KeyPressEvent

from skuggi.common.modes import MODES
from skuggi.frontend import engagement_params, verbs

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
            if n.options:
                # A hierarchical noun (``set engagement``): descend to its params,
                # and offer the enum params' value sets a level further down.
                node[n.name] = {
                    o.name: _values_node(vals)
                    if (vals := engagement_params.enum_values(o.name))
                    else None
                    for o in n.options
                }
                continue
            values = _STATIC_VALUES.get((verb.name, n.name)) or dynamic.get(
                (verb.name, n.name)
            )
            node[n.name] = _values_node(values) if values else None
        tree[verb.name] = node
    tree["cmd"] = dict.fromkeys(cmd_names)
    files: dict[str, object] = dict.fromkeys(reconcile_names)
    tree["reconcile"] = {"diff": dict(files), "all": None, **files}
    return tree


# --- Interactive Tab behavior (prompt_toolkit surfaces only) ------------------
#
# Stock ``NestedCompleter`` falls short in two ways the REPL and attach loop need
# fixed. (1) Its per-level ``WordCompleter`` uses the default word pattern, which
# breaks on ``-``/``.`` -- so ``cmd nmap-h`` or ``set model gpt-5-`` stop matching
# the moment you type past the hyphen/dot. ``build_completer`` swaps in a
# whole-token (``\S+``) pattern so hyphenated/dotted leaves complete. (2) At the
# end of a complete word it re-offers the same word and nothing advances;
# ``install_tab_binding`` makes Tab insert a space there (bash-like), so the next
# Tab lists the children.
#
# prompt_toolkit is imported lazily inside these functions: the module stays
# ptk-free for the daemon's fire-and-forget ``--complete`` tree build.


def build_completer(tree: dict[str, object]) -> Completer:
    """A completer whose per-level matcher treats a whole token as the word.

    So ``nmap-host``/``gpt-5-mini``/``config.json`` complete past the ``-``/``.``
    that the stock ``WordCompleter`` word pattern would treat as a boundary.
    """
    from prompt_toolkit.completion import (  # noqa: PLC0415 -- keep ptk off hot paths
        NestedCompleter,
        WordCompleter,
    )

    class _TokenNestedCompleter(NestedCompleter):
        r"""``NestedCompleter`` with a whole-token (``\S+``) word pattern.

        ``from_nested_dict`` builds via ``cls``, so this subclass propagates to
        every nested level. Only the no-space (leaf-of-recursion) branch differs
        from the base: it builds its ``WordCompleter`` with the token pattern.
        """

        def get_completions(
            self, document: Document, complete_event: CompleteEvent
        ) -> Iterator[Completion]:
            text = document.text_before_cursor.lstrip()
            stripped_len = len(document.text_before_cursor) - len(text)
            if " " in text:
                first_term = text.split()[0]
                completer = self.options.get(first_term)
                if completer is not None:
                    remaining_text = text[len(first_term) :].lstrip()
                    move_cursor = len(text) - len(remaining_text) + stripped_len
                    from prompt_toolkit.document import Document  # noqa: PLC0415

                    new_document = Document(
                        remaining_text,
                        cursor_position=document.cursor_position - move_cursor,
                    )
                    yield from completer.get_completions(new_document, complete_event)
            else:
                word_completer = WordCompleter(
                    list(self.options.keys()),
                    ignore_case=self.ignore_case,
                    pattern=re.compile(r"\S+"),
                )
                yield from word_completer.get_completions(document, complete_event)

    return _TokenNestedCompleter.from_nested_dict(tree)


def _node_at(tree: dict[str, object], tokens: Iterable[str]) -> object | None:
    """Walk `tree` by the already-complete `tokens`; the node reached, or None.

    Mirrors the daemon's host-shell ``_complete`` walk so both surfaces resolve a
    partial line to the same node.
    """
    node: object = tree
    for tok in tokens:
        if isinstance(node, dict) and tok in node:
            node = node[tok]
        else:
            return None
    return node


def tab_inserts_space(tree: dict[str, object], text_before_cursor: str) -> bool:
    """Whether Tab should insert a space rather than complete.

    True only when the cursor sits at the end of a complete, UNAMBIGUOUS word: the
    text is non-empty and does not end in whitespace, its last token is an exact
    key at the resolved node, and that token is not a strict prefix of any sibling
    key (so a word that is also a prefix of a longer one still completes normally).
    """
    if not text_before_cursor or text_before_cursor[-1].isspace():
        return False
    tokens = text_before_cursor.split()
    node = _node_at(tree, tokens[:-1])
    if not isinstance(node, dict):
        return False
    last = tokens[-1]
    if last not in node:
        return False
    return not any(k != last and k.startswith(last) for k in node)


def install_tab_binding(bindings: KeyBindings, tree: dict[str, object]) -> None:
    """Add the "space at the end of a valid word" Tab handler to `bindings`.

    At a complete word, Tab inserts a space (so the next Tab lists the children);
    otherwise it defers to prompt_toolkit's own readline-style completion (fill the
    common prefix, a second Tab lists), i.e. the prior behavior is unchanged there.
    """
    from prompt_toolkit.key_binding.bindings.completion import (  # noqa: PLC0415
        display_completions_like_readline,
    )

    @bindings.add("tab")
    def _(event: KeyPressEvent) -> None:
        buf = event.current_buffer
        if tab_inserts_space(tree, buf.document.text_before_cursor):
            buf.insert_text(" ")
        else:
            display_completions_like_readline(event)
