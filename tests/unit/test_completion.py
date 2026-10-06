"""The shared Tab-completion vocabulary -- structure + value-level guards.

`set mode <TAB>` silently did nothing because every noun leaf in the tree was a
dead ``None``. These tests pin the fix and stop a new value-bearing noun from
shipping with dead completion again.
"""

from __future__ import annotations

from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document

from skuggi.common.modes import MODES
from skuggi.frontend import completion, verbs

# Nouns that take a fixed, enumerable value and therefore MUST expand past the
# noun to a value set (never a dead ``None``). Dynamic ones (provider/model) are
# covered by passing names in below.
_MUST_EXPAND = {
    ("set", "mode"),
    ("remove", "memory"),
    ("show", "tools"),
}


def _tree() -> dict[str, object]:
    return completion.completion_tree(
        ["nmap-host"],
        ["config.json"],
        provider_names=["openai", "ollama"],
        model_names=["gpt-5"],
    )


def test_set_mode_expands_to_the_modes() -> None:
    tree = _tree()
    assert set(tree["set"]["mode"]) == set(MODES)  # type: ignore[index]


def test_known_value_nouns_are_not_dead_leaves() -> None:
    tree = _tree()
    for verb, noun in _MUST_EXPAND:
        leaf = tree[verb][noun]  # type: ignore[index]
        assert isinstance(leaf, dict), f"{verb} {noun} is a dead leaf"
        assert leaf, f"{verb} {noun} expands to nothing"
    # a provider/model leaf expands from the passed-in dynamic names
    assert set(tree["set"]["provider"]) == {"openai", "ollama"}  # type: ignore[index]
    assert set(tree["set"]["model"]) == {"gpt-5"}  # type: ignore[index]


def test_set_engagement_descends_to_params_and_enums() -> None:
    tree = _tree()
    eng = tree["set"]["engagement"]  # type: ignore[index]
    assert isinstance(eng, dict)
    assert {"methodology", "osint", "allowed_hosts"} <= set(eng)
    assert set(eng["methodology"]) == {"phases", "ptes", "attack"}  # enum values
    assert set(eng["autonomous"]) == {"on", "off"}
    assert eng["osint"] is None  # composite -> no value-level completion


def test_every_grouping_verb_has_a_noun_dict() -> None:
    # The tree must carry every grouping verb's nouns (so `set <TAB>` lists them).
    tree = _tree()
    for grouping in ("show", "set", "add", "remove"):
        node = tree[grouping]
        assert isinstance(node, dict)
        assert set(node) == set(verbs.noun_names(grouping))


# --- Interactive Tab behavior ------------------------------------------------


def _complete(text: str) -> list[str]:
    """The completions the interactive completer offers for `text` (cursor at end)."""
    completer = completion.build_completer(_tree())
    doc = Document(text, len(text))
    return [
        c.text
        for c in completer.get_completions(
            doc, CompleteEvent(completion_requested=True)
        )
    ]


def test_partial_hyphenated_and_dotted_names_complete() -> None:
    # Stock NestedCompleter breaks on `-`/`.`; build_completer uses a whole-token
    # pattern so a partial past the separator still matches the full name.
    assert "nmap-host" in _complete("cmd nmap-h")  # hyphen, cmd cheatsheet name
    assert "config.json" in _complete("reconcile config.j")  # dot, reconcile file
    # a bare-prefix partial (no separator yet) keeps working too
    assert "nmap-host" in _complete("cmd nm")


def test_tab_inserts_space_only_at_a_complete_unambiguous_word() -> None:
    tree = _tree()
    # end of a complete word -> Tab should add a space (then the next Tab descends)
    assert completion.tab_inserts_space(tree, "set") is True
    assert completion.tab_inserts_space(tree, "cmd") is True
    # a partial word -> complete it, do not add a space
    assert completion.tab_inserts_space(tree, "se") is False
    # trailing space -> already descended; let completion list the children
    assert completion.tab_inserts_space(tree, "set ") is False
    # a nested complete, unambiguous noun also advances
    assert completion.tab_inserts_space(tree, "set provider") is True
    # but `mode` is a strict prefix of `model`, so it completes instead of a space
    assert completion.tab_inserts_space(tree, "set mode") is False


def test_tab_does_not_add_space_when_word_is_a_prefix_of_a_sibling() -> None:
    # A complete word that is also a strict prefix of a sibling must still complete
    # (to reach the longer sibling) rather than swallow a space.
    tree: dict[str, object] = {"set": None, "setup": None}
    assert completion.tab_inserts_space(tree, "set") is False
    assert completion.tab_inserts_space(tree, "setup") is True
