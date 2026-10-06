"""The shared Tab-completion vocabulary -- structure + value-level guards.

`set mode <TAB>` silently did nothing because every noun leaf in the tree was a
dead ``None``. These tests pin the fix and stop a new value-bearing noun from
shipping with dead completion again.
"""

from __future__ import annotations

from skuggi.common.modes import MODES
from skuggi.frontend import completion, verbs

# Nouns that take a fixed, enumerable value and therefore MUST expand past the
# noun to a value set (never a dead ``None``). Dynamic ones (provider/model) are
# covered by passing names in below.
_MUST_EXPAND = {
    ("set", "mode"),
    ("set", "autonomous"),
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


def test_every_grouping_verb_has_a_noun_dict() -> None:
    # The tree must carry every grouping verb's nouns (so `set <TAB>` lists them).
    tree = _tree()
    for grouping in ("show", "set", "add", "remove"):
        node = tree[grouping]
        assert isinstance(node, dict)
        assert set(node) == set(verbs.noun_names(grouping))
