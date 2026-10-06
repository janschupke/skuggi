"""Lint the one usage grammar so help formatting can't silently drift again.

The harness had two bugs the operator hit: the top-level help outline inlined full
argument grammar (bloating lines like ``doctor [install <tool>|...]``), and the
usage strings mixed two conventions (``<a|b>`` tight vs ``[a | b]`` spaced,
``[filter]`` vs ``[<path>]``). These tests pin the fix:

- every ``Verb``/``Noun`` usage obeys one grammar (``<req>`` / ``[opt]``,
  alternation ``a|b`` with no surrounding spaces, no nested same-type brackets);
- the outline carries NO grammar (name + summary only); grammar lives in detail.
"""

from __future__ import annotations

import re

import pytest

from skuggi.frontend import verbs

# Every usage token the registry declares, labelled for a readable failure.
_USAGES: list[tuple[str, str]] = [
    *((v.name, v.usage) for v in verbs.VERBS),
    *((f"{v.name} {n.name}", n.usage) for v in verbs.VERBS for n in v.nouns),
]

# A generous sanity bound on a single detail row's "invocation usage" cell, so a
# runaway grammar string is caught even though the outline no longer inlines it.
_DETAIL_WIDTH = 64


def _max_depth(usage: str, open_ch: str, close_ch: str) -> int:
    depth = peak = 0
    for ch in usage:
        if ch == open_ch:
            depth += 1
            peak = max(peak, depth)
        elif ch == close_ch:
            depth -= 1
    assert depth == 0, f"unbalanced {open_ch}{close_ch} in {usage!r}"
    return peak


@pytest.mark.parametrize(("name", "usage"), [(n, u) for n, u in _USAGES if u])
def test_usage_obeys_the_one_grammar(name: str, usage: str) -> None:
    # Brackets are balanced and never nested in their own kind (a `<>` may sit
    # inside a `[]` group -- `[note <text>]` -- but never `[x [y]]` or `<a <b>>`).
    assert _max_depth(usage, "<", ">") <= 1, f"{name}: nested <> in {usage!r}"
    assert _max_depth(usage, "[", "]") <= 1, f"{name}: nested [] in {usage!r}"
    # Alternation is tight: no spaces padding a `|`.
    assert " | " not in usage, f"{name}: spaced alternation in {usage!r}"
    assert not re.search(r"\|\s|\s\|", usage), f"{name}: spaced pipe in {usage!r}"
    # No padding just inside a bracket.
    assert not re.search(r"[\[<]\s|\s[\]>]", usage), (
        f"{name}: inner padding in {usage!r}"
    )


@pytest.mark.parametrize(("name", "usage"), [(n, u) for n, u in _USAGES if u])
def test_detail_row_width_is_bounded(name: str, usage: str) -> None:
    assert len(f"{name} {usage}") <= _DETAIL_WIDTH, f"{name}: grammar too wide"


def test_outline_carries_no_argument_grammar() -> None:
    # The top-level outline is name + summary only -- grammar lives in `help <verb>`.
    # (This is what stops a rich-grammar verb from bloating the outline again.)
    for _title, rows in verbs.help_sections():
        for invocation, _summary in rows:
            assert not re.search(r"[<>\[\]|]", invocation), invocation
            assert " " not in invocation, invocation
