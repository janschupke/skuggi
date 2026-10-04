"""L1: `text.highlight` -- the matched substring is emphasised in `cmd` search.

The cheatsheet listing paints the whole entry one colour; this wraps each
case-insensitive hit of the query in a second style so the operator sees WHY an
entry matched. The markup must be escaped so a literal bracket in the text can
never open a spurious tag.
"""

from __future__ import annotations

from skuggi.common.text import highlight, split_matches
from skuggi.frontend.render import highlight_spans


def test_empty_query_just_paints_the_base() -> None:
    assert (
        highlight("nmap-full", "", base="cyan", match="reverse")
        == "[cyan]nmap-full[/cyan]"
    )


def test_match_is_wrapped_case_insensitively() -> None:
    out = highlight("nmap-full", "NMAP", base="cyan", match="reverse")
    assert out == "[cyan][reverse]nmap[/reverse]-full[/cyan]"


def test_every_occurrence_is_wrapped() -> None:
    out = highlight("abXabX", "ab", base="dim", match="reverse")
    assert out.count("[reverse]ab[/reverse]") == 2


def test_markup_in_the_text_is_escaped() -> None:
    out = highlight("a[b]c", "b", base="cyan", match="reverse")
    # the literal brackets are escaped, so only the style tags remain real markup
    assert "\\[" in out
    assert "[reverse]b[/reverse]" in out


def test_no_match_returns_the_plain_base() -> None:
    assert (
        highlight("gobuster", "nmap", base="cyan", match="reverse")
        == "[cyan]gobuster[/cyan]"
    )


def test_split_matches_no_hit_is_one_non_match_run() -> None:
    assert split_matches("gobuster", "nmap") == [("gobuster", False)]


def test_split_matches_blank_query_is_one_non_match_run() -> None:
    assert split_matches("nmap-full", "") == [("nmap-full", False)]


def test_split_matches_flags_each_hit_case_insensitively() -> None:
    assert split_matches("Nmap-nmap", "nmap") == [
        ("Nmap", True),
        ("-", False),
        ("nmap", True),
    ]


def test_split_matches_segments_a_mid_string_hit() -> None:
    assert split_matches("web-dir", "b-d") == [
        ("we", False),
        ("b-d", True),
        ("ir", False),
    ]


def test_split_matches_text_concatenation_is_lossless() -> None:
    runs = split_matches("nmap-host service scan", "s")
    assert "".join(seg for seg, _ in runs) == "nmap-host service scan"


def test_highlight_spans_tags_hits_and_leaves_the_rest_unpainted() -> None:
    assert highlight_spans("nmap-full", "nmap", match="reverse") == [
        ("nmap", "reverse"),
        ("-full", None),
    ]


def test_highlight_spans_blank_query_is_one_unpainted_span() -> None:
    assert highlight_spans("nmap-full", "") == [("nmap-full", None)]


def test_highlight_spans_text_is_lossless() -> None:
    spans = highlight_spans("ab-cd-ab", "ab")
    assert "".join(text for text, _ in spans) == "ab-cd-ab"
