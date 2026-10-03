"""L1: `text.highlight` -- the matched substring is emphasised in `cmd` search.

The cheatsheet listing paints the whole entry one colour; this wraps each
case-insensitive hit of the query in a second style so the operator sees WHY an
entry matched. The markup must be escaped so a literal bracket in the text can
never open a spurious tag.
"""

from __future__ import annotations

from skuggi.common.text import highlight


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
