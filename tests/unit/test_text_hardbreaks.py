"""L1: `text.markdown_hardbreaks` -- keep an answer's line breaks in the REPL.

`rich.markdown.Markdown` reflows a lone newline into a space, so a multi-line
answer collapses into one run-on paragraph. This helper appends the hard-break
marker (two trailing spaces) to prose lines so they survive, without disturbing
blank-line paragraph breaks, lists, or fenced code.
"""

from __future__ import annotations

from skuggi.common.text import markdown_hardbreaks


def test_single_newlines_between_prose_lines_get_a_hard_break() -> None:
    out = markdown_hardbreaks("line one\nline two")
    assert out == "line one  \nline two"


def test_blank_line_paragraph_breaks_are_untouched() -> None:
    src = "first paragraph\n\nsecond paragraph"
    assert markdown_hardbreaks(src) == src


def test_fenced_code_is_left_literal() -> None:
    src = "intro\n```\na\nb\n```\nafter"
    out = markdown_hardbreaks(src)
    # The intro before the fence and the trailing line get a hard break;
    # the code body inside the fence keeps its literal single newlines.
    assert "```\na\nb\n```" in out
    assert out.startswith("intro  \n```")


def test_a_line_already_ending_in_two_spaces_is_not_doubled() -> None:
    out = markdown_hardbreaks("done already  \nnext")
    assert out == "done already  \nnext"


def test_trailing_line_gets_no_break() -> None:
    assert markdown_hardbreaks("only line") == "only line"
