"""L1: the directive heuristic that gates automatic memory capture (pure)."""

from __future__ import annotations

import pytest

from skuggi.preferences import looks_like_directive


@pytest.mark.parametrize(
    "text",
    [
        "always prefer ffuf over gobuster",
        "From now on keep answers terse",
        "never run intrusive scans without asking",
        "use nmap over masscan for the final pass",
        "please remember to cite command ids",
        "by default write helper scripts in python",
        "don't include raw output in the report",
    ],
)
def test_directive_phrasings_are_recognised(text: str) -> None:
    assert looks_like_directive(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "what is exposed on the target?",
        "scan the web host",
        "list the open services",
        "summarize the findings so far",
        "",
    ],
)
def test_ordinary_requests_are_not_directives(text: str) -> None:
    assert looks_like_directive(text) is False
