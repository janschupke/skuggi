"""L1: the semantic colour palette."""

from __future__ import annotations

import pytest

from skuggi import palette


def test_status_style_distinguishes_found_from_missing() -> None:
    assert palette.status_style(found=True) != palette.status_style(found=False)


@pytest.mark.parametrize(
    "method", ["recon", "scan", "enumerate", "bruteforce", "crack", "exploit"]
)
def test_every_method_has_a_defined_colour(method: str) -> None:
    assert palette.method_style(method) != palette.method_style("something-unknown")


def test_method_style_is_case_insensitive() -> None:
    assert palette.method_style("SCAN") == palette.method_style("scan")


def test_unknown_method_falls_back() -> None:
    assert palette.method_style(None) == palette.method_style("nope")


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
def test_every_severity_has_a_defined_colour(severity: str) -> None:
    assert palette.severity_style(severity) in {
        palette.severity_style(s) for s in palette.severities()
    }


@pytest.mark.parametrize("source", ["host", "managed", "missing"])
def test_every_source_has_a_style(source: str) -> None:
    assert palette.source_style(source)


def test_paint_wraps_in_markup() -> None:
    assert palette.paint("x", "red") == "[red]x[/red]"


def test_methods_and_severities_are_exposed() -> None:
    assert "scan" in palette.methods()
    assert "critical" in palette.severities()


def test_methods_never_reuse_a_sentiment_colour() -> None:
    """Methods are a categorical axis, never a good/bad signal."""
    reserved = {palette.SUCCESS, palette.DANGER, palette.WARNING, palette.INFO}
    for method in palette.methods():
        assert palette.method_style(method) not in reserved


def test_status_uses_sentiment_colours() -> None:
    assert palette.status_style(found=True) == palette.SUCCESS
    assert palette.status_style(found=False) == palette.DANGER


def test_source_found_is_neutral_missing_is_danger() -> None:
    assert palette.source_style("host") == palette.NEUTRAL
    assert palette.source_style("managed") == palette.NEUTRAL
    assert palette.source_style("missing") == palette.DANGER
    # A missing source shares the missing-status danger colour.
    assert palette.source_style("missing") == palette.status_style(found=False)
