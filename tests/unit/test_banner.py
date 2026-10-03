"""L1: the wrapped shell's startup banner renderer."""

from __future__ import annotations

from typing import Any

from skuggi.common import palette
from skuggi.frontend.banner import render_startup_banner


def _banner(**over: Any) -> str:
    kwargs: dict[str, Any] = {
        "provider": "anthropic",
        "model": "claude-haiku-4-5",
        "engagement": "acme",
        "has_llm": True,
        "warnings": [],
        "unsupported_shell": None,
    }
    kwargs.update(over)
    return render_startup_banner(**kwargs)


def test_banner_shows_provider_and_model() -> None:
    out = _banner(provider="claude-cli", model="haiku")
    assert "provider claude-cli" in out
    assert "model haiku" in out


def test_banner_lists_each_verb_on_its_own_line_without_the_skuggi_prefix() -> None:
    out = _banner()
    # No pointless "skuggi:" log prefix inside the skuggi shell itself.
    assert "skuggi:" not in out
    assert palette.SHIELD in out
    # Each verb hint is on its own line, not crammed onto one.
    assert "/skuggi ask <prompt>" in out
    assert "/skuggi help" in out
    assert "/skuggi exit" in out
    lines = [ln for ln in out.splitlines() if "/skuggi" in ln]
    assert len(lines) >= 4  # one line per verb


def test_banner_adds_next_steps_only_when_unconfigured() -> None:
    configured = _banner()
    assert "scope an engagement" not in configured
    assert "configure a model" not in configured

    bare = _banner(
        engagement=None,
        has_llm=False,
        warnings=["no engagement selected; running agent-only"],
    )
    assert "no engagement selected; running agent-only" in bare
    assert "scope an engagement" in bare
    assert "configure a model" in bare


def test_banner_notes_an_unsupported_shell_only_when_set() -> None:
    assert "unsupported" not in _banner()
    noted = _banner(unsupported_shell="fish")
    assert "fish is unsupported" in noted
