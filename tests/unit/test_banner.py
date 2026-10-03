"""L1: the wrapped shell's startup banner renderer."""

from __future__ import annotations

from typing import Any

from skuggi.agent.readiness import Readiness
from skuggi.common import palette
from skuggi.frontend.banner import render_startup_banner


def _readiness(**over: Any) -> Readiness:
    fields: dict[str, Any] = {
        "provider": "anthropic",
        "model": "claude-haiku-4-5",
        "has_llm": True,
        "provider_configured": True,
        "engagement": "acme",
        "autonomous": False,
        "mode": "pentest",
        "warnings": (),
    }
    fields.update(over)
    return Readiness(**fields)


def _banner(unsupported_shell: str | None = None, **over: Any) -> str:
    return render_startup_banner(
        readiness=_readiness(**over), unsupported_shell=unsupported_shell
    )


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
        provider_configured=False,
        warnings=("no engagement selected; running agent-only",),
    )
    assert "no engagement selected; running agent-only" in bare
    assert "scope an engagement" in bare
    assert "configure a model" in bare
    # The remedy is phrased in the shell grammar.
    assert "/skuggi set provider" in bare
    assert "/skuggi engagement setup" in bare


def test_banner_notes_an_unsupported_shell_only_when_set() -> None:
    assert "unsupported" not in _banner()
    noted = _banner(unsupported_shell="fish")
    assert "fish is unsupported" in noted
