"""Semantic colour palette for skuggi's console surfaces.

One source of truth so status, source, sentiment, method and severity read the
same everywhere -- the prompt, the banner, the doctor table, the findings list.
Values are Rich style strings; the module is pure data plus tiny lookups, so no
front-end hardcodes a colour and every mapping is trivially unit-tested.
"""

from __future__ import annotations

# Marks that skuggi is active in a session (the wrapped-shell prompt and the
# REPL prompt both carry it).
SHIELD = "🐐"

# --- sentiment --------------------------------------------------------------
# These four are RESERVED: they carry good/bad meaning, so methods (a
# categorical axis, not a sentiment) must never reuse them -- see `_METHOD`.
SUCCESS = "green"
DANGER = "red"
WARNING = "yellow"
INFO = "dim"

# The terminal's own foreground: a neutral, no-sentiment colour.
NEUTRAL = "default"

# --- where a tool resolved --------------------------------------------------
# Found (host or managed) is neutral -- the status column already carries the
# good/bad signal; only a missing source is danger (the same red as a missing
# status).
_SOURCE = {
    "host": NEUTRAL,
    "managed": NEUTRAL,
    "missing": DANGER,
    "unavailable": DANGER,
}

# --- engagement methods -----------------------------------------------------
# Coarse categories (a tool's registry entry fixes its one method). Each gets a
# defined colour; deliberately drawn from a cool/pink/orange palette that shares
# no colour with the reserved sentiment set above, so a method is never mistaken
# for a good/bad signal.
_METHOD = {
    "recon": "cyan",
    "scan": "blue",
    "enumerate": "magenta",
    "bruteforce": "dark_orange",
    "crack": "medium_purple",
    "exploit": "deep_pink3",
}
_METHOD_DEFAULT = "white"

# --- finding severity -------------------------------------------------------
_SEVERITY = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
_SEVERITY_DEFAULT = "white"


def status_style(*, found: bool) -> str:
    """The style for a found/missing tool status (success / danger)."""
    return SUCCESS if found else DANGER


def source_style(source: str) -> str:
    """The style for where a tool resolved (host/managed neutral, missing danger)."""
    return _SOURCE.get(source, NEUTRAL)


def method_style(method: str | None) -> str:
    """The style for an engagement method category."""
    return _METHOD.get((method or "").lower(), _METHOD_DEFAULT)


def severity_style(severity: str) -> str:
    """The style for a finding severity."""
    return _SEVERITY.get(severity.lower(), _SEVERITY_DEFAULT)


def methods() -> tuple[str, ...]:
    """The methods that have a defined colour (for tests and help)."""
    return tuple(_METHOD)


def severities() -> tuple[str, ...]:
    """The severities that have a defined colour (for tests)."""
    return tuple(_SEVERITY)


def paint(text: str, style: str) -> str:
    """Wrap `text` in Rich markup for `style`."""
    return f"[{style}]{text}[/{style}]"
