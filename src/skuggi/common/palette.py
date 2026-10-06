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

# One glyph per operating mode, shown right after the shield in the interactive
# prompt so the active mode is always visible. Single-sourced here like SHIELD so
# no front-end hardcodes an emoji; `mode_glyph` falls back to "" for an unknown
# mode (a new mode shows no glyph rather than crashing the prompt).
_MODE_GLYPH = {
    "pentest": "⚔️",
    "redteam": "🔴",
    "blueteam": "🔵",
    "forensics": "🚔",
}

# --- sentiment --------------------------------------------------------------
# These four are RESERVED: they carry good/bad meaning, so methods (a
# categorical axis, not a sentiment) must never reuse them -- see `_METHOD`.
SUCCESS = "green"
DANGER = "red"
WARNING = "yellow"
INFO = "dim"

# The terminal's own foreground: a neutral, no-sentiment colour.
NEUTRAL = "default"

# --- structured-output roles ------------------------------------------------
# The vocabulary for help / cmd / doctor and any other structured listing, so
# headings, actionable commands, argument placeholders and descriptions read the
# same on both front-ends. PRIMARY is the main command text (bright white);
# PARAM accents an argument placeholder; a description rides the reserved INFO
# (dim). These are a categorical axis (like methods), NOT sentiment, so PARAM
# deliberately avoids the four reserved sentiment colours.
PRIMARY = "white"
PARAM = "cyan"

# Emphasis for a search hit -- the matched substring in `cmd <query>` results.
# This is a categorical emphasis, NOT a sentiment, so it deliberately avoids the
# four reserved colours above; `reverse` inverts fg/bg, so it stands out against
# any base colour and in either terminal theme.
MATCH = "reverse"

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
    "transport": "dark_cyan",
    "forensics": "spring_green3",
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

# --- print (PDF/HTML) colour tokens -----------------------------------------
# Hex analogs of the Rich sentiment/severity/method names above, so the print
# theme (report.css :root tokens, injected by skuggi.pdf) never drifts from the
# terminal palette. A screen terminal renders named colours from its own theme;
# print has no theme, so the same semantics are pinned to concrete hex here.
_SEVERITY_HEX = {
    "critical": "#b91c1c",  # bold red -- the strongest danger
    "high": "#dc2626",  # red
    "medium": "#b45309",  # yellow reads as amber in print (contrast on white)
    "low": "#0e7490",  # cyan
    "info": "#6b7280",  # dim -- muted grey
}
_SEVERITY_HEX_DEFAULT = "#374151"

_METHOD_HEX = {
    "recon": "#0e7490",  # cyan
    "scan": "#1d4ed8",  # blue
    "enumerate": "#a21caf",  # magenta
    "bruteforce": "#c2410c",  # dark_orange
    "crack": "#7c3aed",  # medium_purple
    "exploit": "#be185d",  # deep_pink3
}
_METHOD_HEX_DEFAULT = "#374151"


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


def severity_hex(severity: str) -> str:
    """The print (hex) colour for a finding severity."""
    return _SEVERITY_HEX.get(severity.lower(), _SEVERITY_HEX_DEFAULT)


def method_hex(method: str | None) -> str:
    """The print (hex) colour for an engagement method category."""
    return _METHOD_HEX.get((method or "").lower(), _METHOD_HEX_DEFAULT)


def mode_glyph(mode: str | None) -> str:
    """The prompt glyph for an operating mode ('' for an unknown/absent mode)."""
    return _MODE_GLYPH.get(mode or "", "")


def methods() -> tuple[str, ...]:
    """The methods that have a defined colour (for tests and help)."""
    return tuple(_METHOD)


def severities() -> tuple[str, ...]:
    """The severities that have a defined colour (for tests)."""
    return tuple(_SEVERITY)


def paint(text: str, style: str) -> str:
    """Wrap `text` in Rich markup for `style`."""
    return f"[{style}]{text}[/{style}]"
