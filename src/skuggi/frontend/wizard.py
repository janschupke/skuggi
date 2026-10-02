"""The engagement Q&A wizard: gather a scope interactively, front-end-agnostic.

The wizard knows the engagement fields and how to shape free-text answers into
the JSON an ``EngagementConfig`` validates. It never touches a console or a
socket: it drives everything through an ``ask(prompt) -> str | None`` callable
(``None`` aborts) supplied by the front-end -- the REPL's ``PromptSession`` or
the wrapped-shell attach loop's socket round-trip -- so one wizard serves both.
Validation and persistence stay in ``AgentCore.create_engagement``; this module
only collects answers and retries on the guard's rejection.
"""

from __future__ import annotations

from collections.abc import Callable

from skuggi.config.configs import ConfigError
from skuggi.engagement.engagement import EngagementConfig

Ask = Callable[[str], str | None]
Notify = Callable[[str], None]
Apply = Callable[[dict[str, object]], EngagementConfig]

# Arguments to the `engagement` verb that open the wizard rather than show scope.
WIZARD_ARGS = frozenset({"setup", "new", "edit"})


def _csv(answer: str) -> list[str]:
    return [item.strip() for item in answer.split(",") if item.strip()]


def _windows(answer: str) -> list[dict[str, str]]:
    """Parse ``HH:MM-HH:MM`` clock ranges (comma-separated) into scope dicts."""
    windows: list[dict[str, str]] = []
    for chunk in _csv(answer):
        start, _, end = chunk.partition("-")
        windows.append({"start": start.strip(), "end": end.strip()})
    return windows


def _yesno(answer: str) -> bool:
    return answer.strip().lower() in ("y", "yes", "true", "on", "1")


def _show(value: object) -> str:
    if isinstance(value, list):
        parts = [
            f"{v.get('start', '')}-{v.get('end', '')}"
            if isinstance(v, dict)
            else str(v)
            for v in value
        ]
        return ", ".join(parts)
    return str(value)


# key, prompt, how to shape a non-blank answer into JSON.
_STEPS: tuple[tuple[str, str, Callable[[str], object]], ...] = (
    ("name", "engagement name", str),
    ("timezone", "timezone (IANA, e.g. Europe/Helsinki)", str),
    ("authorized_start", "authorized start (ISO 8601, tz-aware)", str),
    ("authorized_end", "authorized end (ISO 8601, tz-aware)", str),
    (
        "daily_windows",
        "daily windows HH:MM-HH:MM, comma-separated (blank = any)",
        _windows,
    ),
    ("target_networks", "target networks (CIDR, comma-separated)", _csv),
    ("allowed_hosts", "allowed hosts (comma-separated)", _csv),
    ("allowed_tools", "allowed tools (comma-separated)", _csv),
    ("allowed_methods", "allowed methods (comma-separated)", _csv),
    ("autonomous", "autonomous execution? (y/N)", _yesno),
)


def collect_scope(
    ask: Ask, *, existing: EngagementConfig | None = None
) -> dict[str, object] | None:
    """Ask each engagement field via `ask`, returning a scope dict (unvalidated).

    Returns ``None`` if the operator aborts (an `ask` returns ``None``). A blank
    answer keeps the existing value when editing, else leaves the field at its
    schema default; ``timezone`` seeds to ``UTC`` for a fresh engagement so only
    the name and window are strictly required.
    """
    raw: dict[str, object] = (
        existing.model_dump(mode="json")
        if existing is not None
        else {"timezone": "UTC"}
    )
    for key, prompt, transform in _STEPS:
        current = raw.get(key)
        shown = _show(current)
        label = (
            f"{prompt} [{shown}]: "
            if shown not in ("", "[]", "None")
            else f"{prompt}: "
        )
        answer = ask(label)
        if answer is None:
            return None
        answer = answer.strip()
        if answer:
            raw[key] = transform(answer)
    return raw


def run_wizard(
    ask: Ask, apply: Apply, notify: Notify, *, existing: EngagementConfig | None = None
) -> EngagementConfig | None:
    """Collect scope answers, apply them, and retry on a validation rejection.

    `apply` validates and persists the scope (raising ``ConfigError`` on bad
    input); on rejection the wizard reports it and re-asks, so a typo does not
    lose the session. Returns the loaded config, or ``None`` if the operator
    aborted.
    """
    while True:
        raw = collect_scope(ask, existing=existing)
        if raw is None:
            notify("engagement setup cancelled")
            return None
        try:
            engagement = apply(raw)
        except ConfigError as exc:
            notify(f"scope rejected: {exc}")
            continue
        notify(f"engagement '{engagement.name}' loaded")
        return engagement
