"""The guided cheatsheet editor: add or edit a command alias interactively.

The front-end-agnostic twin of ``wizard`` (engagement scope) and ``configflow``
(app settings): it knows the ``CommandAlias`` fields and shapes free-text answers
into the dict ``core.cmds.add``/``update`` validates, driving
everything through an ``ask(prompt) -> str | None`` callable (``None`` aborts) so
one editor serves both the REPL prompt and the wrapped-shell socket round-trip.
Validation and persistence stay in ``AgentCore``; this module only collects
answers and retries on rejection. The registry is equally editable by hand --
this is the in-app path, not the only one.
"""

from __future__ import annotations

import shlex
from collections.abc import Callable

from skuggi.config.configs import ConfigError
from skuggi.tooling.commands import CommandAlias

Ask = Callable[[str], str | None]
Notify = Callable[[str], None]
Apply = Callable[[dict[str, object]], CommandAlias]

# Arguments to the `cmd` verb that open the editor rather than search/resolve.
ADD_ARGS = frozenset({"add", "new"})
EDIT_ARGS = frozenset({"edit"})
REMOVE_ARGS = frozenset({"rm", "remove", "delete"})


def _yesno(answer: str) -> bool:
    return answer.strip().lower() in ("y", "yes", "true", "on", "1")


def _show(value: object) -> str:
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value)
    return str(value)


# key, prompt, how to shape a non-blank answer into JSON.
_STEPS: tuple[tuple[str, str, Callable[[str], object]], ...] = (
    ("name", "alias name", str),
    ("argv", "command template (e.g. nmap -sV -sC)", shlex.split),
    ("description", "description", str),
    ("tool", "tool/binary (blank = first word of the command)", str),
    ("label", "output label (blank = name without the tool prefix)", str),
    ("output_dir", "output folder (blank = the tool's default)", str),
    ("output_flag", "output flag (blank = the tool's default)", str),
    ("output", "write a timestamped output file? (Y/n)", _yesno),
)


def collect_alias(
    ask: Ask, *, existing: CommandAlias | None = None
) -> dict[str, object] | None:
    """Ask each alias field via `ask`, returning an alias dict (unvalidated).

    Returns ``None`` if the operator aborts. A blank answer keeps the existing
    value when editing, else leaves the field at its schema default -- so only
    ``name`` and the command template are strictly required.
    """
    raw: dict[str, object] = (
        existing.model_dump(mode="json") if existing is not None else {}
    )
    for key, prompt, transform in _STEPS:
        current = raw.get(key)
        shown = _show(current)
        label = (
            f"{prompt} [{shown}]: "
            if shown not in ("", "[]", "None", "True")
            else f"{prompt}: "
        )
        answer = ask(label)
        if answer is None:
            return None
        answer = answer.strip()
        if answer:
            raw[key] = transform(answer)
    return raw


def run_cmd_editor(
    ask: Ask, apply: Apply, notify: Notify, *, existing: CommandAlias | None = None
) -> CommandAlias | None:
    """Collect alias answers, apply them, and retry on a validation rejection.

    `apply` validates and persists the alias (raising ``ConfigError`` on bad
    input); on rejection the editor reports it and re-asks, so a typo does not
    lose the work. Returns the saved alias, or ``None`` if the operator aborted.
    """
    while True:
        raw = collect_alias(ask, existing=existing)
        if raw is None:
            notify("cheatsheet edit cancelled")
            return None
        try:
            alias = apply(raw)
        except ConfigError as exc:
            notify(f"alias rejected: {exc}")
            continue
        notify(f"saved alias '{alias.name}'")
        return alias
