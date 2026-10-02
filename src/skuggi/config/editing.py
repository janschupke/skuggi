"""Pure helpers for the ``config`` verb.

Which keys the operator may edit, how the current settings render, and how an
operator's free-text value is coerced to a field's type -- all pure functions of
``Settings`` plus strings, so they are unit-testable without a live session. The
live switch (persisting to ``config.json`` and hot-applying ``provider``/``mode``)
stays in :class:`~skuggi.agent.core.AgentCore`, which owns the session state.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import TypeAdapter, ValidationError

from skuggi.config.config import _SECRET_FIELDS, Settings


def settable_keys() -> frozenset[str]:
    """Config keys the operator may edit -- every setting except secrets."""
    return frozenset(Settings.model_fields) - _SECRET_FIELDS


def render_summary(settings: Settings) -> str:
    """Every setting, one per line, with credentials redacted."""
    data = settings.model_dump(mode="json")
    lines = []
    for key in sorted(data):
        value = "***" if key in _SECRET_FIELDS and data[key] else data[key]
        lines.append(f"{key} = {value}")
    return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class Coerced:
    """A validated config edit: the typed value and its JSON form."""

    value: object
    json_value: object


def coerce_value(key: str, raw: str) -> Coerced | str:
    """Coerce `raw` to `key`'s field type, or return an operator-facing error.

    A pure wrapper over the field's pydantic ``TypeAdapter``; the caller persists
    and hot-applies the result. Refuses secrets and unknown keys.
    """
    if key in _SECRET_FIELDS:
        return f"config: {key} is a secret -- set it in the environment"
    if key not in Settings.model_fields:
        return f"config: unknown setting {key!r}"
    adapter: TypeAdapter[object] = TypeAdapter(Settings.model_fields[key].annotation)
    try:
        coerced = adapter.validate_python(raw)
    except ValidationError:
        return f"config: invalid value for {key}: {raw!r}"
    return Coerced(value=coerced, json_value=adapter.dump_python(coerced, mode="json"))
