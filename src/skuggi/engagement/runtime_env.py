"""The per-engagement *runtime variables* -- the values plugged into commands.

A deliberately separate concern from :mod:`skuggi.engagement.scope`. Scope is
the authorized boundary (gating: which hosts/tools/methods are allowed); these
are the *actual values* the operator drops into individual command calls --
the current ``target``, the listener ``lhost``/``lport``, and a ``wordlist``
path -- updated in real time and exported into the wrapped shell so a rendered
``cmd`` resolves (see ``write_runtime_env`` and :mod:`skuggi.frontend.shell`).

Kept out of ``scope.py`` on purpose: changing a runtime var never widens (or
narrows) authority, so it is not gated like a scope edit, and it persists to its
own ``env.json`` beside ``scope.json`` in the engagement root.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from pydantic import BaseModel, ConfigDict, field_validator

# The runtime variables, in export order. Mirrors ``EngagementEnv``'s fields and
# ``skuggi.tooling.commands.RUNTIME_VARS`` (a test pins the three in sync).
VAR_ORDER = ("target", "lhost", "lport", "wordlist")


class EngagementEnv(BaseModel):
    """The runtime command variables for one engagement (all optional).

    ``target``/``lhost`` are hosts/addresses (no whitespace -- they become
    ``export`` lines); ``lport``/``wordlist`` are free strings so a port range
    or an arbitrary filesystem path works. Everything is neutralised by
    ``shlex.quote`` when written, so validation here only rejects the clearly
    nonsensical (a whitespace-bearing host).
    """

    model_config = ConfigDict(frozen=True)

    target: str | None = None
    lhost: str | None = None
    lport: str | None = None
    wordlist: str | None = None

    @field_validator("target", "lhost")
    @classmethod
    def _no_whitespace(cls, value: str | None) -> str | None:
        if value is not None and (
            value != value.strip() or any(c.isspace() for c in value)
        ):
            msg = "a host/address may not contain whitespace"
            raise ValueError(msg)
        return value

    def exports(self, default_target: str | None = None) -> dict[str, str]:
        """The ``{name: value}`` map to export, in ``VAR_ORDER``.

        ``target`` falls back to `default_target` (the scope-derived first host)
        when unset; blank/``None`` values are dropped so a missing var is simply
        not exported (``write_runtime_env`` ``unset``s it).
        """
        values: dict[str, str | None] = {
            "target": self.target or default_target,
            "lhost": self.lhost,
            "lport": self.lport,
            "wordlist": self.wordlist,
        }
        return {name: value for name in VAR_ORDER if (value := values[name])}

    def effective_target(self, default_target: str | None = None) -> str | None:
        """The current target: the manual value, else the scope-derived default."""
        return self.target or default_target


def write_runtime_env(
    path: Path, env: EngagementEnv, default_target: str | None = None
) -> None:
    """Write the shell-sourced runtime env file for `env`.

    One line per variable in ``VAR_ORDER``: ``export name=<shlex-quoted>`` when
    present, else ``unset name`` -- so sourcing the file always brings the shell
    to the exact desired state, clearing a var that was set and is now blank.
    ``shlex.quote`` is the injection guard for the free ``lport``/``wordlist``.
    """
    present = env.exports(default_target)
    lines = [
        f"export {name}={shlex.quote(present[name])}"
        if name in present
        else f"unset {name}"
        for name in VAR_ORDER
    ]
    path.expanduser().write_text("\n".join(lines) + "\n", encoding="utf-8")
