"""The interactive half of the `config` verb: confirm an LLM-proposed edit.

The mechanical forms (``config show`` / ``config <key> <value>``) are answered
synchronously by ``core.config.line`` and need no front-end help. A
natural-language request escalates: the core proposes ``key=value`` edits, and
this shared driver -- front-end-agnostic, like ``wizard`` -- shows them, asks
the operator to confirm through the supplied ``ask`` callable (the REPL's
prompt or the attach loop's socket round-trip), and applies on a yes. Kept out
of ``AgentCore`` because it owns no state; kept out of the front-ends so the
confirm flow lives in exactly one place.
"""

from __future__ import annotations

from collections.abc import Callable

Notify = Callable[[str], None]
Propose = Callable[[str], list[tuple[str, str]]]
Apply = Callable[[str, str], str]
# (prompt, options, default) -> the chosen option, or None if the operator aborts.
Choose = Callable[[str, list[str], str | None], str | None]


def run_config_request(
    request: str,
    *,
    choose: Choose,
    notify: Notify,
    propose: Propose,
    apply: Apply,
) -> None:
    """Propose edits for `request`, confirm from a menu, and apply on a yes."""
    proposals = propose(request)
    if not proposals:
        notify("config: no changes proposed")
        return
    notify("proposed changes:")
    for key, value in proposals:
        notify(f"  {key} = {value}")
    if choose("Apply these changes?", ["yes", "no"], "no") != "yes":
        notify("config unchanged")
        return
    for key, value in proposals:
        notify(apply(key, value))
