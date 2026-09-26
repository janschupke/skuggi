"""The interactive half of the `config` verb: confirm an LLM-proposed edit.

The mechanical forms (``config show`` / ``config <key> <value>``) are answered
synchronously by ``AgentCore.config_line`` and need no front-end help. A
natural-language request escalates: the core proposes ``key=value`` edits, and
this shared driver -- front-end-agnostic, like ``wizard`` -- shows them, asks
the operator to confirm through the supplied ``ask`` callable (the REPL's
prompt or the attach loop's socket round-trip), and applies on a yes. Kept out
of ``AgentCore`` because it owns no state; kept out of the front-ends so the
confirm flow lives in exactly one place.
"""

from __future__ import annotations

from collections.abc import Callable

Ask = Callable[[str], str | None]
Notify = Callable[[str], None]
Propose = Callable[[str], list[tuple[str, str]]]
Apply = Callable[[str, str], str]


def run_config_request(
    request: str,
    *,
    ask: Ask,
    notify: Notify,
    propose: Propose,
    apply: Apply,
) -> None:
    """Propose edits for `request`, confirm interactively, and apply on a yes."""
    proposals = propose(request)
    if not proposals:
        notify("config: no changes proposed")
        return
    notify("proposed changes:")
    for key, value in proposals:
        notify(f"  {key} = {value}")
    answer = ask("apply these changes? (y/N) ")
    if answer is None or answer.strip().lower() not in ("y", "yes"):
        notify("config unchanged")
        return
    for key, value in proposals:
        notify(apply(key, value))
