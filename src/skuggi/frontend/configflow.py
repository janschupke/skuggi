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
from typing import TYPE_CHECKING

from skuggi.frontend.confirm import Choose, Notify, confirm_write

if TYPE_CHECKING:
    from skuggi.agent.grants import SessionGrants

Propose = Callable[[str], list[tuple[str, str]]]
Apply = Callable[[str, str], str]


def run_config_request(  # noqa: PLR0913 -- keyword-only collaborators + the request
    request: str,
    *,
    choose: Choose,
    notify: Notify,
    propose: Propose,
    apply: Apply,
    grants: SessionGrants,
) -> None:
    """Propose edits for `request`, confirm from a menu, and apply on a yes.

    A config edit writes config.json, so it goes through the shared gated-write
    confirm (``skuggi.frontend.confirm``): apply once, apply with a session grant,
    or abort.
    """
    proposals = propose(request)
    if not proposals:
        notify("config: no changes proposed")
        return
    notify("proposed changes:")
    for key, value in proposals:
        notify(f"  {key} = {value}")
    if not confirm_write(
        "config", grants=grants, choose=choose, notify=notify, agentic=True
    ):
        notify("config unchanged")
        return
    for key, value in proposals:
        notify(apply(key, value))
