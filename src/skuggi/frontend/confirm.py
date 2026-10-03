"""The shared confirm step for every gated write.

The preview (a scope diff, a rendered command, an install argv) is shown by the
caller; this one place decides apply vs. abort and handles the "approve for the
rest of this session" grant, so ``config``/``install``/``scope``/``cmd`` all gate
their writes identically. Front-end-agnostic like the flow drivers: it talks only
through the supplied ``choose``/``notify`` closures (the REPL prompt, or the attach
loop's socket round-trip) and the session-grant broker.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from skuggi.agent.grants import SessionGrants

# (prompt, options, default) -> the chosen option, or None if the operator aborts.
Choose = Callable[[str, list[str], str | None], str | None]
Notify = Callable[[str], None]

SESSION = "yes (rest of session)"


def confirm_write(
    capability: str,
    *,
    grants: SessionGrants,
    choose: Choose,
    notify: Notify,
    prompt: str = "Apply these changes?",
) -> bool:
    """Return whether to apply the previewed write, using the session grant.

    A standing grant for `capability` auto-applies, but announces itself so the
    operator always sees a write happen. Otherwise a three-way menu: apply once,
    apply and grant for the rest of the session, or abort (the default, and what a
    ``None`` abort maps to).
    """
    if grants.granted(capability):
        notify(f"(session grant for {capability} active — applying without asking)")
        return True
    choice = choose(prompt, ["yes", SESSION, "no"], "no")
    if choice == SESSION:
        grants.grant(capability)
        return True
    return choice == "yes"
