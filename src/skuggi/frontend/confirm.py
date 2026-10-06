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

SESSION = "approve for session"

# Capabilities governing the AUTHORIZATION boundary (the engagement scope and the
# autonomous risk ceiling). These are never grantable for a whole session: each
# edit is confirmed explicitly, because an agent-proposed scope edit is driven by
# a natural-language request whose context can include injected tool/web output
# (audit C4). config/install/cmd stay grantable. In the boundary taxonomy
# (skuggi.security.boundaries) every capability here is GRANTABLE-tier -- the hard,
# non-overridable boundaries (scope guard + egress gate) live in code, not here.
_NON_GRANTABLE = frozenset({"scope-edit"})


def confirm_write(  # noqa: PLR0913 -- the capability + keyword-only collaborators and options
    capability: str,
    *,
    grants: SessionGrants,
    choose: Choose,
    notify: Notify,
    prompt: str = "Apply these changes?",
    agentic: bool = False,
) -> bool:
    """Return whether to apply the previewed write, using the session grant.

    This is the gated-write confirm, distinct from a plain ``yes``/``no`` question
    (`menu.confirm`): the operator is authorising an action, so the three-way menu
    reads ``approve`` / ``approve for session`` / ``deny`` -- apply once, apply and
    grant for the rest of the session, or decline (the default, and what a ``None``
    abort maps to). `agentic` marks a write the *model* proposed (the natural-language
    config/scope/cmd edits, install research): it adds a line making clear the
    operator is approving an agent decision, not a deterministic harness action.

    A standing grant for `capability` auto-applies, but announces itself so the
    operator always sees a write happen.
    """
    grantable = capability not in _NON_GRANTABLE
    if grantable and grants.granted(capability):
        notify(f"(session grant for {capability} active -- applying without asking)")
        return True
    if agentic:
        notify("↳ the agent proposes this -- approve to apply, deny to reject")
    options = ["approve", SESSION, "deny"] if grantable else ["approve", "deny"]
    choice = choose(prompt, options, "deny")
    if grantable and choice == SESSION:
        grants.grant(capability)
        return True
    return choice == "approve"
