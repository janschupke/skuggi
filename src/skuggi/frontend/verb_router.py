"""The routing pieces the REPL and the shell daemon share.

Both front-ends are verb-first over the one registry in :mod:`skuggi.frontend.verbs`
and route the grouping verbs (``show``/``set``/``add``/``remove``) on a noun. The
top-level dispatch stays per-surface -- the REPL returns ``bool | None`` and prints
Rich markup, the daemon yields socket frames, and they differ on exit/chat/help --
but the noun-routing mechanics and the audit predicate are identical, so they live
here to keep the two surfaces from drifting. A handler is surface-specific (a sync
callable in the REPL, a frame generator in the daemon), so the helpers are generic
over the handler type.

This module imports only :mod:`skuggi.frontend.verbs` and :mod:`skuggi.common.modes`
-- never ``tui``/``daemon`` -- so it cannot close an import loop with either surface
(enforced by a leaf test).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from skuggi.frontend import verbs

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from skuggi.common.modes import Mode


def should_audit(verb: str, mode: Mode) -> bool:
    """Whether running `verb` in `mode` should be written to the audit log.

    A known, mode-available, non-engagement control verb (engagement verbs manage
    their own auditing). Both surfaces gate ``note_interaction`` on this, so the
    predicate cannot diverge between the REPL and the daemon.
    """
    return (
        verb in verbs.KNOWN
        and verbs.is_available(verb, mode)
        and not verbs.is_engagement(verb)
    )


def noun_usage(verb: str, surface: verbs.Surface) -> str:
    """The ``<noun | noun | ...>`` usage hint for a grouping verb, per surface.

    Returns the formatted invocation only; the caller adds its own ``usage:``
    prefix (Rich-styled in the REPL, plain over the socket).
    """
    options = " | ".join(n.name for n in verbs.nouns_of(verb))
    return verbs.cmd(f"{verb} <{options}>", surface)


def resolve_noun[H](router: Mapping[str, H], arg: str) -> tuple[H | None, str]:
    """Split ``<noun> <rest>`` off `arg` and look the noun up in `router`.

    Returns the matched handler (or ``None`` when the noun is unknown) and the
    stripped remainder, so the caller renders the usage or invokes the handler in
    its own idiom.
    """
    noun, _, rest = arg.partition(" ")
    return router.get(noun.strip().lower()), rest.strip()


def build_router[A, H](
    actions: Mapping[str, A],
    styled: Callable[[A], H],
    extras: Mapping[str, H] | None = None,
) -> dict[str, H]:
    """A noun router: each shared `actions` entry wrapped by `styled`, plus `extras`.

    `styled` adapts a shared :data:`skuggi.frontend.control.Action` into the
    surface's handler; `extras` are the surface-specific nouns that are not plain
    control actions. Keeping assembly here keeps the two surfaces' routers aligned
    with the registry the drift tests check.
    """
    router: dict[str, H] = {name: styled(action) for name, action in actions.items()}
    if extras:
        router.update(extras)
    return router
