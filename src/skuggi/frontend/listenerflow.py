"""The ``set listener`` flow: pick the ``lhost`` from a local interface + a port.

Front-end-agnostic, like :mod:`skuggi.frontend.scopeflow` / ``cmdflow``: it talks
only through ``choose``/``ask``/``notify`` closures and an ``apply`` callback, so
the REPL (inline prompts) and the daemon (attach loop over the socket) drive the
same logic. The listener host is chosen from the machine's local interfaces (see
:func:`skuggi.tooling.probe.local_interfaces`) -- a VPN/tunnel interface is the
default pick -- with a manual-entry escape hatch; the port is free text.
"""

from __future__ import annotations

from collections.abc import Callable

from skuggi.tooling.probe import preferred_interface_index

_MANUAL = "enter manually…"

Ask = Callable[[str], "str | None"]
Choose = Callable[[str, list[str], "str | None"], "str | None"]
Notify = Callable[[str], None]
Apply = Callable[[str, "str | None"], None]


def run_set_listener(
    *,
    interfaces: list[tuple[str, str]],
    choose: Choose,
    ask: Ask,
    notify: Notify,
    apply: Apply,
) -> None:
    """Pick ``lhost`` (from `interfaces`) and ``lport``, then ``apply(lhost, lport)``.

    ``interfaces`` are ``(name, ip)`` pairs; the picker defaults to a VPN/tunnel
    one and offers manual entry. A ``None`` from any prompt (abort) stops without
    applying; a blank port leaves ``lport`` unset.
    """
    lhost = _pick_lhost(interfaces, choose, ask, notify)
    if not lhost:
        notify("cancelled")
        return
    lport = ask("lport (blank to leave unset): ")
    if lport is None:
        notify("cancelled")
        return
    apply(lhost, lport.strip() or None)


def _pick_lhost(
    interfaces: list[tuple[str, str]], choose: Choose, ask: Ask, notify: Notify
) -> str | None:
    """Choose the listener host: an interface address, or a manually-typed host."""
    if not interfaces:
        notify("no local interfaces detected; enter the listener host")
        picked = ask("lhost: ")
        return picked.strip() if picked else None
    labels = [f"{name}  {ip}" for name, ip in interfaces]
    options = [*labels, _MANUAL]
    default = labels[preferred_interface_index(interfaces)]
    chosen = choose("listener interface", options, default)
    if chosen is None:
        return None
    if chosen == _MANUAL:
        typed = ask("lhost: ")
        return typed.strip() if typed else None
    return interfaces[labels.index(chosen)][1]
