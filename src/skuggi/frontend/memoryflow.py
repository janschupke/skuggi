"""Interactive, gated capture of standing operator preferences into harness memory.

The in-loop evaluator (``PreferenceBook.propose_capture``) extracts candidate
directives post-turn but writes nothing; this driver previews them and, through the
shared gated-write step (capability ``memory``), writes them only on the operator's
approval. Harness memory is a WRITE the agent proposes, so the confirm is marked
``agentic`` -- the operator is approving an agent decision.

Front-end-agnostic like the other ``*flow`` modules: it talks only through the
supplied ``choose``/``notify`` closures (the REPL prompt, or the attach loop's
socket round-trip) and the session-grant broker. In a non-interactive context (a
one-shot ``/skuggi ask`` with no loop to prompt in) there is nothing to confirm
against, so it only announces the candidate and writes nothing -- the operator
approves it later in the chat loop or with ``add memory``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from skuggi.frontend.confirm import Choose, Notify, confirm_write

if TYPE_CHECKING:
    from skuggi.agent.grants import SessionGrants

Apply = Callable[["list[str]"], str]


def _preview_lines(candidates: list[str]) -> list[str]:
    """The "would remember" preview shown before any write, one bullet per candidate."""
    return ["the agent suggests remembering:", *(f"  - {c}" for c in candidates)]


def announce_capture(candidates: list[str], *, hint: str) -> list[str]:
    """The one-shot announce (no write): what the evaluator would remember.

    A one-shot ``/skuggi ask`` has no loop to confirm against, so the daemon only
    announces the candidate and points at where to approve it. Returns newline-
    terminated chunk strings; empty when there is nothing to remember.
    """
    if not candidates:
        return []
    lines = [
        *_preview_lines(candidates),
        f"not written -- approve it in the chat loop, or {hint}",
    ]
    return [line + "\n" for line in lines]


def run_memory_capture(  # noqa: PLR0913 -- keyword-only collaborators + the candidates
    candidates: list[str],
    *,
    choose: Choose,
    notify: Notify,
    apply: Apply,
    grants: SessionGrants,
    interactive: bool,
    remember_hint: str = "add memory <text>",
) -> None:
    """Preview the captured `candidates`, confirm, and write them on a yes.

    `candidates` is what the evaluator proposed (empty = nothing to do, no output).
    In a non-interactive context the candidate is announced and nothing is written.
    """
    if not candidates:
        return
    for line in _preview_lines(candidates):
        notify(line)
    if not interactive:
        notify(f"not written -- approve it in the chat loop, or `{remember_hint}`")
        return
    if not confirm_write(
        "memory",
        grants=grants,
        choose=choose,
        notify=notify,
        prompt="Remember these?",
        agentic=True,
    ):
        notify("not remembered")
        return
    notify(apply(candidates))
