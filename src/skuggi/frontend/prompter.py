"""The front-end-agnostic prompt bundle shared by the interactive flows.

A flow driver (the engagement wizard) needs several kinds of operator
interaction -- a line of text, a line with completion, a single-select menu, a
multi-select checklist, a yes/no, a status line, and a step-bar tick. Rather than
thread seven callables through every function, they are bundled into one frozen
``Prompter``. The REPL builds one over its prompt_toolkit widgets; the attach
daemon builds one over socket frames. Each callable returns ``None`` on abort
(except ``notify``/``progress``, which are one-way).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

# One line of text; None aborts.
Ask = Callable[[str], str | None]
# (prompt, candidates, default) -> text with completion; None aborts.
AskComplete = Callable[[str, Sequence[str], str | None], str | None]
# (prompt, options, default) -> the chosen option; None aborts.
Choose = Callable[[str, list[str], str | None], str | None]
# (prompt, options, preselected) -> the checked options; None aborts.
MultiSelect = Callable[[str, Sequence[str], Sequence[str]], list[str] | None]
# (prompt, default) -> the yes/no choice; None aborts.
Confirm = Callable[[str, bool], bool | None]
# A status line (one-way).
Notify = Callable[[str], None]
# (step, total, section-label) -> render a step bar (one-way).
Progress = Callable[[int, int, str], None]


@dataclass(frozen=True)
class Prompter:
    """The operator-interaction callables a flow driver needs."""

    ask: Ask
    ask_complete: AskComplete
    choose: Choose
    multiselect: MultiSelect
    confirm: Confirm
    notify: Notify
    progress: Progress
