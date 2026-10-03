"""Inline arrow-key selection, shared by the REPL and the wrapped-shell client.

A small prompt_toolkit application that renders an option list in place (not a
full-screen dialog, which would clash with the surrounding scrollback), moves
with the arrow keys, selects with Enter, and aborts (returns ``None``) on
Ctrl-C/Esc/q. Both front-ends render selections through here so they look and
behave the same; the client imports it lazily so its fire-and-forget logging
path never pays the prompt_toolkit import.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import cast

from prompt_toolkit import PromptSession
from prompt_toolkit.application import Application
from prompt_toolkit.completion import (
    CompleteEvent,
    Completer,
    Completion,
    WordCompleter,
)
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import StyleAndTextTuples
from prompt_toolkit.input import Input
from prompt_toolkit.key_binding import KeyBindings, KeyPressEvent
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.output import Output
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.styles import Style

# ANSI-named colours map to the parent terminal's own 16-colour palette, so the
# menu reads correctly on light and dark themes without hard-coding RGB. The row
# under the cursor is marked by a coloured caret and bold text -- no background
# fill. A checked box is green, an unchecked one dim.
_STYLE = Style.from_dict(
    {
        "sk.prompt": "bold",
        "sk.hint": "ansibrightblack italic",
        "sk.cursor": "ansicyan bold",
        "sk.selected": "ansicyan",  # active row text in colour -- never a background
        "sk.checked": "ansigreen",
        "sk.unchecked": "ansibrightblack",
    }
)


def select(
    prompt: str,
    options: Sequence[str],
    *,
    default: str | None = None,
    pt_input: Input | None = None,
    pt_output: Output | None = None,
) -> str | None:
    """Show `options` as an arrow-key menu; return the chosen one, or ``None``.

    `default` pre-selects an option. `pt_input`/`pt_output` are injected by tests
    (a pipe input + dummy output) so the menu runs without a real terminal.
    """
    opts = list(options)
    if not opts:
        return None
    state = {"pos": opts.index(default) if default in opts else 0}
    bindings = KeyBindings()

    def _move(delta: int) -> None:
        state["pos"] = (state["pos"] + delta) % len(opts)

    @bindings.add("up")
    @bindings.add("c-p")
    def _up(_event: KeyPressEvent) -> None:
        _move(-1)

    @bindings.add("down")
    @bindings.add("c-n")
    def _down(_event: KeyPressEvent) -> None:
        _move(1)

    @bindings.add("enter")
    def _accept(event: KeyPressEvent) -> None:
        event.app.exit(result=opts[state["pos"]])

    @bindings.add("c-c")
    @bindings.add("escape")
    @bindings.add("q")
    def _abort(event: KeyPressEvent) -> None:
        event.app.exit(result=None)

    def _render() -> StyleAndTextTuples:
        rows: StyleAndTextTuples = []
        for i, opt in enumerate(opts):
            if i == state["pos"]:
                rows.append(("class:sk.cursor", "▸ "))
                rows.append(("class:sk.selected", f"{opt}\n"))
            else:
                rows.append(("", f"  {opt}\n"))
        return rows

    layout = Layout(
        HSplit(
            [
                Window(
                    FormattedTextControl(lambda: [("class:sk.prompt", prompt)]),
                    height=1,
                ),
                # show_cursor=False + always_hide_cursor: no terminal block cursor
                # paints a reverse-video square over the first row.
                Window(
                    FormattedTextControl(_render, focusable=True, show_cursor=False),
                    always_hide_cursor=True,
                ),
            ]
        )
    )
    app: Application[object] = Application(
        layout=layout,
        key_bindings=bindings,
        style=_STYLE,
        full_screen=False,
        mouse_support=False,
        input=pt_input,
        output=pt_output,
    )
    return cast("str | None", app.run())


def confirm(
    prompt: str,
    *,
    default: bool = False,
    pt_input: Input | None = None,
    pt_output: Output | None = None,
) -> bool | None:
    """A yes/no arrow menu. Returns the choice, or ``None`` if aborted."""
    choice = select(
        prompt,
        ["yes", "no"],
        default="yes" if default else "no",
        pt_input=pt_input,
        pt_output=pt_output,
    )
    if choice is None:
        return None
    return choice == "yes"


def multiselect(
    prompt: str,
    options: Sequence[str],
    *,
    preselected: Sequence[str] = (),
    pt_input: Input | None = None,
    pt_output: Output | None = None,
) -> list[str] | None:
    """A checklist: toggle options with space, accept with Enter.

    Returns the checked options in `options` order, or ``None`` on abort
    (Ctrl-C/Esc/q). An empty `options` returns ``[]`` (an empty set is a valid
    answer, not an abort). `preselected` pre-checks matching options.
    """
    opts = list(options)
    if not opts:
        return []
    checked = {i for i, opt in enumerate(opts) if opt in set(preselected)}
    state = {"pos": 0}
    bindings = KeyBindings()

    def _move(delta: int) -> None:
        state["pos"] = (state["pos"] + delta) % len(opts)

    @bindings.add("up")
    @bindings.add("c-p")
    def _up(_event: KeyPressEvent) -> None:
        _move(-1)

    @bindings.add("down")
    @bindings.add("c-n")
    def _down(_event: KeyPressEvent) -> None:
        _move(1)

    @bindings.add("space")
    def _toggle(_event: KeyPressEvent) -> None:
        pos = state["pos"]
        if pos in checked:
            checked.discard(pos)
        else:
            checked.add(pos)

    @bindings.add("enter")
    def _accept(event: KeyPressEvent) -> None:
        event.app.exit(result=[opts[i] for i in range(len(opts)) if i in checked])

    @bindings.add("c-c")
    @bindings.add("escape")
    @bindings.add("q")
    def _abort(event: KeyPressEvent) -> None:
        event.app.exit(result=None)

    def _header() -> StyleAndTextTuples:
        return [
            ("class:sk.prompt", prompt + "\n"),
            ("class:sk.hint", "space toggles · enter accepts"),
        ]

    def _render() -> StyleAndTextTuples:
        rows: StyleAndTextTuples = []
        for i, opt in enumerate(opts):
            on_cursor = i == state["pos"]
            rows.append(("class:sk.cursor", "▸ " if on_cursor else "  "))
            if i in checked:
                rows.append(("class:sk.checked", "[x] "))
            else:
                rows.append(("class:sk.unchecked", "[ ] "))
            rows.append(("class:sk.selected" if on_cursor else "", f"{opt}\n"))
        return rows

    layout = Layout(
        HSplit(
            [
                Window(FormattedTextControl(_header), height=2),
                # show_cursor=False + always_hide_cursor: no terminal block cursor.
                Window(
                    FormattedTextControl(_render, focusable=True, show_cursor=False),
                    always_hide_cursor=True,
                ),
            ]
        )
    )
    app: Application[object] = Application(
        layout=layout,
        key_bindings=bindings,
        style=_STYLE,
        full_screen=False,
        mouse_support=False,
        input=pt_input,
        output=pt_output,
    )
    return cast("list[str] | None", app.run())


class _CsvCompleter(Completer):
    """Completes the token after the last comma against a word list (prefix)."""

    def __init__(self, words: Sequence[str]) -> None:
        self._inner = WordCompleter(list(words), ignore_case=True)

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        tail = document.text_before_cursor.rsplit(",", 1)[-1].lstrip()
        sub = Document(tail, cursor_position=len(tail))
        yield from self._inner.get_completions(sub, complete_event)


def ask_complete(  # noqa: PLR0913 -- keyword-only widget options + test I/O
    prompt: str,
    candidates: Sequence[str],
    *,
    default: str | None = None,
    multi: bool = False,
    pt_input: Input | None = None,
    pt_output: Output | None = None,
) -> str | None:
    """Free-text input with completion from `candidates`; ``None`` on abort.

    `candidates` only assist -- any text is accepted. Completion is standard-CLI
    Tab (``READLINE_LIKE``): nothing floats, Tab fills the single/common prefix
    and a second Tab lists columns. `multi=True` completes the token after the
    last comma (for a comma-separated list). `pt_input`/`pt_output` are injected
    by tests.
    """
    completer: Completer = (
        _CsvCompleter(candidates)
        if multi
        else WordCompleter(list(candidates), ignore_case=True)
    )
    session: PromptSession[str] = PromptSession(
        completer=completer,
        complete_while_typing=False,
        complete_style=CompleteStyle.READLINE_LIKE,
        input=pt_input,
        output=pt_output,
    )
    try:
        return session.prompt(prompt, default=default or "")
    except (EOFError, KeyboardInterrupt):
        return None
