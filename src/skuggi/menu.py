"""Inline arrow-key selection, shared by the REPL and the wrapped-shell client.

A small prompt_toolkit application that renders an option list in place (not a
full-screen dialog, which would clash with the surrounding scrollback), moves
with the arrow keys, selects with Enter, and aborts (returns ``None``) on
Ctrl-C/Esc/q. Both front-ends render selections through here so they look and
behave the same; the client imports it lazily so its fire-and-forget logging
path never pays the prompt_toolkit import.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from prompt_toolkit.application import Application
from prompt_toolkit.formatted_text import StyleAndTextTuples
from prompt_toolkit.input import Input
from prompt_toolkit.key_binding import KeyBindings, KeyPressEvent
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.output import Output
from prompt_toolkit.styles import Style

_STYLE = Style.from_dict({"menu.selected": "reverse", "menu.prompt": "bold"})


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
                rows.append(("class:menu.selected", f" > {opt} \n"))
            else:
                rows.append(("", f"   {opt} \n"))
        return rows

    layout = Layout(
        HSplit(
            [
                Window(
                    FormattedTextControl(lambda: [("class:menu.prompt", prompt)]),
                    height=1,
                ),
                Window(FormattedTextControl(_render, focusable=True)),
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
