"""L1: the inline arrow-key selection menu (driven by a pipe input)."""

from __future__ import annotations

import io
import re
from collections.abc import Callable, Iterator

import pytest
from prompt_toolkit.data_structures import Size
from prompt_toolkit.input.base import PipeInput
from prompt_toolkit.input.defaults import create_pipe_input
from prompt_toolkit.output import DummyOutput
from prompt_toolkit.output.color_depth import ColorDepth
from prompt_toolkit.output.vt100 import Vt100_Output

from skuggi.frontend import menu

_DOWN = "\x1b[B"
_UP = "\x1b[A"
_ENTER = "\r"
_CTRL_C = "\x03"
_SPACE = " "


@pytest.fixture
def pipe() -> Iterator[PipeInput]:
    with create_pipe_input() as inp:
        yield inp


def _select(pipe: PipeInput, keys: str, **kwargs: object) -> str | None:
    pipe.send_text(keys)
    return menu.select(
        "pick one",
        ["openai", "anthropic", "ollama"],
        pt_input=pipe,
        pt_output=DummyOutput(),
        **kwargs,  # type: ignore[arg-type]
    )


def test_enter_selects_the_first_option(pipe: PipeInput) -> None:
    assert _select(pipe, _ENTER) == "openai"


def test_arrow_down_moves_the_selection(pipe: PipeInput) -> None:
    assert _select(pipe, _DOWN + _ENTER) == "anthropic"
    assert _select(pipe, _DOWN + _DOWN + _ENTER) == "ollama"


def test_default_preselects(pipe: PipeInput) -> None:
    assert _select(pipe, _ENTER, default="ollama") == "ollama"


def test_up_wraps_around(pipe: PipeInput) -> None:
    assert _select(pipe, _UP + _ENTER) == "ollama"  # up from the first wraps to last


def test_ctrl_c_aborts_to_none(pipe: PipeInput) -> None:
    assert _select(pipe, _CTRL_C) is None


def test_confirm_maps_yes_no(pipe: PipeInput) -> None:
    pipe.send_text(_ENTER)
    assert (
        menu.confirm("ok?", default=True, pt_input=pipe, pt_output=DummyOutput())
        is True
    )


def test_confirm_abort_is_none(pipe: PipeInput) -> None:
    pipe.send_text(_CTRL_C)
    assert menu.confirm("ok?", pt_input=pipe, pt_output=DummyOutput()) is None


# --- multiselect ------------------------------------------------------------


def _multiselect(pipe: PipeInput, keys: str, **kwargs: object) -> list[str] | None:
    pipe.send_text(keys)
    return menu.multiselect(
        "pick some",
        ["recon", "scan", "enumerate"],
        pt_input=pipe,
        pt_output=DummyOutput(),
        **kwargs,  # type: ignore[arg-type]
    )


def test_multiselect_enter_with_nothing_is_empty(pipe: PipeInput) -> None:
    assert _multiselect(pipe, _ENTER) == []


def test_multiselect_space_toggles_the_cursor_row(pipe: PipeInput) -> None:
    assert _multiselect(pipe, _SPACE + _ENTER) == ["recon"]
    assert _multiselect(pipe, _DOWN + _SPACE + _ENTER) == ["scan"]


def test_multiselect_returns_picks_in_option_order(pipe: PipeInput) -> None:
    # Toggle the third, then the first; result follows option order, not click order.
    keys = _DOWN + _DOWN + _SPACE + _UP + _UP + _SPACE + _ENTER
    assert _multiselect(pipe, keys) == ["recon", "enumerate"]


def test_multiselect_preselected_is_checked(pipe: PipeInput) -> None:
    assert _multiselect(pipe, _ENTER, preselected=["scan"]) == ["scan"]


def test_multiselect_ctrl_c_aborts_to_none(pipe: PipeInput) -> None:
    assert _multiselect(pipe, _CTRL_C) is None


def test_multiselect_empty_options_is_empty_not_abort() -> None:
    assert menu.multiselect("none", [], pt_output=DummyOutput()) == []


# --- ask_complete -----------------------------------------------------------


def test_ask_complete_returns_typed_text(pipe: PipeInput) -> None:
    pipe.send_text("Europe/Helsinki" + _ENTER)
    result = menu.ask_complete(
        "tz: ", ["UTC", "Europe/Helsinki"], pt_input=pipe, pt_output=DummyOutput()
    )
    assert result == "Europe/Helsinki"


def test_ask_complete_bare_enter_returns_default(pipe: PipeInput) -> None:
    pipe.send_text(_ENTER)
    result = menu.ask_complete(
        "tz: ",
        ["UTC"],
        default="UTC",
        pt_input=pipe,
        pt_output=DummyOutput(),
    )
    assert result == "UTC"


def test_ask_complete_ctrl_c_aborts_to_none(pipe: PipeInput) -> None:
    pipe.send_text(_CTRL_C)
    result = menu.ask_complete("tz: ", ["UTC"], pt_input=pipe, pt_output=DummyOutput())
    assert result is None


# --- no background / reverse-video (the operator's complaint) ----------------


def _bg_in_sgr(rendered: str) -> bool:
    """True if any SGR sequence sets a background colour or reverse video."""
    for params in re.findall(r"\x1b\[([0-9;]*)m", rendered):
        codes = params.split(";")
        if "48" in codes:  # 256/true-colour background
            return True
        if "7" in codes or "07" in codes:  # reverse video
            return True
        for code in codes:
            if code.isdigit() and (40 <= int(code) <= 47 or 100 <= int(code) <= 107):
                return True  # 16-colour background
    return False


def _render_to_vt100(run: Callable[[PipeInput, Vt100_Output], object]) -> str:
    """Render one real menu frame to a VT100 byte stream and return it."""
    buf = io.StringIO()
    out = Vt100_Output(
        buf,
        lambda: Size(rows=24, columns=80),
        default_color_depth=ColorDepth.DEPTH_4_BIT,
    )
    with create_pipe_input() as pin:
        pin.send_text(_ENTER)  # accept immediately
        run(pin, out)
    return buf.getvalue()


def test_select_paints_no_background() -> None:
    out = _render_to_vt100(
        lambda p, o: menu.select(
            "pick", ["recon", "scan", "enumerate"], pt_input=p, pt_output=o
        )
    )
    assert not _bg_in_sgr(out)  # foreground-only: no bar, no block, no grey fill


def test_multiselect_paints_no_background() -> None:
    out = _render_to_vt100(
        lambda p, o: menu.multiselect(
            "methods",
            ["recon", "scan"],
            preselected=["recon"],
            pt_input=p,
            pt_output=o,
        )
    )
    assert not _bg_in_sgr(out)
