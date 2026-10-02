"""L1: the inline arrow-key selection menu (driven by a pipe input)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from prompt_toolkit.input.base import PipeInput
from prompt_toolkit.input.defaults import create_pipe_input
from prompt_toolkit.output import DummyOutput

from skuggi.frontend import menu

_DOWN = "\x1b[B"
_UP = "\x1b[A"
_ENTER = "\r"
_CTRL_C = "\x03"


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
