"""The structured-output seam: obtain a validated schema from one LLM call.

Lifted out of :mod:`skuggi.agent.protocol` (which now holds only the request/
response *schemas* and their rendering) so the protocol module stays under the
size cap and the model-call seam -- the one place a provider's native
``with_structured_output`` vs. the tool-less JSON-contract-plus-repair path is
chosen, and every structured round-trip is timed -- is its own unit. The turn
graph and the intel loops reach it through ``agent.requests.ask``; a few control
verbs (install research, memory extraction) call :func:`structured_invoke`
directly.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Sequence
from typing import cast

from langchain_core.language_models import BaseChatModel, LanguageModelInput
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, ValidationError

from skuggi.common.logs import get_logger
from skuggi.common.timing import record_call

log = get_logger(__name__)


_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.MULTILINE)


def format_instructions(schema: type[BaseModel]) -> str:
    """The JSON contract appended to a request on the non-native path."""
    js = json.dumps(schema.model_json_schema(), indent=2, sort_keys=True)
    return (
        "Respond with a SINGLE JSON object and nothing else -- no prose, no "
        "markdown, no code fences -- conforming to this JSON schema:\n" + js
    )


def _text_of(reply: object) -> str:
    """The plain text of a chat reply, however the provider shaped it.

    A chat model returns a ``BaseMessage``. With the OpenAI Responses API -- the
    ``chatgpt``/codex provider, and the only one on this non-native path -- its
    ``content`` is a list of content blocks (a reasoning item plus a text item),
    not a string. ``BaseMessage.text`` flattens that to the assistant's text,
    skipping the reasoning/non-text blocks; ``str(content)`` would instead yield a
    Python repr (single quotes) that is not valid JSON and crashes ``_extract_json``.
    The ``.text`` *property* is used deliberately -- calling ``.text()`` is
    deprecated and the suite runs under ``-W error``.
    """
    if isinstance(reply, BaseMessage):
        return str(reply.text)
    content = getattr(reply, "content", reply)
    return content if isinstance(content, str) else str(content)


def _extract_json[T: BaseModel](text: str, schema: type[T]) -> T:
    """Parse the first JSON object out of ``text`` and validate it as ``schema``.

    Tolerant of a stray code fence or leading prose: the object is located by its
    outermost braces. A parse or validation failure raises, so the caller can
    decide whether to spend a repair retry.
    """
    stripped = _FENCE.sub("", text).strip()
    start, end = stripped.find("{"), stripped.rfind("}")
    if start == -1 or end <= start:
        msg = "no JSON object found in the reply"
        raise ValueError(msg)
    return schema.model_validate_json(stripped[start : end + 1])


def _timed_invoke[R](label: str, *, repaired: bool, call: Callable[[], R]) -> R:
    """Run one model ``call``, recording its wall-clock against the active turn.

    The one seam where every structured LLM round-trip is timed: it feeds the
    per-turn :mod:`skuggi.common.timing` collector (so a turn can report where its
    seconds went) and logs one diagnostic line per call. ``repaired`` marks the
    JSON-contract retry so a doubled tool-less call is visible, not hidden. Timing
    is recorded in ``finally`` so a failed call still accounts for the time spent.
    """
    start = time.perf_counter()
    try:
        return call()
    finally:
        elapsed = time.perf_counter() - start
        record_call(label, elapsed, repaired=repaired)
        log.info(
            "llm call node=%s elapsed_s=%.3f repaired=%s",
            label or "llm",
            elapsed,
            repaired,
        )


def structured_invoke[T: BaseModel](  # noqa: PLR0913 -- the model seam binds the schema, messages, provider path, and its diagnostics label
    llm: BaseChatModel,
    schema: type[T],
    messages: Sequence[BaseMessage],
    *,
    native: bool,
    repair: bool = True,
    label: str = "",
) -> T:
    """Obtain a validated ``schema`` instance from one LLM call.

    ``native`` providers use ``with_structured_output``. The tool-less chatgpt
    path instead appends :func:`format_instructions`, parses the JSON out of the
    reply, and -- once, when ``repair`` is set -- re-asks with the validation
    error if the first reply does not validate. ``label`` names the calling node
    (planner/worker/critic) so the per-turn latency breakdown can attribute time;
    it is diagnostics only and never changes the result.
    """
    msgs = list(messages)
    if native:
        raw = _timed_invoke(
            label,
            repaired=False,
            call=lambda: llm.with_structured_output(schema).invoke(
                cast("LanguageModelInput", msgs)
            ),
        )
        return schema.model_validate(raw)

    instructed: list[BaseMessage] = [
        *msgs,
        SystemMessage(content=format_instructions(schema)),
    ]
    text = _text_of(
        _timed_invoke(
            label,
            repaired=False,
            call=lambda: llm.invoke(cast("LanguageModelInput", instructed)),
        )
    )
    try:
        return _extract_json(text, schema)
    except (ValidationError, ValueError):
        if not repair:
            raise
        retry: list[BaseMessage] = [
            *instructed,
            AIMessage(content=text),
            HumanMessage(
                content="That was not valid JSON for the schema. Return ONLY the "
                "JSON object, nothing else."
            ),
        ]
        return _extract_json(
            _text_of(
                _timed_invoke(
                    label,
                    repaired=True,
                    call=lambda: llm.invoke(cast("LanguageModelInput", retry)),
                )
            ),
            schema,
        )
