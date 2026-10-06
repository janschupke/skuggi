"""The gated AI-vision seam: a structured, cited description of an image.

Vision is the one forensic signal that is *not* deterministic -- it is a model
reading an image -- so it is held to the strictest grounding discipline: the
request forces a structured :class:`VisionReport` whose every observation carries a
``speculative`` flag, the model is told to describe only what is visibly present
and flag any inference, and the evidence reference is set by US (the source image),
never taken from the model. Only genuinely vision-capable providers are used
(:data:`VISION_PROVIDERS`); on any other provider the seam returns ``None`` and the
loop proceeds without vision rather than crashing.

Reuses the ``requests.ask`` egress discipline (redaction + ``structured_invoke``)
but with a multimodal ``HumanMessage`` carrying a base64 image part.
"""

from __future__ import annotations

import base64
from pathlib import Path

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from skuggi.agent import prompts
from skuggi.agent.invoke import structured_invoke
from skuggi.common.logs import get_logger

log = get_logger(__name__)

# Providers that accept image content blocks. chatgpt (codex OAuth) and claude-cli
# (a local text-only binary) and ollama (model-dependent) are excluded: vision
# degrades to "unavailable" there, never a malformed call.
VISION_PROVIDERS: frozenset[str] = frozenset({"openai", "anthropic"})

_MIME = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".bmp": "image/bmp",
}


class VisionObservation(BaseModel):
    """One thing the examiner reports about an image."""

    text: str
    speculative: bool = Field(
        default=True,
        description="True unless the observation is plainly, directly visible.",
    )


class VisionReport(BaseModel):
    """The structured result of examining one image."""

    observations: tuple[VisionObservation, ...] = ()
    summary: str = ""


def vision_available(provider: str) -> bool:
    """Whether `provider` can process image content blocks."""
    return provider in VISION_PROVIDERS


def _data_url(path: Path) -> str | None:
    """A ``data:`` URL for `path`, or None when its type is not a known image."""
    mime = _MIME.get(path.suffix.lower())
    if mime is None:
        return None
    b64 = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime};base64,{b64}"


def describe_image(
    llm: BaseChatModel | None,
    provider: str,
    path: Path,
    *,
    native: bool,
    label: str = "vision",
) -> VisionReport | None:
    """A structured description of the image at `path`, or None when unavailable.

    Returns ``None`` (never raises) when the provider cannot do vision, the model
    is not built, or the file is not a recognised image -- so the forensics loop
    treats vision as best-effort. Every returned observation is model output and
    must be treated as speculative evidence, cited to `path` by the caller.
    """
    if llm is None or not vision_available(provider):
        return None
    data_url = _data_url(path)
    if data_url is None:
        return None
    prompt: list[BaseMessage] = [
        SystemMessage(content=prompts.VISION_EXAMINER_INSTRUCTION),
        HumanMessage(
            content=[
                {"type": "text", "text": f"Examine this image: {path.name}"},
                {"type": "image_url", "image_url": {"url": data_url}},
            ]
        ),
    ]
    try:
        return structured_invoke(llm, VisionReport, prompt, native=native, label=label)
    except (ValueError, RuntimeError) as exc:
        # A provider that advertises vision but rejects this call must not kill the
        # loop; log and let the caller proceed without a vision report.
        log.warning("vision call failed for %s: %s", path.name, exc)
        return None
