"""L1: the OCR analyzer and the gated AI-vision seam (no real tesseract/provider)."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from langchain_core.language_models import BaseChatModel

from skuggi.agent import vision
from skuggi.agent.vision import VisionObservation, VisionReport
from skuggi.forensics.analyzers import ocr

# A stand-in for the chat model: the seam never calls it (we monkeypatch
# structured_invoke, or it returns before use), so its identity is all that matters.
_LLM = cast("BaseChatModel", object())


def _png(tmp_path: Path) -> Path:
    """A tiny valid PNG written with Pillow (skips if Pillow is absent)."""
    pil = pytest.importorskip("PIL.Image")
    p = tmp_path / "shot.png"
    pil.new("RGB", (8, 8), "white").save(p)
    return p


# --- OCR --------------------------------------------------------------------


def test_ocr_returns_recognised_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytesseract = pytest.importorskip("pytesseract")
    monkeypatch.setattr(pytesseract, "image_to_string", lambda _img: "SECRET note\n")
    [obs] = ocr.analyze(_png(tmp_path))
    assert obs.kind == "ocr"
    assert obs.value == "SECRET note"
    assert obs.attributes["source"] == "shot.png"


def test_ocr_on_a_non_image_is_a_note(tmp_path: Path) -> None:
    pytest.importorskip("pytesseract")
    bad = tmp_path / "notimage.bin"
    bad.write_bytes(b"\x00\x01\x02not an image")
    [obs] = ocr.analyze(bad)
    assert obs.kind == "note"


def test_ocr_rejects_an_oversized_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("pytesseract")
    p = _png(tmp_path)
    monkeypatch.setattr(ocr, "_MAX_IMAGE_BYTES", 1)
    [obs] = ocr.analyze(p)
    assert obs.kind == "note"
    assert "too large" in obs.value


# --- vision gating ----------------------------------------------------------


def test_vision_available_only_for_multimodal_providers() -> None:
    assert vision.vision_available("openai")
    assert vision.vision_available("anthropic")
    assert not vision.vision_available("claude-cli")
    assert not vision.vision_available("chatgpt")
    assert not vision.vision_available("ollama")


def test_describe_image_skips_a_non_vision_provider(tmp_path: Path) -> None:
    out = vision.describe_image(_LLM, "claude-cli", _png(tmp_path), native=True)
    assert out is None


def test_describe_image_skips_a_non_image_file(tmp_path: Path) -> None:
    txt = tmp_path / "a.txt"
    txt.write_text("hi", encoding="utf-8")
    assert vision.describe_image(_LLM, "openai", txt, native=True) is None


def test_describe_image_returns_structured_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = VisionReport(
        observations=(
            VisionObservation(text="a login form is visible", speculative=False),
            VisionObservation(text="appears to be a bank", speculative=True),
        ),
        summary="screenshot of a login page",
    )
    monkeypatch.setattr(vision, "structured_invoke", lambda *_a, **_k: report)
    out = vision.describe_image(_LLM, "openai", _png(tmp_path), native=True)
    assert out is report
    assert any(o.speculative for o in out.observations)


def test_describe_image_swallows_a_failing_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> VisionReport:
        msg = "provider rejected the image"
        raise RuntimeError(msg)

    monkeypatch.setattr(vision, "structured_invoke", boom)
    assert vision.describe_image(_LLM, "anthropic", _png(tmp_path), native=True) is None
