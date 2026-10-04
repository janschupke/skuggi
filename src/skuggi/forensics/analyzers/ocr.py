"""Optical character recognition over an image evidence file (local, offline).

Pillow + pytesseract, both lazily imported (the ``forensics`` extra) so the core
import graph never pulls them, and pytesseract needs a system ``tesseract`` binary
(surfaced by the doctor). OCR is deterministic -- the same image yields the same
text -- so its output is evidence, cited to the source image, not a model guess.
A missing dependency or tesseract binary yields a ``note`` observation, never an
exception, so the forensics loop keeps running without OCR.
"""

from __future__ import annotations

from pathlib import Path

from skuggi.forensics.analyzers.base import Observation

# Above this, OCR is unlikely to be the point and tesseract gets slow; the loop can
# still hash/inspect the image. Mirrors the analyzers' bounded-work discipline.
_MAX_IMAGE_BYTES = 32 * 1024 * 1024


def analyze(path: Path) -> list[Observation]:
    """Extract text from the image at `path` via tesseract OCR.

    Returns one ``ocr`` observation with the recognised text (empty when the image
    has none), or a ``note`` when OCR is unavailable.
    """
    try:
        import pytesseract  # noqa: PLC0415
        from PIL import Image, UnidentifiedImageError  # noqa: PLC0415
    except ImportError:
        return [
            Observation(
                kind="note",
                value="OCR unavailable: install the `forensics` extra",
            )
        ]
    if path.stat().st_size > _MAX_IMAGE_BYTES:
        return [
            Observation(
                kind="note",
                value="image too large for OCR",
                attributes={"max_bytes": str(_MAX_IMAGE_BYTES)},
            )
        ]
    try:
        with Image.open(path) as img:
            text = pytesseract.image_to_string(img)
    except UnidentifiedImageError:
        return [Observation(kind="note", value="not a readable image for OCR")]
    except pytesseract.TesseractNotFoundError:
        return [
            Observation(
                kind="note",
                value="OCR unavailable: the `tesseract` binary is not installed",
            )
        ]
    stripped = text.strip()
    return [
        Observation(
            kind="ocr",
            value=stripped,
            attributes={"source": path.name, "chars": str(len(stripped))},
        )
    ]
