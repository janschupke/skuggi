"""labctl -- the skuggi practice-range controller.

Standalone dev tooling under ``labs/_lib`` (not part of the shipped ``skuggi``
wheel). It reads each lab's ``manifest.json`` to bring a lab up, revert it to a
pristine planted state, wipe it, and verify the planted loot.
"""

from __future__ import annotations

from pathlib import Path

# labs/_lib/labctl/__init__.py -> parents[2] is the labs/ directory.
LABS_DIR = Path(__file__).resolve().parents[2]
