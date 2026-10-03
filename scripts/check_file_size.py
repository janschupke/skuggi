#!/usr/bin/env python
"""Gate: fail if any source file exceeds the line-count cap.

Ruff guards *function* size and complexity (the pylint ``PLR09xx`` family and
mccabe ``C901``), but it has no file-length rule. This is that rule: a cohesive
module has a ceiling, past which it should be split along a real seam -- never an
arbitrary part-1/part-2 cut. It runs inside ``make check`` and CI alongside
ruff/mypy, and as a pre-commit hook.

The cap catches bloat; it does not force cosmetic splits. Nothing sits near it: the
former hub ``agent/core.py`` was decomposed into a facade over collaborators
(``provider_kernel``, ``engagement_manager``, ``turn_runner``,
``reconcile_controller``), and the two largest files (``frontend/tui.py``,
``persistence/ledger.py``) are each a cohesive single class comfortably under it.

If a file needs to grow past the cap, that is the signal to find a genuine seam --
the way ``dispatch.py`` became ``outcomes``/``presenters``, ``daemon.py`` shed
``daemon_server``/``attach``, and ``core.py`` became a facade over four
collaborators -- not to raise the cap.

Usage:
    python scripts/check_file_size.py            # gate the tree
    python scripts/check_file_size.py --max 800  # try a tighter cap
"""

from __future__ import annotations

import argparse
from collections.abc import Iterator
from pathlib import Path

# The linted, shipped/maintained trees -- the same roots ruff's ``src`` covers.
# The numbered practice labs hold deliberately-messy vulnerable app code and are
# excluded from every gate, this one included.
ROOTS = ("src/skuggi", "tests", "labs/_lib", "scripts")
MAX_LINES = 900


def _line_count(path: Path) -> int:
    """Line count, matching ``wc -l`` for the newline-terminated files here."""
    return path.read_text(encoding="utf-8").count("\n")


def offenders(max_lines: int) -> Iterator[tuple[Path, int]]:
    """Every tracked ``*.py`` under ROOTS whose length exceeds `max_lines`."""
    for root in ROOTS:
        for path in sorted(Path(root).rglob("*.py")):
            count = _line_count(path)
            if count > max_lines:
                yield path, count


def main(argv: list[str] | None = None) -> int:
    """Print every over-cap file and return 1 when any exist."""
    parser = argparse.ArgumentParser(description="File line-count gate.")
    parser.add_argument(
        "--max", type=int, default=MAX_LINES, help=f"line cap (default {MAX_LINES})"
    )
    args = parser.parse_args(argv)
    bad = list(offenders(args.max))
    for path, count in bad:
        print(f"{path}: {count} lines (cap {args.max})")
    if bad:
        print(
            f"\n{len(bad)} file(s) over the {args.max}-line cap. "
            "Split along a real seam, don't raise the cap."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
