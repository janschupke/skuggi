"""Entry point: ``python -m labctl`` and the ``labs/labctl`` shim both land here."""

from __future__ import annotations

from labctl.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
