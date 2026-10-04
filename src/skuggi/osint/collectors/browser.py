"""The Playwright-backed rendered-page driver (optional extra).

A :class:`~skuggi.osint.collectors.base.Driver` implementation over Playwright,
imported lazily so the base install (without the ``osint-browser`` extra) still
imports and runs the HTTP-only loop. ``playwright_available`` gates it via
``find_spec`` without importing it; ``default_driver_factory`` returns ``None`` when
the extra is absent, which is what makes the browser collectors report themselves
unavailable instead of crashing.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable

from skuggi.common.logs import get_logger
from skuggi.osint.collectors.base import Driver

log = get_logger(__name__)
_NAV_TIMEOUT_MS = 15_000


def playwright_available() -> bool:
    """Whether the optional ``playwright`` package is importable (no import)."""
    return importlib.util.find_spec("playwright") is not None


class PlaywrightDriver:
    """A headless-Chromium page fetcher (one browser per instance)."""

    def __init__(self) -> None:
        """Launch a headless Chromium via the sync Playwright API (lazy import)."""
        from playwright.sync_api import sync_playwright  # noqa: PLC0415 -- optional dep

        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)

    def fetch_html(self, url: str) -> str:
        """Navigate to ``url`` and return the rendered HTML."""
        page = self._browser.new_page()
        try:
            page.goto(url, timeout=_NAV_TIMEOUT_MS, wait_until="domcontentloaded")
            return str(page.content())
        finally:
            page.close()

    def close(self) -> None:
        """Close the browser and stop Playwright."""
        self._browser.close()
        self._pw.stop()


def default_driver_factory() -> Callable[[], Driver] | None:
    """A factory that builds a PlaywrightDriver, or None when the extra is absent."""
    if not playwright_available():
        return None
    return PlaywrightDriver
