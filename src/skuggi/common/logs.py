"""The diagnostic file log -- skuggi's own record of what went wrong.

This is *not* the domain log. The engagement timeline and the harness-interaction
audit are structured SQLite tables in ``skuggi.ledger``; they record what the
operator and agent *did*. This module is the orthogonal thing: a plain rotating
text file under the data home that records what *failed* -- swallowed exceptions,
degraded config loads, provider/network errors -- so a silent failure leaves a
durable trace instead of vanishing into a backgrounded daemon's dead stderr.

Library convention, kept deliberately: modules only ever *get* a logger
(``get_logger(__name__)``) and never configure one; only the console-script entry
points call ``setup_logging`` once at startup. The handler is file-only -- a
stream handler on stdout/stderr would corrupt the Rich TUI that owns the terminal.

The log path is resolved under the data home (``skuggi.home.data_home``) **at call
time**, never at import: the test suite redirects ``SKUGGI_DATA_HOME`` per test,
and a module-level ``.expanduser()`` is the standing anti-pattern this whole home
split exists to avoid (see ``skuggi.home``). ``setup_logging`` also deliberately
does not take a ``Settings`` -- a boot failure must still be logged even when
constructing ``Settings`` is itself what failed.
"""

from __future__ import annotations

import logging
import os
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from skuggi.common import home
from skuggi.common.paths import ensure_parent

# The leaf log file under ``<data home>/logs/``. Rotated in place.
_LOG_DIRNAME = "logs"
_LOG_FILENAME = "skuggi.log"

# Rotation: a handful of 5 MB files is plenty for post-mortem on a local harness
# and bounds disk use without a cron.
_MAX_BYTES = 5 * 1024 * 1024
_BACKUP_COUNT = 5

_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
# UTC, ISO-8601 with an explicit ``Z`` -- so the diagnostic log lines up with the
# UTC ledger/preferences timestamps instead of drifting by the host's offset. The
# formatter's ``converter`` (set to ``time.gmtime`` below) is what actually makes
# ``%(asctime)s`` render in UTC; ``%(asctime)s`` defaults to ``time.localtime``.
_DATEFMT = "%Y-%m-%dT%H:%M:%SZ"

# Env knobs. ``SKUGGI_LOG_LEVEL`` takes a level name or number; ``SKUGGI_DEBUG``
# (the existing traceback toggle read in ``skuggi.boot``) forces DEBUG.
_LEVEL_ENV = "SKUGGI_LOG_LEVEL"
_DEBUG_ENV = "SKUGGI_DEBUG"

# Third-party loggers whose DEBUG/INFO would flood the file. Capped at WARNING so
# their genuine warnings and errors (a provider 4xx, a dropped connection) are
# still recorded -- exactly the failures hardest to diagnose otherwise.
_NOISY_LIBRARIES = (
    "httpx",
    "httpcore",
    "urllib3",
    "openai",
    "anthropic",
    "langchain",
    "langchain_core",
    "langgraph",
    "faiss",
)

# A marker attribute on our handler so ``setup_logging`` is idempotent: repeated
# entry-point calls (e.g. a nested ``guard_boot``) must not stack handlers.
_MARKER = "_skuggi_file_handler"


def default_log_path() -> Path:
    """The diagnostic log file path (``<data home>/logs/skuggi.log``).

    Resolved per call, never cached: the data home is itself resolved per call and
    the test suite redirects it between tests.
    """
    return home.data_home() / _LOG_DIRNAME / _LOG_FILENAME


def resolve_level() -> int:
    """The effective log level: ``SKUGGI_LOG_LEVEL`` > ``SKUGGI_DEBUG`` > INFO.

    ``SKUGGI_LOG_LEVEL`` accepts a name (``DEBUG``) or a number (``10``); an
    unrecognised value falls through to the default rather than crashing startup.
    """
    raw = (os.environ.get(_LEVEL_ENV) or "").strip()
    if raw:
        if raw.isdigit():
            return int(raw)
        named = logging.getLevelName(raw.upper())
        if isinstance(named, int):
            return named
    if (os.environ.get(_DEBUG_ENV) or "").strip():
        return logging.DEBUG
    return logging.INFO


def setup_logging(path: Path | None = None, level: int | None = None) -> Path:
    """Attach the rotating file handler to the root logger. Idempotent.

    ``path`` and ``level`` default to :func:`default_log_path` and
    :func:`resolve_level`. Returns the resolved path so an entry point can report
    it. A second call with our handler already installed only updates the level,
    so repeated startup paths never stack handlers or reopen the file.
    """
    resolved = ensure_parent(path or default_log_path())
    effective = level if level is not None else resolve_level()
    root = logging.getLogger()
    root.setLevel(effective)

    existing = next(
        (h for h in root.handlers if getattr(h, _MARKER, False)),
        None,
    )
    if existing is None:
        handler = RotatingFileHandler(
            resolved,
            maxBytes=_MAX_BYTES,
            backupCount=_BACKUP_COUNT,
            encoding="utf-8",
        )
        formatter = logging.Formatter(_FORMAT, datefmt=_DATEFMT)
        formatter.converter = time.gmtime
        handler.setFormatter(formatter)
        setattr(handler, _MARKER, True)
        root.addHandler(handler)
    existing_or_new = next(h for h in root.handlers if getattr(h, _MARKER, False))
    existing_or_new.setLevel(effective)

    for name in _NOISY_LIBRARIES:
        logging.getLogger(name).setLevel(logging.WARNING)

    return resolved


def get_logger(name: str) -> logging.Logger:
    """The module logger for ``name`` (conventionally ``__name__``).

    A thin wrapper so modules import one symbol from here and never touch the
    stdlib ``logging`` configuration directly.
    """
    return logging.getLogger(name)
