"""The diagnostic file log setup (`skuggi.logs`).

The conftest redirects ``SKUGGI_DATA_HOME`` under ``tmp_path`` and the autouse
``reset_logging`` fixture restores the root logger after each test, so these
cases configure logging freely without leaking a handler into the next test or
writing to the developer's real data home.
"""

from __future__ import annotations

import logging
import re
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

import pytest

from skuggi.common import home, logs


def test_default_log_path_is_under_the_data_home() -> None:
    assert logs.default_log_path() == home.data_home() / "logs" / "skuggi.log"


def test_resolve_level_defaults_to_info() -> None:
    assert logs.resolve_level() == logging.INFO


def test_resolve_level_honours_named_level(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SKUGGI_LOG_LEVEL", "warning")
    assert logs.resolve_level() == logging.WARNING


def test_resolve_level_honours_numeric_level(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SKUGGI_LOG_LEVEL", "10")
    assert logs.resolve_level() == logging.DEBUG


def test_resolve_level_falls_back_through_debug_toggle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SKUGGI_DEBUG", "1")
    assert logs.resolve_level() == logging.DEBUG


def test_unrecognised_level_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SKUGGI_LOG_LEVEL", "not-a-level")
    assert logs.resolve_level() == logging.INFO


def test_setup_logging_writes_under_the_data_home() -> None:
    path = logs.setup_logging()
    assert path == home.data_home() / "logs" / "skuggi.log"
    assert path.parent.is_dir()


def test_setup_logging_attaches_a_rotating_file_handler_and_no_stream_handler() -> None:
    root = logging.getLogger()
    before = root.handlers[:]
    logs.setup_logging()
    added = [h for h in root.handlers if h not in before]
    # Exactly one handler is added, and it is a file handler -- never a stream
    # handler, which would corrupt the Rich TUI that owns the terminal.
    assert len(added) == 1
    handler = added[0]
    assert isinstance(handler, RotatingFileHandler)
    assert handler.maxBytes == 5 * 1024 * 1024
    assert handler.backupCount == 5


def test_setup_logging_is_idempotent() -> None:
    root = logging.getLogger()
    before = len(root.handlers)
    logs.setup_logging()
    logs.setup_logging()
    added = len(root.handlers) - before
    assert added == 1


def test_setup_logging_updates_level_on_a_second_call() -> None:
    logs.setup_logging(level=logging.WARNING)
    logs.setup_logging(level=logging.DEBUG)
    assert logging.getLogger().level == logging.DEBUG


def test_a_log_record_reaches_the_file() -> None:
    path = logs.setup_logging(level=logging.DEBUG)
    logs.get_logger("skuggi.test").error("canary-message")
    for handler in logging.getLogger().handlers:
        handler.flush()
    assert "canary-message" in path.read_text(encoding="utf-8")


def test_log_exception_captures_a_traceback(tmp_path: Path) -> None:
    path = logs.setup_logging(path=tmp_path / "logs" / "skuggi.log", level=logging.INFO)
    log = logs.get_logger("skuggi.test")
    try:
        _ = 1 / 0
    except ZeroDivisionError:
        log.exception("handled failure")
    for handler in logging.getLogger().handlers:
        handler.flush()
    text = path.read_text(encoding="utf-8")
    assert "handled failure" in text
    assert "Traceback" in text
    assert "ZeroDivisionError" in text


def test_noisy_libraries_are_capped_at_warning() -> None:
    logs.setup_logging(level=logging.DEBUG)
    assert logging.getLogger("httpx").level == logging.WARNING


def test_the_handler_timestamps_in_utc() -> None:
    # The diagnostic log must line up with the UTC ledger: asctime defaults to
    # local time, so the formatter has to convert via time.gmtime.
    logs.setup_logging(level=logging.DEBUG)
    handler = next(
        h for h in logging.getLogger().handlers if isinstance(h, RotatingFileHandler)
    )
    assert handler.formatter is not None
    assert handler.formatter.converter is time.gmtime


def test_a_log_line_carries_a_utc_z_timestamp() -> None:
    path = logs.setup_logging(level=logging.DEBUG)
    logs.get_logger("skuggi.test").error("stamp-canary")
    for handler in logging.getLogger().handlers:
        handler.flush()
    line = next(
        ln
        for ln in path.read_text(encoding="utf-8").splitlines()
        if "stamp-canary" in ln
    )
    # Leading ISO-8601 UTC timestamp ending in Z, e.g. 2026-10-02T14:30:00Z.
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z ", line)
