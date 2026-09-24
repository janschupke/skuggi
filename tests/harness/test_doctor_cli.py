"""L3: the skuggi-doctor console script."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from skuggi import doctor
from skuggi import probe as probe_mod
from skuggi.config import Settings


def test_probe_statuses_reads_the_registry(
    pentest_configs: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    pentest_configs()
    monkeypatch.setattr(probe_mod, "probe", lambda *_a, **_k: [])
    assert doctor.probe_statuses(Settings()) == []


def test_main_returns_zero_with_configs(
    pentest_configs: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    pentest_configs()
    monkeypatch.setattr(probe_mod, "probe", lambda *_a, **_k: [])
    monkeypatch.setattr(probe_mod, "probe_runtimes", lambda *_a, **_k: [])
    monkeypatch.setattr(probe_mod, "probe_net_tools", lambda *_a, **_k: [])
    assert doctor.main() == 0


def test_main_reports_missing_registry() -> None:
    # No configs written; the default registry path does not exist.
    assert doctor.main() == 1
