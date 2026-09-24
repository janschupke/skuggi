"""L3: the skuggi-doctor console script."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from skuggi import doctor
from skuggi.config import Settings


def test_render_probes_and_reports(
    pentest_configs: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    pentest_configs()
    monkeypatch.setattr(doctor, "probe", lambda *_a, **_k: [])
    report = doctor.render(Settings())
    assert "# skuggi tool doctor" in report


def test_main_returns_zero_with_configs(
    pentest_configs: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    pentest_configs()
    monkeypatch.setattr(doctor, "probe", lambda *_a, **_k: [])
    assert doctor.main() == 0


def test_main_reports_missing_registry() -> None:
    # No configs written; the default registry path does not exist.
    assert doctor.main() == 1
