"""L5 isolation guard: the live layer must never touch the operator's real homes.

The e2e layer is exempt from the root ``isolate_credentials`` fixture, so this is
the live-layer equivalent of ``tests/unit/test_config.py::
test_suite_does_not_see_real_credentials``. If it fails, an e2e run is writing
the operator's real ``~/.config/skuggi`` / ``~/.local/share/skuggi`` -- the one
leak the suite otherwise cannot report on. It needs no docker lab, so it runs
under ``make e2e`` whether or not the fixture target is up.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.common import home
from skuggi.common.logs import default_log_path, get_logger, setup_logging
from skuggi.install.init import initialise

from .conftest import REAL_CONFIG_HOME, REAL_DATA_HOME


def _snapshot(root: Path) -> dict[str, tuple[int, int]]:
    """A (relpath -> (size, mtime_ns)) map of every file under ``root``.

    Empty when ``root`` is absent -- which is the common, and strongest, case:
    an absent real home must stay absent after a live run.
    """
    if not root.exists():
        return {}
    out: dict[str, tuple[int, int]] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            st = p.stat()
            out[str(p.relative_to(root))] = (st.st_size, st.st_mtime_ns)
    return out


@pytest.mark.e2e
def test_e2e_homes_are_redirected_under_tmp(tmp_path: Path) -> None:
    """The ``isolate_e2e_homes`` fixture actually redirected both homes."""
    assert home.config_home() == tmp_path / "config-home"
    assert home.data_home() == tmp_path / "data-home"
    assert tmp_path in default_log_path().parents


@pytest.mark.e2e
def test_e2e_touches_no_real_homes(tmp_path: Path) -> None:
    """Home-writing operations during an e2e test land in tmp, never the real homes.

    Exercises the two sharpest leak vectors directly: ``initialise`` (seeds config
    templates into the config home) and the diagnostic log (``setup_logging``
    writes under the data home). Both resolve their paths through
    ``skuggi.common.home`` at call time, so if the redirect were missing they
    would hit the operator's real homes.
    """
    before = {
        "config": _snapshot(REAL_CONFIG_HOME),
        "data": _snapshot(REAL_DATA_HOME),
    }

    # A config seed and a diagnostic-log write -- the real home-resolving paths.
    # migrate_from=None is mandatory: the _AUTO default would MOVE a checkout's
    # databases out of the repo (see skuggi-init's migration half).
    initialise(migrate_from=None)
    log_path = setup_logging()
    get_logger(__name__).info("isolation probe")
    for handler in __import__("logging").getLogger().handlers:
        handler.flush()

    # The writes went to the redirected (tmp) homes...
    assert home.config_home() == tmp_path / "config-home"
    assert (home.config_home() / "config.json").exists()
    assert log_path == default_log_path()
    assert tmp_path in log_path.parents
    assert log_path.exists()

    # ...and the operator's real homes are byte-for-byte unchanged.
    after = {
        "config": _snapshot(REAL_CONFIG_HOME),
        "data": _snapshot(REAL_DATA_HOME),
    }
    assert after == before, (
        "e2e run modified the operator's real homes -- isolation leak: "
        f"config_home={REAL_CONFIG_HOME}, data_home={REAL_DATA_HOME}"
    )
