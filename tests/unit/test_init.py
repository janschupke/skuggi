"""L1: `skuggi-init` -- seeding the homes, and migrating a checkout's live state.

Every case passes `migrate_from` explicitly. The default detects the real
checkout, and this module's whole subject is a function that MOVES databases:
a test that took the default would relocate the developer's own session history.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skuggi.common import home
from skuggi.config.config import Settings
from skuggi.install.init import SCOPE_TEMPLATE, SEEDED, initialise
from skuggi.install.update import checkout_root


def _homes(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "config-home", tmp_path / "data-home"


def test_seeds_every_harness_config(tmp_path: Path) -> None:
    config_dir, data_dir = _homes(tmp_path)
    initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=None)
    for _, installed in SEEDED:
        assert (config_dir / installed).is_file(), installed
    assert (config_dir / SCOPE_TEMPLATE).is_file()


def test_creates_both_homes(tmp_path: Path) -> None:
    config_dir, data_dir = _homes(tmp_path)
    initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=None)
    assert config_dir.is_dir()
    assert data_dir.is_dir()


def test_seeded_config_is_valid_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Seeding has to produce a config the harness can actually load."""
    config_dir, data_dir = _homes(tmp_path)
    initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=None)
    monkeypatch.setenv(home.CONFIG_HOME_ENV, str(config_dir))
    monkeypatch.setenv(home.DATA_HOME_ENV, str(data_dir))
    assert Settings().provider == "openai"


def test_never_overwrites_an_existing_file(tmp_path: Path) -> None:
    config_dir, data_dir = _homes(tmp_path)
    config_dir.mkdir()
    (config_dir / "config.json").write_text('{"provider": "ollama"}', encoding="utf-8")
    initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=None)
    kept = json.loads((config_dir / "config.json").read_text(encoding="utf-8"))
    assert kept == {"provider": "ollama"}


def test_is_idempotent(tmp_path: Path) -> None:
    config_dir, data_dir = _homes(tmp_path)
    initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=None)
    before = {p.name: p.read_bytes() for p in sorted(config_dir.iterdir())}
    lines = initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=None)
    after = {p.name: p.read_bytes() for p in sorted(config_dir.iterdir())}
    assert after == before
    assert any("already present" in line for line in lines)


def test_notes_a_config_that_drifted_from_its_template(tmp_path: Path) -> None:
    config_dir, data_dir = _homes(tmp_path)
    config_dir.mkdir()
    # An existing config that differs from the packaged template -- seeding leaves
    # it untouched, so init must flag it so the operator can reconcile.
    (config_dir / "tools.json").write_text('{"tools": []}', encoding="utf-8")
    lines = initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=None)
    assert any("differ from the packaged templates" in line for line in lines)
    assert any("tools.json" in line and "config home" not in line for line in lines)


def test_no_drift_note_for_a_fresh_seed(tmp_path: Path) -> None:
    config_dir, data_dir = _homes(tmp_path)
    lines = initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=None)
    assert not any("differ from the packaged templates" in line for line in lines)


# --- migration --------------------------------------------------------------


def _fake_checkout(tmp_path: Path) -> Path:
    root = tmp_path / "checkout"
    (root / "configs").mkdir(parents=True)
    (root / "data").mkdir(parents=True)
    (root / "configs" / "tools.json").write_text('{"tools": []}', encoding="utf-8")
    (root / "configs" / "config.json").write_text(
        '{"provider": "ollama"}', encoding="utf-8"
    )
    (root / "data" / "sessions.db").write_bytes(b"sqlite-ish")
    (root / "data" / ".repl_history").write_text("ask something\n", encoding="utf-8")
    (root / "data" / "reports").mkdir()
    (root / "data" / "reports" / "one.md").write_text("# report", encoding="utf-8")
    return root


def test_migrates_live_config_and_data_out_of_a_checkout(tmp_path: Path) -> None:
    """That state is gitignored, so leaving it behind orphans it permanently."""
    config_dir, data_dir = _homes(tmp_path)
    root = _fake_checkout(tmp_path)
    initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=root)

    assert (config_dir / "tools.json").read_text(encoding="utf-8") == '{"tools": []}'
    assert (data_dir / "sessions.db").read_bytes() == b"sqlite-ish"
    assert (data_dir / ".repl_history").is_file()
    assert (data_dir / "reports" / "one.md").is_file()
    # A move, not a copy: one live database, no ambiguity about which is in use.
    assert not (root / "configs" / "tools.json").exists()
    assert not (root / "data" / "sessions.db").exists()


def test_a_migrated_config_is_not_then_overwritten_by_the_template(
    tmp_path: Path,
) -> None:
    """Migration runs before seeding, or it would clobber what it just moved."""
    config_dir, data_dir = _homes(tmp_path)
    root = _fake_checkout(tmp_path)
    initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=root)
    kept = json.loads((config_dir / "config.json").read_text(encoding="utf-8"))
    assert kept == {"provider": "ollama"}


def test_migration_never_clobbers_a_file_already_in_the_home(tmp_path: Path) -> None:
    """A second checkout must not overwrite the first one's migrated data."""
    config_dir, data_dir = _homes(tmp_path)
    data_dir.mkdir(parents=True)
    (data_dir / "sessions.db").write_bytes(b"the-real-one")
    root = _fake_checkout(tmp_path)
    initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=root)
    assert (data_dir / "sessions.db").read_bytes() == b"the-real-one"
    # Left in place rather than deleted -- nothing is ever destroyed.
    assert (root / "data" / "sessions.db").is_file()


def test_templates_are_not_migrated_as_live_config(tmp_path: Path) -> None:
    """`*.example.json` in a checkout's configs/ is a template, not live config."""
    config_dir, data_dir = _homes(tmp_path)
    root = _fake_checkout(tmp_path)
    (root / "configs" / "scope.example.json").write_text("{}", encoding="utf-8")
    initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=root)
    assert (root / "configs" / "scope.example.json").is_file()


def test_migration_from_a_root_without_those_directories_is_a_no_op(
    tmp_path: Path,
) -> None:
    config_dir, data_dir = _homes(tmp_path)
    bare = tmp_path / "bare"
    bare.mkdir()
    lines = initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=bare)
    assert not any("migrated" in line for line in lines)


def test_migrate_from_none_leaves_a_checkout_alone(tmp_path: Path) -> None:
    config_dir, data_dir = _homes(tmp_path)
    root = _fake_checkout(tmp_path)
    initialise(config_dir=config_dir, data_dir=data_dir, migrate_from=None)
    assert (root / "data" / "sessions.db").is_file()
    assert (root / "configs" / "tools.json").is_file()


def test_checkout_root_finds_this_repo() -> None:
    """Editable installs resolve into the source tree, which is what `update` needs."""
    root = checkout_root()
    assert root is not None
    assert (root / "pyproject.toml").is_file()
    assert (root / "src" / "skuggi" / "install" / "init.py").is_file()
