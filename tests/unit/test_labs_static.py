"""Offline validation of the practice range: every lab must be well-formed.

Runs inside ``make check`` (no docker, no network): it parses every
``labs/<id>/manifest.json`` against the labctl schema, validates each drop-in
``scope.json`` through the real ``EngagementConfig``, and asserts the on-disk
artifacts a lab promises actually exist. A malformed lab fails here rather than
at ``docker compose up`` time.
"""

from __future__ import annotations

import pytest

from labctl import LABS_DIR
from labctl.manifest import LabManifest, discover_labs
from skuggi.engagement.engagement import EngagementConfig

LABS = discover_labs(LABS_DIR)
LAB_IDS = [m.id for m in LABS]


def test_at_least_the_trivial_baseline_exists() -> None:
    assert "01-trivial-goat-cms" in LAB_IDS


def test_lab_ids_are_unique() -> None:
    assert len(LAB_IDS) == len(set(LAB_IDS))


def test_webapp_set_is_discovered() -> None:
    # The nested labs/webapp/ set is found by the one-level-deep discovery.
    webapp = {m.id for m in LABS if m.category == "webapp"}
    assert "01-easy-php-plain" in webapp


def test_category_is_derived_from_layout() -> None:
    # Flat labs/<id> are "base"; labs/<group>/<id> take the group name.
    by_id = {m.id: m for m in LABS}
    assert by_id["01-trivial-goat-cms"].category == "base"
    assert by_id["01-easy-php-plain"].category == "webapp"


@pytest.mark.parametrize("manifest", LABS, ids=LAB_IDS)
def test_lab_is_well_formed(manifest: LabManifest) -> None:
    # id matches the directory name.
    assert manifest.root.name == manifest.id
    # The four required artifacts and the compose file exist.
    assert manifest.compose_file.is_file()
    assert manifest.scope_file.is_file()
    for doc in ("briefing.md", "solution.md", "README.md"):
        assert (manifest.root / doc).is_file(), f"{manifest.id} missing {doc}"
    # Ports are loopback-only and unique within the lab.
    published = [p.published for p in manifest.ports]
    assert len(published) == len(set(published))


@pytest.mark.parametrize("manifest", LABS, ids=LAB_IDS)
def test_scope_validates_as_an_engagement(manifest: LabManifest) -> None:
    scope = EngagementConfig.model_validate_json(
        manifest.scope_file.read_text(encoding="utf-8")
    )
    # The scope name lines up with the lab id (labctl scope --install relies on it).
    assert scope.name == manifest.id


@pytest.mark.parametrize("manifest", LABS, ids=LAB_IDS)
def test_loot_entries_are_addressable(manifest: LabManifest) -> None:
    for item in manifest.loot:
        assert item.fingerprint, f"{manifest.id}/{item.id} has no fingerprint"
        if item.kind == "http_contains":
            assert item.where
        elif item.kind == "file_in_container":
            assert item.service
            assert item.path
        elif item.kind == "container_exec":
            assert item.service
            assert item.cmd
        elif item.kind == "tcp_banner":
            assert item.host
            assert item.port
