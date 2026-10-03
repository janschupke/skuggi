"""Integrity of the vendored, pinned framework taxonomies (offline).

This does NOT hit the network -- that is the sync script's job (`make frameworks`,
or `sync_frameworks.py --check` for an online drift check). Here we only assert the
committed snapshot is well-formed and resolvable, so a corrupt or truncated vendor
file fails CI rather than at an operator's finding.
"""

from __future__ import annotations

import re

import pytest

from skuggi.frameworks import registry

_ID_PATTERNS = {
    "wstg": re.compile(r"^WSTG-[A-Z]+-\d{2}$"),
    "attack": re.compile(r"^T\d{4}(\.\d{3})?$"),
    "ptes": re.compile(r"^PTES-\d{2}$"),
}


@pytest.mark.parametrize("framework", registry.FRAMEWORKS)
def test_snapshot_is_wellformed(framework: registry.Framework) -> None:
    refs = registry.entries(framework)
    assert refs, f"{framework} has no entries"
    seen: set[str] = set()
    pattern = _ID_PATTERNS[framework]
    for ref in refs:
        assert ref.framework == framework
        assert pattern.match(ref.id), f"{framework}: malformed id {ref.id!r}"
        assert ref.title, f"{framework}: {ref.id} has no title"
        assert ref.url.startswith(("http://", "https://")), f"{framework}: {ref.id} url"
        assert ref.id not in seen, f"{framework}: duplicate id {ref.id}"
        seen.add(ref.id)


@pytest.mark.parametrize("framework", registry.FRAMEWORKS)
def test_provenance_is_present(framework: registry.Framework) -> None:
    prov = registry.provenance(framework)
    for key in ("source_url", "ref", "version", "fetched_at"):
        assert prov.get(key), f"{framework}: provenance missing {key}"


def test_resolve_and_validate() -> None:
    # A known id from each framework resolves to a ref with the right link shape.
    assert registry.resolve("wstg", "WSTG-ATHN-01") is not None
    attack = registry.resolve("attack", "T1110")  # Brute Force
    assert attack is not None
    assert attack.url == "https://attack.mitre.org/techniques/T1110"
    assert registry.resolve("ptes", "PTES-05").title == "Exploitation"  # type: ignore[union-attr]

    assert registry.validate_id("wstg", "WSTG-ATHN-01")
    assert not registry.validate_id("wstg", "WSTG-NOPE-99")
    assert registry.resolve("attack", "T9999") is None


def test_unknown_framework_rejected() -> None:
    with pytest.raises(registry.FrameworkError):
        registry.provenance("bogus")  # type: ignore[arg-type]
