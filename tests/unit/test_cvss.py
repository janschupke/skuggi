"""CVSS v3.1 scoring, checked against authoritative values.

The base-score fixtures are the widely-published canonical CVSS v3.1 scores (the
same numbers the FIRST calculator yields); the temporal/environmental fixtures are
hand-derived from the spec formulae and exercise both the scope-unchanged and
scope-changed branches. Keeping them here makes "the score is real and
reproducible" a test, not a claim.
"""

from __future__ import annotations

import pytest

from skuggi.frameworks import cvss

# (vector, expected base score, expected severity band)
_BASE_VECTORS = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),  # reflected XSS
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9, "medium"),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "low"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "none"),
]


@pytest.mark.parametrize(("vector", "base", "severity"), _BASE_VECTORS)
def test_base_score(vector: str, base: float, severity: str) -> None:
    result = cvss.score(vector)
    assert result.base == base
    assert result.severity == severity
    assert result.version == "3.1"
    # No temporal/environmental metrics -> overall is the base, others absent.
    assert result.overall == base
    assert result.temporal is None
    assert result.environmental is None


def test_temporal_dampens_the_base() -> None:
    # Base 9.8, then E:U (0.91) * RL:O (0.95) * RC:C (1.0) -> roundup(8.4721) = 8.5.
    result = cvss.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C")
    assert result.base == 9.8
    assert result.temporal == 8.5
    assert result.environmental is None
    assert result.overall == 8.5


def test_environmental_scope_unchanged() -> None:
    # Security requirements raise MISS to its 0.915 cap; MAC:H lowers exploitability.
    result = cvss.score(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAC:H"
    )
    assert result.base == 9.8
    assert result.environmental == 8.1
    assert result.overall == 8.1
    assert result.severity == "high"


def test_environmental_scope_changed() -> None:
    # Base scope Changed; modified CIA all High under default requirements -> 10.0.
    result = cvss.score(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N/MS:C/MC:H/MI:H/MA:H"
    )
    assert result.base == 7.2
    assert result.environmental == 10.0
    assert result.overall == 10.0


def test_overall_prefers_environmental_over_temporal() -> None:
    result = cvss.score(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C/CR:L"
    )
    assert result.temporal is not None
    assert result.environmental is not None
    assert result.overall == result.environmental


def test_score_is_reproducible_from_stored_vector() -> None:
    """The stored (version, vector) alone reconstructs the number -- no turn context."""
    original = cvss.score("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:L/E:F/RL:T/CR:H")
    # Re-score from only what the ledger would persist.
    assert original.version == "3.1"
    recomputed = cvss.score(original.vector)
    assert recomputed.overall == original.overall
    assert recomputed.base == original.base
    assert recomputed.temporal == original.temporal
    assert recomputed.environmental == original.environmental


def test_serialize_is_canonical_and_drops_not_defined() -> None:
    parsed = cvss.parse("CVSS:3.1/UI:N/AC:L/AV:N/PR:N/S:U/A:H/C:H/I:H/E:X")
    # Canonical metric order, and the Not-Defined E:X is dropped.
    assert cvss.serialize(parsed) == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.mark.parametrize(
    "vector",
    [
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # no version prefix
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # wrong version
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A (mandatory)
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # invalid base value
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:N",  # unknown metric
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # duplicate metric
    ],
)
def test_parse_rejects_bad_vectors(vector: str) -> None:
    with pytest.raises(cvss.CvssError):
        cvss.parse(vector)
