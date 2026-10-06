"""L1: the authorization-boundary taxonomy (hard block / escalation / grantable)."""

from __future__ import annotations

from skuggi.security.boundaries import BoundaryKind, boundary_kind, label


def test_out_of_scope_is_a_hard_block() -> None:
    assert boundary_kind(allowed=False, within_ceiling=True) is BoundaryKind.HARD_BLOCK
    assert boundary_kind(allowed=False, within_ceiling=False) is BoundaryKind.HARD_BLOCK


def test_in_scope_above_ceiling_is_an_escalation() -> None:
    assert boundary_kind(allowed=True, within_ceiling=False) is BoundaryKind.ESCALATION


def test_in_scope_under_ceiling_runs() -> None:
    assert boundary_kind(allowed=True, within_ceiling=True) is None


def test_label_prefixes_the_kind() -> None:
    assert (
        label(BoundaryKind.HARD_BLOCK, "outside scope") == "hard block: outside scope"
    )
    assert (
        label(BoundaryKind.ESCALATION, "above ceiling") == "escalation: above ceiling"
    )
