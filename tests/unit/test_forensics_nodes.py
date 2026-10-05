"""L1: the forensics anti-hallucination grounding gate (audit B1).

A finding may read CONFIRMED only when every evidence_ref resolves EXACTLY to a
collected evidence id. With ids E1..E11, a ref E100 (superstring of E10) or a
bare "1" (substring of E1) must NOT resolve -- the old bidirectional substring
check let both through, leaking ungrounded findings to the case ledger.
"""

from __future__ import annotations

from skuggi.forensics.nodes import _ground
from skuggi.forensics.schema import ForensicsFinding, ForensicsVerdict

VALID = {f"E{i}" for i in range(1, 12)}  # E1..E11


def _verdict(*refs: str, speculative: bool = False) -> ForensicsVerdict:
    return ForensicsVerdict(
        findings=(
            ForensicsFinding(title="t", evidence_refs=refs, speculative=speculative),
        )
    )


def _only(verdict: ForensicsVerdict) -> ForensicsFinding:
    assert len(verdict.findings) == 1
    return verdict.findings[0]


def test_exact_ref_is_grounded() -> None:
    assert _only(_ground(_verdict("E1"), VALID)).speculative is False
    assert _only(_ground(_verdict("E11"), VALID)).speculative is False


def test_superstring_ref_does_not_resolve() -> None:
    assert _only(_ground(_verdict("E100"), VALID)).speculative is True


def test_substring_ref_does_not_resolve() -> None:
    assert _only(_ground(_verdict("1"), VALID)).speculative is True


def test_no_refs_is_speculative() -> None:
    assert _only(_ground(_verdict(), VALID)).speculative is True


def test_case_and_whitespace_are_normalized() -> None:
    assert _only(_ground(_verdict(" e1 "), VALID)).speculative is False


def test_model_marked_speculative_stays_speculative_even_when_grounded() -> None:
    assert _only(_ground(_verdict("E1", speculative=True), VALID)).speculative is True


def test_all_refs_must_resolve() -> None:
    assert _only(_ground(_verdict("E1", "E100"), VALID)).speculative is True
