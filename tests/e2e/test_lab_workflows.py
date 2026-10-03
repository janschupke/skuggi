"""L5 workflow breadth: more of the engagement surface against the frozen fixture.

These reuse the single ``skuggi-lab`` stack (the one the e2e fixture owns, never
the user-facing ``labs/`` range) rather than standing up new targets -- bring-up
dominates wall time, so many scenarios share one stack. That is only safe
because every scenario here is READ-ONLY against the target, which the no-race
guard below proves: a shared stack stays order-independent. See
``docs/testing.md`` and the plan for the matrix and its budget.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.agent.protocol import FindingDraft
from tests.e2e.conftest import Lab, Runner

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]

# The fixture's pinned oracles (see tests/e2e/fixtures/lab/web/db/seed.sql).
_ADMIN_MD5 = "482c811da5d5b4bc6d497ffa98491e38"
_DRAFT_SENTINEL = "remove /backup/db_dump.sql before launch"
_SQLI_UNION = (
    "id=0%20UNION%20SELECT%201,username,password,4,email,6,7%20FROM%20users--%20-"
)

# CVSS vectors spanning three bands (scored by skuggi's own oracle, not asserted
# here -- test_chain_report.py pins the band math).
_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
_MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"


def _weasyprint_available() -> bool:
    try:
        import weasyprint  # noqa: F401, PLC0415
    except (ImportError, OSError):  # OSError: the native Pango libs are missing
        return False
    return True


def test_shared_target_is_not_mutated_across_scenarios(
    engage: Runner, lab: Lab
) -> None:
    """The no-race guarantee: reading the target repeatedly is order-independent.

    Runs an IDOR read, a SQLi read, then the SAME IDOR read again in one
    engagement; the two IDOR captures must be byte-identical. If any scenario
    sharing this stack mutated the target, the second read would differ -- so
    this is the standing proof that stacking many read-only scenarios on one
    container cannot race.
    """
    idor = f"curl -s {lab.base_url}/post.php?id=4"
    sqli = f"curl -s {lab.base_url}/post.php?{_SQLI_UNION}"
    rows = engage.run(idor, sqli, idor)

    executed = [r for r in rows if r.status == "executed"]
    assert len(executed) == 3
    idor_rows = [r for r in executed if "post.php?id=4" in r.command]
    assert len(idor_rows) == 2
    assert _DRAFT_SENTINEL in idor_rows[0].stdout  # the IDOR oracle really fired
    assert idor_rows[0].stdout == idor_rows[1].stdout  # target unchanged between them


def test_multi_finding_report_groups_and_renders_pdf(engage: Runner, lab: Lab) -> None:
    """A multi-finding engagement renders grouped Markdown and, if able, a PDF.

    Three findings across bands ride a real three-command engagement; once
    approved they must render under severity headings in canonical order. The
    PDF leg skips cleanly when WeasyPrint's native stack is unavailable.
    """
    findings = (
        FindingDraft(
            title="SQLi dumps password hashes",
            description="post.php?id= concatenates into a numeric SQL context.",
            evidence=f"admin hash {_ADMIN_MD5} recovered via UNION",
            cvss_vector=_CRITICAL,
        ),
        FindingDraft(
            title="IDOR exposes an unpublished draft",
            description="post.php?id=4 returns a draft to an unauthenticated user.",
            cvss_vector=_HIGH,
        ),
        FindingDraft(
            title="Database backup is world-readable",
            description="/backup/db_dump.sql is served to anyone.",
            cvss_vector=_MEDIUM,
        ),
    )
    engage.run(
        f"curl -s {lab.base_url}/post.php?{_SQLI_UNION}",
        f"curl -s {lab.base_url}/post.php?id=4",
        f"curl -s {lab.base_url}/backup/db_dump.sql",
        findings=findings,
    )
    core = engage.core
    recorded = core.journal.findings()
    assert len(recorded) == 3
    for row in recorded:
        core.ledger.set_finding_status(row.id, "approved")

    md = core.journal.write_report()
    assert isinstance(md, Path)
    text = md.read_text(encoding="utf-8")
    headings = ["### CRITICAL (1)", "### HIGH (1)", "### MEDIUM (1)"]
    positions = [text.index(h) for h in headings]
    assert positions == sorted(positions)  # canonical severity order
    assert "Approved findings: 3" in text

    if not _weasyprint_available():
        pytest.skip("WeasyPrint not available -- PDF leg skipped")
    result = core.journal.write_report(pdf=True)
    assert isinstance(result, tuple)
    _md_path, pdf_path = result
    assert pdf_path.suffix == ".pdf"
    assert pdf_path.is_file()
    assert pdf_path.stat().st_size > 0
