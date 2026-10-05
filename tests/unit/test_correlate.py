"""L1: the deterministic CVE-id join across the research collectors (audit E16)."""

from __future__ import annotations

from skuggi.intel.schema import IntelItem, IntelResult
from skuggi.research.correlate import cve_correlations


def _result(source: str, *items: IntelItem) -> IntelResult:
    return IntelResult(task_id=source, source=source, subject="nginx", items=items)


def test_join_ties_cve_to_its_exploits_and_modules() -> None:
    cve = _result(
        "cve",
        IntelItem(
            kind="cve",
            value="CVE-2021-1234",
            attributes={"severity": "HIGH", "url": "https://nvd/CVE-2021-1234"},
        ),
    )
    edb = _result(
        "exploitdb",
        IntelItem(
            kind="exploit", value="EDB-500", attributes={"cves": "CVE-2021-1234"}
        ),
    )
    msf = _result(
        "metasploit",
        IntelItem(
            kind="module",
            value="exploit/linux/http/x",
            attributes={"cves": "CVE-2021-1234,CVE-2021-9999"},
        ),
    )

    [primary, secondary] = cve_correlations([cve, edb, msf])
    assert primary.cve_id == "CVE-2021-1234"
    assert primary.severity == "HIGH"
    assert primary.exploits == ("EDB-500",)
    assert primary.modules == ("exploit/linux/http/x",)
    # a CVE referenced only by a module still enters the view
    assert secondary.cve_id == "CVE-2021-9999"
    assert secondary.modules == ("exploit/linux/http/x",)


def test_join_is_empty_without_any_cves() -> None:
    plain = _result("exploitdb", IntelItem(kind="exploit", value="EDB-1"))
    assert cve_correlations([plain]) == []
