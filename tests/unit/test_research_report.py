"""L1: the research Markdown report writer -- render, redact, confine."""

from __future__ import annotations

from pathlib import Path

from skuggi.intel.schema import IntelItem, IntelResult
from skuggi.research.report import render_report, write_research_report
from skuggi.research.schema import ResearchProfile, VulnRef


def _profile() -> ResearchProfile:
    return ResearchProfile(
        subject="wordpress",
        latest_version="6.4.3",
        commonly_deployed_versions=("6.4", "6.3"),
        built_on=("PHP", "MySQL"),
        known_vulnerabilities=(
            VulnRef(
                id="CVE-2024-0001",
                title="auth bypass",
                severity="HIGH",
                url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
                source="cve",
            ),
        ),
        notes="widely deployed CMS",
    )


def _results() -> list[IntelResult]:
    return [
        IntelResult(
            task_id="t1",
            source="cve",
            subject="wordpress",
            items=(IntelItem(kind="cve", value="CVE-2024-0001"),),
            note="1 CVE",
        )
    ]


def test_render_includes_profile_and_vuln_table() -> None:
    md = render_report("research wordpress", _profile(), _results())
    assert "# Research: wordpress" in md
    assert "**Latest version:** 6.4.3" in md
    assert "6.4, 6.3" in md
    assert "PHP, MySQL" in md
    assert "CVE-2024-0001" in md
    assert "| ID | Severity |" in md
    assert "## Collected sources" in md


def test_render_without_profile_falls_back_to_request() -> None:
    md = render_report("jenkins", None, [])
    assert "# Research: jenkins" in md
    assert "## Summary" not in md
    assert "## Collected sources" not in md


def test_write_report_redacts_and_confines(tmp_path: Path) -> None:
    out = tmp_path / "research"
    path = write_research_report(
        out,
        "research wordpress",
        _profile(),
        _results(),
        clean=lambda s: s.replace("auth bypass", "[REDACTED]"),
    )
    assert path.parent == out.resolve()
    body = path.read_text(encoding="utf-8")
    assert "[REDACTED]" in body
    assert "auth bypass" not in body
    assert path.name.startswith("wordpress-")
    assert path.suffix == ".md"


def test_write_report_sanitizes_a_traversal_subject(tmp_path: Path) -> None:
    # Unlike the per-source store, the report filename is slugged, so a traversal
    # subject is sanitized into a safe name rather than escaping the output root.
    out = tmp_path / "research"
    bad = ResearchProfile(subject="../../etc")
    path = write_research_report(out, "x", bad, [], clean=lambda s: s)
    assert path.parent == out.resolve()
    assert ".." not in path.name


def test_report_renders_the_cve_exploitability_join() -> None:
    """The report ties a CVE to its exploit/module via the deterministic join (E16)."""
    results = [
        IntelResult(
            task_id="c",
            source="cve",
            subject="nginx",
            items=(
                IntelItem(
                    kind="cve", value="CVE-2024-0001", attributes={"severity": "HIGH"}
                ),
            ),
        ),
        IntelResult(
            task_id="m",
            source="metasploit",
            subject="nginx",
            items=(
                IntelItem(
                    kind="module",
                    value="exploit/x",
                    attributes={"cves": "CVE-2024-0001"},
                ),
            ),
        ),
    ]
    out = render_report("nginx vulns", None, results)
    assert "## Exploitability (CVE join)" in out
    assert "CVE-2024-0001" in out
    assert "exploit/x" in out


def test_report_omits_exploitability_without_a_join() -> None:
    results = [
        IntelResult(
            task_id="c",
            source="cve",
            subject="nginx",
            items=(IntelItem(kind="cve", value="CVE-2024-0001"),),
        )
    ]
    assert "## Exploitability" not in render_report("nginx", None, results)
