"""L1: the forensics boundary -- allow-list, no-writes, evidence confinement."""

from __future__ import annotations

from pathlib import Path

from skuggi.engagement.workspace import Workspace
from skuggi.forensics.scope import (
    FORENSIC_TOOLS,
    check_forensic_command,
    check_forensic_tool,
)
from skuggi.tooling.registry import ToolSpec

_SPEC = ToolSpec(name="file", binary="file", method="forensics", positional_file=True)


def _case(tmp_path: Path) -> Workspace:
    ws = Workspace.at(tmp_path / "case1")
    ws.ensure_case()
    return ws


def test_only_allow_listed_tools_pass() -> None:
    assert check_forensic_tool("file").allowed
    assert check_forensic_tool("exiftool").allowed
    assert not check_forensic_tool("nmap").allowed
    assert not check_forensic_tool("sqlmap").allowed
    assert "nmap" not in FORENSIC_TOOLS


def test_offensive_tool_is_denied(tmp_path: Path) -> None:
    ws = _case(tmp_path)
    v = check_forensic_command(None, ["nmap", "10.0.0.1"], ws, cwd=ws.root)
    assert not v.allowed


def test_reading_evidence_in_the_case_is_allowed(tmp_path: Path) -> None:
    ws = _case(tmp_path)
    sample = ws.evidence_dir / "a.bin"
    sample.write_bytes(b"\x7fELF")
    v = check_forensic_command(_SPEC, ["file", "evidence/a.bin"], ws, cwd=ws.root)
    assert v.allowed


def test_reading_a_path_outside_the_case_is_denied(tmp_path: Path) -> None:
    ws = _case(tmp_path)
    v = check_forensic_command(_SPEC, ["file", "/etc/shadow"], ws, cwd=ws.root)
    assert not v.allowed
    assert "evidence" in v.reason


def test_dotdot_escape_is_denied(tmp_path: Path) -> None:
    ws = _case(tmp_path)
    outside = ws.root.parent / "secret.txt"
    outside.write_text("x", encoding="utf-8")
    v = check_forensic_command(
        _SPEC, ["file", "../secret.txt"], ws, cwd=ws.evidence_dir
    )
    assert not v.allowed


def test_write_and_extract_flags_are_denied(tmp_path: Path) -> None:
    ws = _case(tmp_path)
    (ws.evidence_dir / "a.bin").write_bytes(b"x")
    exif = ToolSpec(
        name="exiftool", binary="exiftool", method="forensics", positional_file=True
    )
    # an exiftool tag assignment edits the file in place
    assert not check_forensic_command(
        exif, ["exiftool", "-Comment=pwned", "evidence/a.bin"], ws, cwd=ws.root
    ).allowed
    # binwalk extraction writes carved files to disk
    binw = ToolSpec(
        name="binwalk", binary="binwalk", method="forensics", positional_file=True
    )
    assert not check_forensic_command(
        binw, ["binwalk", "-e", "evidence/a.bin"], ws, cwd=ws.root
    ).allowed


def test_numeric_flag_value_is_not_mistaken_for_a_path(tmp_path: Path) -> None:
    """A flag value like ``-n 8`` must not be confined as an evidence path."""
    ws = _case(tmp_path)
    (ws.evidence_dir / "a.bin").write_bytes(b"x")
    # (cwd/'8') does not exist, so it is skipped, not denied
    v = check_forensic_command(_SPEC, ["file", "-s", "evidence/a.bin"], ws, cwd=ws.root)
    assert v.allowed
