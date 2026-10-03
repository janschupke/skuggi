"""L1: the per-engagement workspace layout and path derivation."""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.engagement.workspace import Workspace, WorkspaceLayout


def test_default_layout_lists_every_directory() -> None:
    dirs = WorkspaceLayout().dirs()
    assert "recon" in dirs
    assert "recon/nmap" in dirs
    assert "recon/dirs" in dirs
    assert "recon/domains" in dirs
    assert "recon/web" in dirs
    assert "reports" in dirs
    assert "loot" in dirs
    assert "inputs" in dirs
    assert "evidence" in dirs


def test_ensure_creates_inputs_and_evidence(tmp_path: Path) -> None:
    ws = Workspace.for_engagement(tmp_path / "engagements", "acme-2026")
    ws.ensure()
    assert ws.inputs_dir.is_dir()
    assert ws.evidence_dir.is_dir()


def test_vault_path_is_a_root_dotfile(tmp_path: Path) -> None:
    ws = Workspace.for_engagement(tmp_path / "e", "x")
    assert ws.vault_path == ws.root / ".vault.db"


def test_resolve_within_allows_a_confined_path(tmp_path: Path) -> None:
    ws = Workspace.for_engagement(tmp_path / "e", "x")
    ws.ensure()
    resolved = ws.resolve_within(ws.inputs_dir, "rockyou.txt")
    assert resolved == (ws.inputs_dir / "rockyou.txt").resolve()


@pytest.mark.parametrize("escape", ["../../etc/passwd", "../../../tmp/x", "../loot/x"])
def test_resolve_within_rejects_traversal(tmp_path: Path, escape: str) -> None:
    ws = Workspace.for_engagement(tmp_path / "e", "x")
    ws.ensure()
    with pytest.raises(ValueError, match="escapes the workspace"):
        ws.resolve_within(ws.inputs_dir, escape)


def test_resolve_within_rejects_a_symlink_out(tmp_path: Path) -> None:
    ws = Workspace.for_engagement(tmp_path / "e", "x")
    ws.ensure()
    secret = (tmp_path / "secret.txt").resolve()
    secret.write_text("SECRET", encoding="utf-8")
    link = ws.inputs_dir / "link.txt"
    link.symlink_to(secret)
    with pytest.raises(ValueError, match="escapes the workspace"):
        ws.resolve_within(ws.inputs_dir, "link.txt")


def test_derives_paths_from_the_engagement_name(tmp_path: Path) -> None:
    ws = Workspace.for_engagement(tmp_path / "engagements", "acme-2026")
    assert ws.root == tmp_path / "engagements" / "acme-2026"
    assert ws.scope_path == ws.root / "scope.json"
    assert ws.ledger_path == ws.root / "ledger.db"
    assert ws.reports_dir == ws.root / "reports"
    assert ws.recon_dir == ws.root / "recon"
    assert ws.notes_file == ws.notes_dir / "notes.md"
    assert ws.loot_file == ws.loot_dir / "loot.md"


def test_ensure_creates_the_tree(tmp_path: Path) -> None:
    ws = Workspace.for_engagement(tmp_path / "engagements", "acme-2026")
    ws.ensure()
    assert ws.root.is_dir()
    assert ws.reports_dir.is_dir()
    assert (ws.recon_dir / "nmap").is_dir()
    assert (ws.recon_dir / "dirs").is_dir()
    assert (ws.recon_dir / "domains").is_dir()
    assert (ws.recon_dir / "web").is_dir()
    assert ws.findings_dir.is_dir()
    assert ws.loot_dir.is_dir()


def test_ensure_is_idempotent(tmp_path: Path) -> None:
    ws = Workspace.for_engagement(tmp_path / "engagements", "acme-2026")
    ws.ensure()
    ws.ensure()  # must not raise
    assert ws.root.is_dir()


def test_layout_override_changes_paths(tmp_path: Path) -> None:
    layout = WorkspaceLayout(reports="out", recon="scans")
    ws = Workspace.for_engagement(tmp_path / "e", "x", layout=layout)
    ws.ensure()
    assert ws.reports_dir == ws.root / "out"
    assert ws.recon_dir == ws.root / "scans"
    assert (ws.root / "out").is_dir()


# --- S5: an engagement name must not traverse out of engagements_dir --------


@pytest.mark.parametrize(
    "bad", ["../../tmp/x", "/etc/skuggi", "a/b", "..", "~root", "", ".hidden"]
)
def test_for_engagement_rejects_an_unsafe_name(tmp_path: Path, bad: str) -> None:
    with pytest.raises(ValueError, match="engagement name"):
        Workspace.for_engagement(tmp_path, bad)


def test_for_engagement_accepts_a_safe_name(tmp_path: Path) -> None:
    ws = Workspace.for_engagement(tmp_path, "acme-2026")
    assert ws.root == tmp_path / "acme-2026"
