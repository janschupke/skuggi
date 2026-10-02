"""L1: the per-engagement workspace layout and path derivation."""

from __future__ import annotations

from pathlib import Path

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
