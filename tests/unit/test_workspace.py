"""L1: the per-engagement workspace layout and path derivation."""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.engagement.workspace import (
    Workspace,
    WorkspaceLayout,
    has_engagement,
    safe_engagement_name,
)


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
    ws = Workspace.at(tmp_path / "eng")
    ws.ensure()
    assert ws.inputs_dir.is_dir()
    assert ws.evidence_dir.is_dir()


def test_vault_path_is_a_root_dotfile(tmp_path: Path) -> None:
    ws = Workspace.at(tmp_path / "e")
    assert ws.vault_path == ws.root / ".vault.db"


def test_resolve_within_allows_a_confined_path(tmp_path: Path) -> None:
    ws = Workspace.at(tmp_path / "e")
    ws.ensure()
    resolved = ws.resolve_within(ws.inputs_dir, "rockyou.txt")
    assert resolved == (ws.inputs_dir / "rockyou.txt").resolve()


@pytest.mark.parametrize("escape", ["../../etc/passwd", "../../../tmp/x", "../loot/x"])
def test_resolve_within_rejects_traversal(tmp_path: Path, escape: str) -> None:
    ws = Workspace.at(tmp_path / "e")
    ws.ensure()
    with pytest.raises(ValueError, match="escapes the workspace"):
        ws.resolve_within(ws.inputs_dir, escape)


def test_resolve_within_rejects_a_symlink_out(tmp_path: Path) -> None:
    ws = Workspace.at(tmp_path / "e")
    ws.ensure()
    secret = (tmp_path / "secret.txt").resolve()
    secret.write_text("SECRET", encoding="utf-8")
    link = ws.inputs_dir / "link.txt"
    link.symlink_to(secret)
    with pytest.raises(ValueError, match="escapes the workspace"):
        ws.resolve_within(ws.inputs_dir, "link.txt")


def test_derives_paths_from_the_root(tmp_path: Path) -> None:
    root = tmp_path / "acme-2026"
    ws = Workspace.at(root)
    assert ws.root == root
    assert ws.scope_path == ws.root / "scope.json"
    assert ws.ledger_path == ws.root / "ledger.db"
    assert ws.reports_dir == ws.root / "reports"
    assert ws.recon_dir == ws.root / "recon"
    assert ws.notes_file == ws.notes_dir / "notes.md"
    assert ws.loot_file == ws.loot_dir / "loot.md"


def test_ensure_creates_the_tree(tmp_path: Path) -> None:
    ws = Workspace.at(tmp_path / "eng")
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
    ws = Workspace.at(tmp_path / "eng")
    ws.ensure()
    ws.ensure()  # must not raise
    assert ws.root.is_dir()


def test_layout_override_changes_paths(tmp_path: Path) -> None:
    layout = WorkspaceLayout(reports="out", recon="scans")
    ws = Workspace.at(tmp_path / "e", layout=layout)
    ws.ensure()
    assert ws.reports_dir == ws.root / "out"
    assert ws.recon_dir == ws.root / "scans"
    assert (ws.root / "out").is_dir()


def test_has_engagement_detects_a_scope_file(tmp_path: Path) -> None:
    root = tmp_path / "eng"
    root.mkdir()
    assert not has_engagement(root)  # empty dir is not an engagement
    (root / "scope.json").write_text("{}", encoding="utf-8")
    assert has_engagement(root)
    assert not has_engagement(tmp_path / "missing")  # absent root


# --- the scope NAME label (no longer a directory segment) -------------------


@pytest.mark.parametrize(
    ("name", "slug"),
    [
        ("Lab 01", "lab-01"),  # a human name works
        ("acme-2026", "acme-2026"),
        ("MyEngagement", "myengagement"),
        ("a/b", "a-b"),
        ("~root", "root"),
        (".hidden", "hidden"),
    ],
)
def test_safe_engagement_name_normalizes_a_label(name: str, slug: str) -> None:
    assert safe_engagement_name(name) == slug


@pytest.mark.parametrize("bad", ["", "..", "   ", "!!!", "///", "-"])
def test_safe_engagement_name_rejects_an_empty_or_unsafe_label(bad: str) -> None:
    with pytest.raises(ValueError, match="engagement name"):
        safe_engagement_name(bad)
