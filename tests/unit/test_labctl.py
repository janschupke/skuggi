"""Unit tests for the labctl controller (docker mocked; no real subprocess).

labctl lives outside the shipped package (``labs/_lib``) and is excluded from
``--cov=skuggi``, so these do not affect the coverage gate; they pin the CLI's
dispatch, the destructive-confirm flow, and scope installation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from labctl import LABS_DIR, cli, compose, loot
from labctl.manifest import Loot, resolve_lab

LAB = "01-trivial-goat-cms"


@pytest.fixture
def no_docker(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, object]]:
    """Record compose calls instead of shelling out to docker."""
    calls: list[tuple[str, object]] = []

    def up(_f: Path, **kw: object) -> int:
        calls.append(("up", kw))
        return 0

    def down(_f: Path, **kw: object) -> int:
        calls.append(("down", kw))
        return 0

    def exec_in(_f: Path, svc: str, argv: object) -> int:
        calls.append(("exec", (svc, tuple(argv))))  # type: ignore[arg-type]
        return 0

    monkeypatch.setattr(compose, "is_up", lambda _f: False)
    monkeypatch.setattr(compose, "up", up)
    monkeypatch.setattr(compose, "down", down)
    monkeypatch.setattr(compose, "exec_in", exec_in)
    return calls


def test_list_renders_every_lab(
    no_docker: object, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert LAB in out
    assert "trivial" in out


def test_unknown_lab_is_a_clean_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["up", "99-nope"]) == 2
    assert "unknown lab" in capsys.readouterr().out


def test_resolve_lab_finds_a_nested_webapp_lab() -> None:
    # resolve_lab searches category subdirs, so a bare webapp id resolves.
    m = resolve_lab(LABS_DIR, "01-easy-php-plain")
    assert m.id == "01-easy-php-plain"
    assert m.category == "webapp"


def test_list_groups_by_category(
    no_docker: object, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "== base ==" in out
    assert "== webapp ==" in out
    assert "01-easy-php-plain" in out


def test_up_builds_and_waits(no_docker: list[tuple[str, object]]) -> None:
    assert cli.main(["up", LAB]) == 0
    assert no_docker == [("up", {})]


def test_restore_recreate_drops_volumes_then_up(
    no_docker: list[tuple[str, object]],
) -> None:
    assert cli.main(["restore", LAB]) == 0  # lab 01 uses strategy "recreate"
    kinds = [c[0] for c in no_docker]
    assert kinds == ["down", "up"]
    assert no_docker[0][1] == {"volumes": True}


def test_wipe_aborts_when_declined(no_docker: list[tuple[str, object]]) -> None:
    assert cli.main(["wipe", LAB], ask=lambda _p: "n") == 1
    assert no_docker == []  # nothing torn down


def test_wipe_yes_tears_down_and_removes_engagement(
    no_docker: list[tuple[str, object]],
) -> None:
    eng = loot.engagements_dir() / LAB
    eng.mkdir(parents=True)
    (eng / "ledger.db").write_text("x", encoding="utf-8")
    assert cli.main(["wipe", LAB, "--yes"]) == 0
    assert ("down", {"volumes": True}) in [(c[0], c[1]) for c in no_docker]
    assert not eng.exists()


def test_scope_install_writes_into_engagements() -> None:
    dest = loot.engagements_dir() / LAB / "scope.json"
    assert not dest.exists()
    assert cli.main(["scope", LAB, "--install"]) == 0
    assert dest.is_file()
    # It is the lab's scope verbatim and still a valid engagement.
    src = resolve_lab(LABS_DIR, LAB).scope_file.read_text(encoding="utf-8")
    assert dest.read_text(encoding="utf-8") == src


def test_verify_reports_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = Loot(id="x", kind="http_contains", fingerprint="z", where="http://h/")
    monkeypatch.setattr(
        loot,
        "verify",
        lambda _m: [loot.LootResult(loot=fake, present=False, detail="GET http://h/")],
    )
    assert cli.main(["verify", LAB]) == 1
    assert "MISS" in capsys.readouterr().out


def test_labs_dir_is_the_range_root() -> None:
    assert (LABS_DIR / "01-trivial-goat-cms").is_dir()
    assert isinstance(LABS_DIR, Path)
