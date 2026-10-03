"""L1: the interactive, gated install-missing flow (front-end-agnostic)."""

from __future__ import annotations

from pathlib import Path

from skuggi.agent.grants import SessionGrants
from skuggi.frontend.confirm import SESSION, Choose
from skuggi.frontend.installflow import run_install_missing
from skuggi.tooling.registry import InstallPlan, ToolSpec, ToolStatus

_PLAN = InstallPlan(argv=("brew", "install", "nmap"), target="host", installer="brew")


def _choose(answer: str | None) -> Choose:
    def choose(_p: str, _o: list[str], _d: str | None) -> str | None:
        return answer

    return choose


def _status(binary: str, *, found: bool) -> ToolStatus:
    spec = ToolSpec(name=binary, binary=binary, method="scan")
    return ToolStatus(
        spec=spec,
        found=found,
        path=Path(f"/usr/bin/{binary}") if found else None,
        version="1.0" if found else None,
        source="host" if found else "missing",
    )


class _Installer:
    """A recording ``install`` stub returning a post-install status."""

    def __init__(self, *, found: bool = True) -> None:
        self.calls: list[str] = []
        self._found = found

    def __call__(self, binary: str) -> ToolStatus | None:
        self.calls.append(binary)
        return _status(binary, found=self._found)


def test_nothing_to_install_is_reported() -> None:
    notes: list[str] = []
    inst = _Installer()
    run_install_missing(
        choose=_choose("yes"),
        notify=notes.append,
        propose=list,
        install=inst,
        grants=SessionGrants(),
    )
    assert inst.calls == []
    assert any("no missing scoped tools" in n for n in notes)


def test_declining_installs_nothing() -> None:
    inst = _Installer()
    run_install_missing(
        choose=_choose("no"),
        notify=lambda _m: None,
        propose=lambda: [("nmap", _PLAN)],
        install=inst,
        grants=SessionGrants(),
    )
    assert inst.calls == []


def test_confirming_installs_each_and_reports() -> None:
    notes: list[str] = []
    inst = _Installer()
    run_install_missing(
        choose=_choose("yes"),
        notify=notes.append,
        propose=lambda: [("nmap", _PLAN), ("nikto", _PLAN)],
        install=inst,
        grants=SessionGrants(),
    )
    assert inst.calls == ["nmap", "nikto"]
    assert any("installed nmap" in n for n in notes)


def test_a_failed_install_is_reported_not_claimed() -> None:
    notes: list[str] = []
    run_install_missing(
        choose=_choose("yes"),
        notify=notes.append,
        propose=lambda: [("nmap", _PLAN)],
        install=_Installer(found=False),  # install ran, tool still absent
        grants=SessionGrants(),
    )
    assert any("install failed or unavailable for nmap" in n for n in notes)


def test_session_grant_is_recorded() -> None:
    grants = SessionGrants()
    run_install_missing(
        choose=_choose(SESSION),
        notify=lambda _m: None,
        propose=lambda: [("nmap", _PLAN)],
        install=_Installer(),
        grants=grants,
    )
    assert grants.granted("install")
