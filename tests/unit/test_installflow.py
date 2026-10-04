"""L1: the interactive, gated install-missing flow (front-end-agnostic)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
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
        choose=_choose("approve"),
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
        choose=_choose("deny"),
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
        choose=_choose("approve"),
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
        choose=_choose("approve"),
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


def test_pending_wraps_each_install_with_a_labelled_affordance() -> None:
    """Each blocking install is held inside its `pending` context, in order.

    That is what lets the front-end show live progress instead of a frozen shell.
    """
    events: list[str] = []
    inst = _Installer()

    def recording_install(binary: str) -> ToolStatus | None:
        events.append(f"install:{binary}")
        return inst(binary)

    @contextmanager
    def pending(label: str) -> Iterator[None]:
        events.append(f"enter:{label}")
        try:
            yield
        finally:
            events.append(f"exit:{label}")

    run_install_missing(
        choose=_choose("approve"),
        notify=lambda _m: None,
        propose=lambda: [("nmap", _PLAN), ("nikto", _PLAN)],
        install=recording_install,
        grants=SessionGrants(),
        pending=pending,
    )
    assert events == [
        "enter:installing nmap (1 of 2)",
        "install:nmap",
        "exit:installing nmap (1 of 2)",
        "enter:installing nikto (2 of 2)",
        "install:nikto",
        "exit:installing nikto (2 of 2)",
    ]


# --- run_install_research: the escalation flow for an unresolved tool ---------


from skuggi.frontend.installflow import run_install_research  # noqa: E402
from skuggi.tooling.registry import InstallOutcome, ResearchResult  # noqa: E402

_RESEARCHED = InstallPlan(
    argv=("brew", "install", "--cask", "burp-suite"),
    target="host",
    installer="brew",
    rationale="best cask match",
    source="searched:brew-cask",
)


def _research(result: ResearchResult) -> Callable[[str], ResearchResult]:
    def research(_tool: str) -> ResearchResult:
        return result

    return research


class _PlanInstaller:
    """Records (plan, binary) calls; returns a scripted outcome per call."""

    def __init__(self, *outcomes: bool) -> None:
        self._outcomes = list(outcomes)
        self.calls: list[tuple[tuple[str, ...], str]] = []

    def __call__(self, plan: InstallPlan, binary: str) -> InstallOutcome:
        self.calls.append((plan.argv, binary))
        installed = self._outcomes.pop(0) if self._outcomes else False
        return InstallOutcome(
            binary=binary,
            installed=installed,
            path=None,
            source="cask" if installed else "failed",
        )


def test_research_with_no_plans_reports_advice_and_does_not_confirm() -> None:
    notes: list[str] = []
    inst = _PlanInstaller()
    run_install_research(
        "burpsuite",
        choose=_choose("approve"),  # would approve, but must never be asked
        notify=notes.append,
        research=_research(ResearchResult(plans=(), advice="grab it from the vendor")),
        install=inst,
        grants=SessionGrants(),
    )
    assert inst.calls == []
    assert any("grab it from the vendor" in n for n in notes)


def test_research_confirmed_installs_and_stops_at_first_success() -> None:
    notes: list[str] = []
    second = InstallPlan(
        argv=("apt-get", "install", "-y", "burp"), target="host", installer="apt"
    )
    inst = _PlanInstaller(True, True)
    run_install_research(
        "burpsuite",
        choose=_choose("approve"),
        notify=notes.append,
        research=_research(ResearchResult(plans=(_RESEARCHED, second))),
        install=inst,
        grants=SessionGrants(),
    )
    # First plan succeeded, so the second is never attempted.
    assert inst.calls == [(_RESEARCHED.argv, "burpsuite")]
    assert any("installed burpsuite via cask" in n for n in notes)


def test_research_falls_through_to_the_next_plan_on_failure() -> None:
    notes: list[str] = []
    second = InstallPlan(
        argv=("brew", "install", "burpsuite"), target="host", installer="brew"
    )
    inst = _PlanInstaller(False, True)
    run_install_research(
        "burpsuite",
        choose=_choose("approve"),
        notify=notes.append,
        research=_research(ResearchResult(plans=(_RESEARCHED, second))),
        install=inst,
        grants=SessionGrants(),
    )
    assert [c[0] for c in inst.calls] == [_RESEARCHED.argv, second.argv]
    assert any("installed burpsuite via cask" in n for n in notes)


def test_research_declined_installs_nothing() -> None:
    inst = _PlanInstaller(True)
    run_install_research(
        "burpsuite",
        choose=_choose("deny"),
        notify=lambda _m: None,
        research=_research(ResearchResult(plans=(_RESEARCHED,))),
        install=inst,
        grants=SessionGrants(),
    )
    assert inst.calls == []
