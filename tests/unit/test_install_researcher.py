"""L1: install research -- the grounding/validation boundary over the LLM's picks.

The LLM only SELECTS from search hits; the controller re-validates every pick and
rebuilds the argv. These tests drive the validation directly by stubbing the search
results and the structured LLM reply, so the security properties (grounding, the
installer allow-list, metacharacter rejection) are pinned without a real model.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from skuggi.agent.install_researcher import InstallResearcher
from skuggi.agent.protocol import InstallCandidate, InstallResearch
from skuggi.tooling.registry import PackageHit

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore


class _FakeSettings:
    managed_tools_dir = Path("managed-tools")  # unused here; install() is not called

    def supports_structured_output(self) -> bool:
        return False


class _FakeCore:
    def __init__(self) -> None:
        self.settings = _FakeSettings()

    def ensure_llm(self) -> object:
        return object()


def _researcher() -> InstallResearcher:
    return InstallResearcher(cast("AgentCore", _FakeCore()))


def _wire(  # noqa: PLR0913 -- a test fixture wiring several independent stubs
    monkeypatch: pytest.MonkeyPatch,
    *,
    installers: set[str],
    hits: list[PackageHit],
    reply: InstallResearch,
    forbid_llm: bool = False,
    pip_hits: list[PackageHit] | None = None,
) -> None:
    monkeypatch.setattr(
        "skuggi.tooling.probe.available_installers", lambda: frozenset(installers)
    )
    monkeypatch.setattr("skuggi.tooling.probe.search_packages", lambda *_a, **_k: hits)
    # Stubbed so researcher tests never touch the network (and so the pip branch is
    # controllable); pip grounding is exercised explicitly via `pip_hits`.
    monkeypatch.setattr(
        "skuggi.tooling.websearch.pypi_candidates", lambda *_a, **_k: pip_hits or []
    )

    def _invoke(*_a: object, **_k: object) -> InstallResearch:
        if forbid_llm:
            msg = "the LLM must not be consulted here"
            raise AssertionError(msg)
        return reply

    monkeypatch.setattr("skuggi.agent.install_researcher.structured_invoke", _invoke)


def test_a_grounded_pick_becomes_a_rebuilt_install_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _wire(
        monkeypatch,
        installers={"brew"},
        hits=[PackageHit("brew", "nmap", "network mapper")],
        reply=InstallResearch(
            candidates=(
                InstallCandidate(installer="brew", package="nmap", rationale="r"),
            )
        ),
    )
    result = _researcher().research("nmap")
    assert len(result.plans) == 1
    plan = result.plans[0]
    assert plan.argv == ("brew", "install", "nmap")
    assert plan.installer == "brew"
    assert plan.rationale == "r"
    assert plan.source == "searched:brew"


def test_a_cask_pick_builds_a_cask_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(
        monkeypatch,
        installers={"brew"},
        hits=[PackageHit("brew-cask", "burp-suite")],
        reply=InstallResearch(
            candidates=(InstallCandidate(installer="brew-cask", package="burp-suite"),)
        ),
    )
    [plan] = _researcher().research("burpsuite").plans
    assert plan.argv == ("brew", "install", "--cask", "burp-suite")
    assert plan.is_cask


def test_an_ungrounded_package_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A package the search never returned cannot become a plan.

    That covers both a model hallucination and an injected/attacker-suggested name.
    """
    _wire(
        monkeypatch,
        installers={"brew"},
        hits=[PackageHit("brew", "nmap")],
        reply=InstallResearch(
            candidates=(InstallCandidate(installer="brew", package="evil-not-found"),)
        ),
    )
    assert _researcher().research("nmap").plans == ()


def test_an_installer_absent_from_the_host_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _wire(
        monkeypatch,
        installers={"brew"},  # apt is NOT present
        hits=[PackageHit("apt", "nmap")],  # a stale/implausible apt hit
        reply=InstallResearch(
            candidates=(InstallCandidate(installer="apt", package="nmap"),)
        ),
    )
    assert _researcher().research("nmap").plans == ()


def test_a_non_allowlisted_installer_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _wire(
        monkeypatch,
        installers={"brew", "snap"},
        hits=[PackageHit("snap", "whatever")],  # snap is not in the allow-list
        reply=InstallResearch(
            candidates=(InstallCandidate(installer="snap", package="whatever"),)
        ),
    )
    assert _researcher().research("whatever").plans == ()


def test_a_grounded_token_with_metacharacters_is_still_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Last line of defence against a grounded-but-unsafe token.

    Even a 'grounded' token that carries shell metacharacters never reaches an argv.
    """
    _wire(
        monkeypatch,
        installers={"brew"},
        hits=[PackageHit("brew", "bad;rm -rf /")],
        reply=InstallResearch(
            candidates=(InstallCandidate(installer="brew", package="bad;rm -rf /"),)
        ),
    )
    assert _researcher().research("x").plans == ()


def test_no_search_hits_still_advises_but_grounds_out_any_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tool in no package manager (e.g. GitHub-only) still gets honest advice.

    Any ungrounded install command the model returns alongside it is dropped.
    """
    _wire(
        monkeypatch,
        installers={"brew"},
        hits=[],  # in no package manager
        reply=InstallResearch(
            candidates=(InstallCandidate(installer="brew", package="made-up"),),
            advice="clone github.com/cddmp/enum4linux-ng and run it",
        ),
    )
    result = _researcher().research("enum4linux-ng")
    assert result.plans == ()  # the ungrounded candidate never survives
    assert "cddmp/enum4linux-ng" in result.advice


def test_advice_is_passed_through_when_nothing_is_installable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _wire(
        monkeypatch,
        installers={"brew"},
        hits=[PackageHit("brew", "unrelated")],
        reply=InstallResearch(advice="download it from the vendor portal"),
    )
    result = _researcher().research("burpsuite")
    assert result.plans == ()
    assert result.advice == "download it from the vendor portal"


def test_a_pip_pick_grounded_by_pypi_targets_the_managed_venv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The enum4linux-ng case: pip-only, grounded via PyPI, routed to the venv."""
    _wire(
        monkeypatch,
        installers={"brew", "pip"},
        hits=[],  # neither brew nor apt has it
        pip_hits=[PackageHit("pip", "enum4linux-ng", "AD enumeration")],
        reply=InstallResearch(
            candidates=(InstallCandidate(installer="pip", package="enum4linux-ng"),)
        ),
    )
    [plan] = _researcher().research("enum4linux-ng").plans
    assert plan.argv == ("pip", "install", "enum4linux-ng")
    assert plan.target == "managed"
    assert plan.installer == "pip"


def test_duplicate_picks_are_de_duplicated(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(
        monkeypatch,
        installers={"brew"},
        hits=[PackageHit("brew", "nmap")],
        reply=InstallResearch(
            candidates=(
                InstallCandidate(installer="brew", package="nmap"),
                InstallCandidate(installer="brew", package="nmap"),
            )
        ),
    )
    assert len(_researcher().research("nmap").plans) == 1
