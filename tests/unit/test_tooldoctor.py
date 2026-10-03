"""L1: ToolDoctor.propose_installs -- the deterministic install candidate set."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from skuggi.agent.core import AgentCore
from skuggi.agent.tooldoctor import ToolDoctor
from skuggi.tooling import probe
from skuggi.tooling.registry import InstallPlan, ToolSpec, ToolStatus

_PLAN = InstallPlan(argv=("brew", "install", "x"), target="host", installer="brew")


def _spec(
    binary: str, method: str = "scan", *, install: dict[str, str] | None = None
) -> ToolSpec:
    return ToolSpec(name=binary, binary=binary, method=method, install=install or {})


def _status(spec: ToolSpec, *, found: bool) -> ToolStatus:
    return ToolStatus(
        spec=spec,
        found=found,
        path=Path("/x") if found else None,
        version=None,
        source="host" if found else "missing",
    )


def _doctor(engagement: object, specs: list[ToolSpec]) -> ToolDoctor:
    core = SimpleNamespace(
        engagement=engagement,
        registry=SimpleNamespace(tools=tuple(specs)),
        settings=SimpleNamespace(tool_source="combine", managed_tools_dir=Path("/m")),
    )
    return ToolDoctor(cast("AgentCore", core))


def test_no_engagement_proposes_nothing() -> None:
    assert _doctor(None, [_spec("nmap")]).propose_installs() == []


def test_only_scoped_missing_installable_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    nmap = _spec("nmap", "scan")  # scoped by tool, missing, installable
    sqlmap = _spec("sqlmap", "enumerate")  # scoped by method, missing, installable
    found = _spec("nikto", "scan")  # scoped but already present -> excluded
    unscoped = _spec("hydra", "bruteforce")  # not scoped -> excluded
    noplan = _spec("burp", "scan")  # scoped, missing, but no install plan -> excluded
    specs = [nmap, sqlmap, found, unscoped, noplan]

    statuses = {
        "nmap": _status(nmap, found=False),
        "sqlmap": _status(sqlmap, found=False),
        "nikto": _status(found, found=True),
        "hydra": _status(unscoped, found=False),
        "burp": _status(noplan, found=False),
    }
    monkeypatch.setattr(
        probe, "probe_presence", lambda *_a, **_k: list(statuses.values())
    )
    monkeypatch.setattr(
        probe,
        "select_install",
        lambda spec, **_k: None if spec.binary == "burp" else _PLAN,
    )

    engagement = SimpleNamespace(
        allowed_tools=frozenset({"nmap", "nikto", "burp"}),
        allowed_methods=frozenset({"enumerate"}),
    )
    proposed = dict(_doctor(engagement, specs).propose_installs())
    assert set(proposed) == {"nmap", "sqlmap"}
    assert proposed["nmap"] is _PLAN
