"""L1: OSINT scope-promotion candidates + the verifier's gated proposal (E17)."""

from __future__ import annotations

from datetime import UTC, datetime

from skuggi.engagement.engagement import EngagementConfig
from skuggi.intel.schema import IntelItem, IntelResult
from skuggi.osint import nodes
from skuggi.osint.deps import OsintDeps
from skuggi.osint.promote import promotable_hosts


def _engagement(**kw: object) -> EngagementConfig:
    base: dict[str, object] = {
        "name": "e",
        "timezone": "UTC",
        "authorized_start": datetime(2000, 1, 1, tzinfo=UTC),
        "authorized_end": datetime(2999, 1, 1, tzinfo=UTC),
    }
    base.update(kw)
    return EngagementConfig.model_validate(base)


def _result(*items: IntelItem) -> IntelResult:
    return IntelResult(task_id="t", source="dns", subject="example.com", items=items)


def test_promotes_an_in_network_host_not_yet_allowed() -> None:
    eng = _engagement(target_networks=["10.0.0.0/24"], allowed_hosts=["10.0.0.1"])
    results = [
        _result(
            IntelItem(
                kind="subdomain", value="api.example.com", attributes={"ip": "10.0.0.9"}
            ),
            IntelItem(kind="host", value="10.0.0.1"),  # already allowed -> skipped
            IntelItem(kind="host", value="8.8.8.8"),  # out of network -> skipped
        )
    ]
    assert promotable_hosts(results, eng) == ["10.0.0.9"]


def test_nothing_promotable_without_target_networks() -> None:
    eng = _engagement(allowed_hosts=["10.0.0.1"])
    results = [_result(IntelItem(kind="host", value="10.0.0.9"))]
    assert promotable_hosts(results, eng) == []


def test_verifier_summary_appends_a_gated_scope_proposal() -> None:
    eng = _engagement(target_networks=["10.0.0.0/24"])
    deps = OsintDeps(engagement=eng)
    results = [_result(IntelItem(kind="host", value="10.0.0.42"))]
    out = nodes._with_scope_proposal("base summary", results, deps)
    assert "base summary" in out
    assert "10.0.0.42" in out
    assert "set scope" in out  # routed through the gated flow, not auto-applied


def test_verifier_summary_unchanged_without_candidates() -> None:
    deps = OsintDeps(engagement=_engagement())
    assert nodes._with_scope_proposal("s", [], deps) == "s"
