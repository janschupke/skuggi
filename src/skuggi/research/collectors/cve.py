"""CVE collector over the public NVD API (keyless by default).

Queries the NVD CVE 2.0 API for the subject and returns each match as a ``cve``
item (id, a short description, a CVSS severity when present, and the public NVD
detail URL). Unauthenticated by default (rate-limited); an ``nvd_api_key`` in the
injected secrets raises the limit. Best-effort: any failure yields an empty result.
"""

from __future__ import annotations

import json

from skuggi.intel.collectors.base import (
    CollectContext,
    CollectTask,
    HttpRequest,
    IntelItem,
    IntelResult,
    empty_result,
)

_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DETAIL = "https://nvd.nist.gov/vuln/detail/"
_MAX = 20


class CveCollector:
    """Published CVEs for the subject, from the NVD public API."""

    source: str = "cve"

    def available(self, ctx: CollectContext) -> bool:  # noqa: ARG002 -- protocol shape
        """Always available: the NVD API works unauthenticated."""
        return True

    def collect(self, task: CollectTask, ctx: CollectContext) -> IntelResult:
        """Query NVD, version-scoped via a CPE when a version is known, else keyword.

        When an upstream version collector resolved a concrete version for this
        subject (audit E15/E16), query NVD by ``virtualMatchString`` -- a CPE pinned
        to that product+version -- so the hits are the CVEs that actually affect the
        running version, not every CVE ever filed against the product name. With no
        known version it falls back to the historical keyword search.
        """
        headers = {}
        key = ctx.secrets.get("nvd_api_key")
        if key:
            headers["apiKey"] = key
        version = _version_from_upstream(ctx.upstream, task.subject)
        if version:
            cpe = _cpe(task.subject, version)
            params = {"virtualMatchString": cpe, "resultsPerPage": str(_MAX)}
            mode = f"CPE {cpe}"
        else:
            params = {"keywordSearch": task.subject, "resultsPerPage": str(_MAX)}
            mode = "keyword"
        body = ctx.fetch(HttpRequest(_NVD, params=params, headers=headers))
        if not body:
            return empty_result(task, "no CVE data returned from NVD")
        return _parse(task, body, mode=mode)


def _version_from_upstream(upstream: tuple[IntelResult, ...], subject: str) -> str:
    """The most relevant concrete version an upstream collector resolved, or "".

    Prefers a ``version`` item whose result subject matches this task's subject
    (the usual version -> CVE dependency), else the first version item seen. An
    ``eol`` cycle like ``1.18`` is a usable CPE version; a bare ``latest`` is used
    only as a fallback.
    """
    want = subject.strip().lower()
    candidates: list[str] = []
    for result in upstream:
        for item in result.items:
            if item.kind != "version":
                continue
            value = item.value.strip()
            if not value:
                continue
            if result.subject.strip().lower() == want:
                return value
            candidates.append(value)
    return candidates[0] if candidates else ""


def _cpe(subject: str, version: str) -> str:
    """A permissive CPE 2.3 match string pinned to the product and version.

    The vendor is left wild (``*``) because the research loop rarely knows it; NVD's
    ``virtualMatchString`` still narrows to the product + version, which is the win
    over a bare keyword search. The product is the subject's leading token, lowered.
    """
    product = subject.strip().lower().split()[0] if subject.strip() else "*"
    product = "".join(c if c.isalnum() or c in "._-" else "_" for c in product)
    return f"cpe:2.3:a:*:{product or '*'}:{version}:*:*:*:*:*:*:*"


def _parse(task: CollectTask, body: str, *, mode: str = "keyword") -> IntelResult:
    try:
        data = json.loads(body)
    except ValueError:
        return empty_result(task, "NVD response was not valid JSON")
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list):
        return empty_result(task, "NVD response had no vulnerabilities")
    items = tuple(item for row in vulns if (item := _item(row)) is not None)
    return IntelResult(
        task_id=task.id,
        source="cve",
        subject=task.subject,
        items=items,
        note=f"{len(items)} CVEs via NVD ({mode})",
    )


def _item(row: object) -> IntelItem | None:
    if not isinstance(row, dict):
        return None
    cve = row.get("cve")
    if not isinstance(cve, dict):
        return None
    cve_id = str(cve.get("id", ""))
    if not cve_id:
        return None
    return IntelItem(
        kind="cve",
        value=cve_id,
        attributes={
            "description": _description(cve),
            "severity": _severity(cve),
            "url": f"{_DETAIL}{cve_id}",
        },
    )


def _description(cve: dict[str, object]) -> str:
    descriptions = cve.get("descriptions")
    if isinstance(descriptions, list):
        for d in descriptions:
            if isinstance(d, dict) and d.get("lang") == "en":
                return str(d.get("value", ""))[:300]
    return ""


def _severity(cve: dict[str, object]) -> str:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key)
        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
            data = rows[0].get("cvssData")
            if isinstance(data, dict):
                return str(data.get("baseSeverity") or data.get("baseScore") or "")
    return ""
