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
        """Search NVD by keyword and return the top CVE matches."""
        headers = {}
        key = ctx.secrets.get("nvd_api_key")
        if key:
            headers["apiKey"] = key
        body = ctx.fetch(
            HttpRequest(
                _NVD,
                params={"keywordSearch": task.subject, "resultsPerPage": str(_MAX)},
                headers=headers,
            )
        )
        if not body:
            return empty_result(task, "no CVE data returned from NVD")
        return _parse(task, body)


def _parse(task: CollectTask, body: str) -> IntelResult:
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
        note=f"{len(items)} CVEs via NVD",
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
