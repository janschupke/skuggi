"""Shodan host-search collector (passive HTTP, needs a key).

Queries the Shodan REST API for hosts matching the subject's hostname -- exposed
ports, products and known CVEs -- a passive database lookup (``recon`` tier), never
a scan of the target. Requires ``shodan_api_key``; unavailable (a recorded gap)
without it. Best-effort parsing, never raises.
"""

from __future__ import annotations

import json

from skuggi.engagement.scope import OsintSource
from skuggi.intel.collectors.base import CollectContext, HttpRequest, empty_result
from skuggi.osint.schema import OsintItem, OsintResult, OsintTask

_URL = "https://api.shodan.io/shodan/host/search"


class ShodanCollector:
    """Exposed-service intelligence from the Shodan database."""

    source: OsintSource = "shodan"

    def available(self, ctx: CollectContext) -> bool:
        """Usable only with a Shodan API key."""
        return bool(ctx.secrets.get("shodan_api_key"))

    def collect(self, task: OsintTask, ctx: CollectContext) -> OsintResult:
        """Search Shodan for hosts under the subject hostname."""
        key = ctx.secrets.get("shodan_api_key")
        if not key:
            return empty_result(task, "shodan api key not configured")
        body = ctx.fetch(
            HttpRequest(_URL, params={"key": key, "query": f"hostname:{task.subject}"})
        )
        if not body:
            return empty_result(task, "shodan returned no data")
        return _parse(task, body)


def _parse(task: OsintTask, body: str) -> OsintResult:
    try:
        data = json.loads(body)
    except ValueError:
        return empty_result(task, "shodan response was not valid JSON")
    matches = data.get("matches") if isinstance(data, dict) else None
    if not isinstance(matches, list):
        return empty_result(task, "shodan response had no matches")
    items = tuple(
        OsintItem(
            kind="host",
            value=str(m.get("ip_str", "")),
            attributes={
                "port": str(m.get("port", "")),
                "product": str(m.get("product") or ""),
                "cves": ",".join(str(v) for v in (m.get("vulns") or {})),
            },
        )
        for m in matches
        if isinstance(m, dict) and m.get("ip_str")
    )
    return OsintResult(
        task_id=task.id,
        source="shodan",
        subject=task.subject,
        items=items,
        note=f"{len(items)} exposed hosts from shodan",
    )
