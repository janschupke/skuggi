"""crt.sh certificate-transparency collector (passive, keyless).

Queries the public crt.sh JSON endpoint for certificates issued to a domain and
its subdomains -- a classic passive subdomain-discovery source. Best-effort: a
network failure or unparseable body yields an empty result, never an exception.
"""

from __future__ import annotations

import json

from skuggi.engagement.scope import OsintSource
from skuggi.osint.collectors.base import (
    CollectContext,
    HttpRequest,
    empty_result,
)
from skuggi.osint.schema import OsintItem, OsintResult, OsintTask

_URL = "https://crt.sh/"


class CrtShCollector:
    """Passive subdomain discovery via certificate transparency."""

    source: OsintSource = "crtsh"

    def available(self, ctx: CollectContext) -> bool:  # noqa: ARG002 -- protocol shape
        """Always available: public, keyless."""
        return True

    def collect(self, task: OsintTask, ctx: CollectContext) -> OsintResult:
        """Fetch issued-certificate names for the subject domain."""
        body = ctx.fetch(
            HttpRequest(_URL, params={"q": f"%.{task.subject}", "output": "json"})
        )
        if not body:
            return empty_result(task, "crt.sh returned no data")
        return _parse(task, body)


def _parse(task: OsintTask, body: str) -> OsintResult:
    """Turn crt.sh JSON into unique subdomain items under the subject."""
    try:
        rows = json.loads(body)
    except ValueError:
        return empty_result(task, "crt.sh response was not valid JSON")
    if not isinstance(rows, list):
        return empty_result(task, "crt.sh response was not a list")
    suffix = task.subject.lower()
    hosts: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        issuer = str(row.get("issuer_name", ""))
        for name in str(row.get("name_value", "")).splitlines():
            host = name.strip().lstrip("*.").lower()
            if host and (host == suffix or host.endswith(f".{suffix}")):
                hosts.setdefault(host, issuer)
    items = tuple(
        OsintItem(kind="subdomain", value=host, attributes={"issuer": issuer})
        for host, issuer in sorted(hosts.items())
    )
    note = f"{len(items)} unique subdomains from certificate transparency"
    return OsintResult(
        task_id=task.id, source="crtsh", subject=task.subject, items=items, note=note
    )
