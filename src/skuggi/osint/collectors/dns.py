"""Passive DNS collector via DNS-over-HTTPS (public, keyless).

Resolves the subject's common record types through the public DoH JSON API -- a
passive lookup against a resolver, never a query to the target's own servers. Each
answer becomes a ``dns:<TYPE>`` item. Best-effort per record type: one type
failing never fails the task.
"""

from __future__ import annotations

import json

from skuggi.engagement.scope import OsintSource
from skuggi.intel.collectors.base import CollectContext, HttpRequest
from skuggi.osint.schema import OsintItem, OsintResult, OsintTask

_DOH_URL = "https://dns.google/resolve"
_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


class DnsCollector:
    """Passive DNS record lookup over DoH."""

    source: OsintSource = "dns"

    def available(self, ctx: CollectContext) -> bool:  # noqa: ARG002 -- protocol shape
        """Always available: public, keyless."""
        return True

    def collect(self, task: OsintTask, ctx: CollectContext) -> OsintResult:
        """Resolve the subject's A/AAAA/MX/NS/TXT records."""
        items: list[OsintItem] = []
        for rtype in _RECORD_TYPES:
            body = ctx.fetch(
                HttpRequest(_DOH_URL, params={"name": task.subject, "type": rtype})
            )
            items.extend(_answers(body, rtype))
        note = f"{len(items)} DNS records across {len(_RECORD_TYPES)} types"
        return OsintResult(
            task_id=task.id,
            source="dns",
            subject=task.subject,
            items=tuple(items),
            note=note,
        )


def _answers(body: str | None, rtype: str) -> list[OsintItem]:
    """Parse a DoH JSON ``Answer`` list into items (empty on any failure)."""
    if not body:
        return []
    try:
        data = json.loads(body)
    except ValueError:
        return []
    answers = data.get("Answer") if isinstance(data, dict) else None
    if not isinstance(answers, list):
        return []
    return [
        OsintItem(kind=f"dns:{rtype}", value=str(a["data"]))
        for a in answers
        if isinstance(a, dict) and "data" in a
    ]
