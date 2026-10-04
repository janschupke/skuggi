"""Version collector over the public endoflife.date API.

Resolves a product's release cycles from endoflife.date -- the latest release and
the currently-supported (commonly-deployed) versions -- returning each cycle as a
``version`` item. The subject is lowercased into a product slug; a ``versions``
source-config block may map an alias (``"wordpress 6.x"`` -> ``"wordpress"``).
Keyless and best-effort: any failure yields an empty result.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime

from skuggi.intel.collectors.base import (
    CollectContext,
    CollectTask,
    HttpRequest,
    IntelItem,
    IntelResult,
    empty_result,
)

_API = "https://endoflife.date/api"


class VersionsCollector:
    """Latest + supported versions for a product, from endoflife.date."""

    source: str = "versions"

    def available(self, ctx: CollectContext) -> bool:  # noqa: ARG002 -- protocol shape
        """Always available: the endoflife.date API needs no key."""
        return True

    def collect(self, task: CollectTask, ctx: CollectContext) -> IntelResult:
        """Resolve the subject's release cycles from endoflife.date."""
        product = _product(task.subject, ctx.config_for("versions"))
        body = ctx.fetch(HttpRequest(f"{_API}/{product}.json"))
        if not body:
            return empty_result(task, f"no version data for {product!r}")
        return _parse(task, body)


def _product(subject: str, cfg: Mapping[str, str]) -> str:
    """Slug the subject into an endoflife.date product id, honouring an alias map."""
    stripped = subject.strip().lower()
    base = stripped.split()[0] if stripped else subject
    return cfg.get(stripped, cfg.get(base, base))


def _parse(task: CollectTask, body: str) -> IntelResult:
    try:
        cycles = json.loads(body)
    except ValueError:
        return empty_result(task, "endoflife.date response was not valid JSON")
    if not isinstance(cycles, list):
        return empty_result(task, "endoflife.date response was not a list")
    items = tuple(item for row in cycles if (item := _item(row)) is not None)
    return IntelResult(
        task_id=task.id,
        source="versions",
        subject=task.subject,
        items=items,
        note=f"{len(items)} release cycles",
    )


def _item(row: object) -> IntelItem | None:
    if not isinstance(row, dict):
        return None
    cycle = str(row.get("cycle", ""))
    if not cycle:
        return None
    eol = row.get("eol")
    today = datetime.now(UTC).date().isoformat()
    supported = eol is False or (isinstance(eol, str) and eol >= today)
    return IntelItem(
        kind="version",
        value=cycle,
        attributes={
            "latest": str(row.get("latest") or ""),
            "released": str(row.get("releaseDate") or ""),
            "eol": str(eol),
            "supported": str(bool(supported)),
        },
    )
