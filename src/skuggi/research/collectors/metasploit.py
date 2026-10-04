"""metasploit collector -- local module metadata, read-only (optional tool).

Lights up only when the metasploit module-metadata cache is readable
(``~/.msf4/store/modules_metadata.json``, written by the framework itself);
otherwise ``available`` is False and the task degrades to a coverage gap. ``collect``
filters the cached module index by the subject -- a fast, read-only file parse that
avoids spawning a slow ``msfconsole`` search. The cache loader is injected so the
collector is offline-testable with a fake. No network, no target interaction.
"""

from __future__ import annotations

from skuggi.intel.collectors.base import (
    CollectContext,
    CollectTask,
    IntelItem,
    IntelResult,
    empty_result,
)
from skuggi.research.collectors.local import CacheLoader, default_msf_cache

_MAX = 30


class MetasploitCollector:
    """Local metasploit module metadata matching the subject (when installed)."""

    source: str = "metasploit"

    def __init__(self, *, load_cache: CacheLoader = default_msf_cache) -> None:
        """Inject the module-metadata cache loader (a fake in tests)."""
        self._load = load_cache

    def available(self, ctx: CollectContext) -> bool:  # noqa: ARG002 -- protocol shape
        """Only when the metasploit module-metadata cache is readable."""
        return self._load() is not None

    def collect(self, task: CollectTask, ctx: CollectContext) -> IntelResult:  # noqa: ARG002
        """Filter the cached module index by the subject."""
        cache = self._load()
        if not cache:
            return empty_result(task, "metasploit module cache unavailable")
        needle = task.subject.strip().lower()
        items = tuple(
            item
            for key, row in cache.items()
            if (item := _item(str(key), row, needle)) is not None
        )[:_MAX]
        return IntelResult(
            task_id=task.id,
            source="metasploit",
            subject=task.subject,
            items=items,
            note=f"{len(items)} metasploit modules",
        )


def _item(fullname: str, row: object, needle: str) -> IntelItem | None:
    if not isinstance(row, dict):
        return None
    name = str(row.get("name", ""))
    haystack = f"{fullname} {name}".lower()
    if needle and needle not in haystack:
        return None
    refs = row.get("references")
    cves = (
        ",".join(
            str(r[1])
            for r in refs
            if isinstance(r, list) and len(r) == 2 and r[0] == "CVE"  # noqa: PLR2004
        )
        if isinstance(refs, list)
        else ""
    )
    return IntelItem(
        kind="module",
        value=fullname,
        attributes={"name": name, "type": str(row.get("type", "")), "cves": cves},
    )
