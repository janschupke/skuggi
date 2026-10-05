"""searchsploit collector -- a local, offline Exploit-DB query (optional tool).

Lights up only when ``searchsploit`` is installed (the Kali/exploitdb package);
otherwise ``available`` is False and the planner's task degrades to a coverage
gap. ``collect`` runs ``searchsploit --json <subject>`` -- a read-only query of the
LOCAL Exploit-DB copy, no network and no target interaction -- and parses the JSON.
The subprocess call and the ``which`` probe are injected so the collector is
offline-testable with fakes.
"""

from __future__ import annotations

import json

from skuggi.intel.collectors.base import (
    CollectContext,
    CollectTask,
    IntelItem,
    IntelResult,
    empty_result,
)
from skuggi.research.collectors.local import (
    LocalRun,
    default_local_run,
    have,
    safe_subject,
)

_EXPLOIT = "https://www.exploit-db.com/exploits/"


class SearchsploitCollector:
    """Local Exploit-DB search via the ``searchsploit`` CLI (when installed)."""

    source: str = "searchsploit"

    def __init__(
        self,
        *,
        run: LocalRun = default_local_run,
        have_tool: bool | None = None,
    ) -> None:
        """Inject the subprocess runner and (for tests) the tool-presence flag."""
        self._run = run
        self._have = have("searchsploit") if have_tool is None else have_tool

    def available(self, ctx: CollectContext) -> bool:  # noqa: ARG002 -- protocol shape
        """Only when ``searchsploit`` is on the host PATH."""
        return self._have

    def collect(self, task: CollectTask, ctx: CollectContext) -> IntelResult:  # noqa: ARG002
        """Run a local ``searchsploit`` JSON query and parse the exploit list."""
        subject = safe_subject(task.subject)
        if subject is None:
            return empty_result(task, "subject rejected by the research input guard")
        body = self._run(["searchsploit", "--json", subject])
        if not body:
            return empty_result(task, "searchsploit returned no data")
        return _parse(task, body)


def _parse(task: CollectTask, body: str) -> IntelResult:
    try:
        data = json.loads(body)
    except ValueError:
        return empty_result(task, "searchsploit output was not valid JSON")
    rows = data.get("RESULTS_EXPLOIT") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return empty_result(task, "searchsploit output had no exploits")
    items = tuple(item for row in rows if (item := _item(row)) is not None)
    return IntelResult(
        task_id=task.id,
        source="searchsploit",
        subject=task.subject,
        items=items,
        note=f"{len(items)} local Exploit-DB entries",
    )


def _item(row: object) -> IntelItem | None:
    if not isinstance(row, dict):
        return None
    edb_id = str(row.get("EDB-ID", ""))
    title = str(row.get("Title", ""))
    if not edb_id and not title:
        return None
    return IntelItem(
        kind="exploit",
        value=f"EDB-{edb_id}" if edb_id else title,
        attributes={
            "title": title,
            "path": str(row.get("Path", "")),
            "url": f"{_EXPLOIT}{edb_id}" if edb_id else "",
        },
    )
