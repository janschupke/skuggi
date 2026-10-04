"""First-party web search collector with a pluggable backend (shared).

skuggi had no general web search (``tooling.websearch`` is PyPI-only), so this is
the harness's own: a ``SearchBackend`` dispatch over several providers, defaulting
to the no-API-key DuckDuckGo HTML endpoint. Brave / Google CSE / SearXNG are
selected via the source config (``source_config["websearch"]["backend"]``) and
need a key (``osint_search_api_key``) where the provider requires one.

Shared by both intelligence loops: it reads only ``task.subject``/``objective``
(the ``CollectTask`` view), so it serves OSINT org footprinting and research
tech-stack lookups alike. Each backend returns ``(title, url)`` hits parsed
best-effort; a missing key or a dead backend yields an empty result with a note,
never an exception.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping

from skuggi.intel.collectors.base import (
    CollectContext,
    CollectTask,
    HttpRequest,
    IntelItem,
    IntelResult,
    empty_result,
)

_DDG_URL = "https://html.duckduckgo.com/html/"
_BRAVE_URL = "https://api.search.brave.com/res/v1/web/search"
_GOOGLE_URL = "https://www.googleapis.com/customsearch/v1"
# DuckDuckGo HTML result anchors: <a class="result__a" href="URL">TITLE</a>.
_DDG_RESULT = re.compile(
    r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
    re.DOTALL,
)
_TAG = re.compile(r"<[^>]+>")
_MAX_RESULTS = 10


class WebSearchCollector:
    """Public web search over a pluggable backend (DuckDuckGo by default)."""

    source: str = "websearch"

    def available(self, ctx: CollectContext) -> bool:
        """DuckDuckGo/SearXNG need no key; Brave/Google need a search api key."""
        backend = self._backend(ctx.config_for("websearch"))
        if backend in ("brave", "google"):
            return bool(ctx.secrets.get("osint_search_api_key"))
        return True

    @staticmethod
    def _backend(cfg: Mapping[str, str]) -> str:
        return cfg.get("backend", "duckduckgo").lower()

    def collect(self, task: CollectTask, ctx: CollectContext) -> IntelResult:
        """Search for the subject + objective and return the top hits."""
        cfg = ctx.config_for("websearch")
        backend = self._backend(cfg)
        query = f'"{task.subject}" {task.objective}'.strip()
        key = ctx.secrets.get("osint_search_api_key", "")
        hits = _search(ctx, backend, query, cfg, key)
        if hits is None:
            return empty_result(task, f"websearch backend {backend!r} returned no data")
        items = tuple(
            IntelItem(kind="web", value=url, attributes={"title": title})
            for title, url in hits[:_MAX_RESULTS]
        )
        return IntelResult(
            task_id=task.id,
            source="websearch",
            subject=task.subject,
            items=items,
            note=f"{len(items)} web results via {backend}",
        )


def _search(
    ctx: CollectContext,
    backend: str,
    query: str,
    cfg: Mapping[str, str],
    key: str,
) -> list[tuple[str, str]] | None:
    """Dispatch to a backend; None means the fetch failed."""
    if backend == "brave":
        body = ctx.fetch(
            HttpRequest(
                _BRAVE_URL, params={"q": query}, headers={"X-Subscription-Token": key}
            )
        )
        return _parse_brave(body)
    if backend == "google":
        cx = cfg.get("cx", "")
        body = ctx.fetch(
            HttpRequest(_GOOGLE_URL, params={"q": query, "key": key, "cx": cx})
        )
        return _parse_google(body)
    if backend == "searxng":
        base = cfg.get("url", "")
        body = ctx.fetch(
            HttpRequest(f"{base}/search", params={"q": query, "format": "json"})
        )
        return _parse_searxng(body)
    # default: duckduckgo html
    body = ctx.fetch(HttpRequest(_DDG_URL, method="POST", data={"q": query}))
    return _parse_ddg(body)


def _parse_ddg(body: str | None) -> list[tuple[str, str]] | None:
    if body is None:
        return None
    hits = []
    for url, raw_title in _DDG_RESULT.findall(body):
        title = _TAG.sub("", raw_title).strip()
        hits.append((title, url))
    return hits


def _json_hits(body: str | None, extract: str) -> list[tuple[str, str]] | None:
    """Shared JSON-backend parse; ``extract`` names the brave/google/searxng path."""
    if body is None:
        return None
    try:
        data = json.loads(body)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    rows: object
    if extract == "brave":
        web = data.get("web")
        rows = web.get("results") if isinstance(web, dict) else None
    elif extract == "google":
        rows = data.get("items")
    else:  # searxng
        rows = data.get("results")
    if not isinstance(rows, list):
        return []
    return [
        (str(r.get("title", "")), str(r.get("url", r.get("link", ""))))
        for r in rows
        if isinstance(r, dict)
    ]


def _parse_brave(body: str | None) -> list[tuple[str, str]] | None:
    return _json_hits(body, "brave")


def _parse_google(body: str | None) -> list[tuple[str, str]] | None:
    return _json_hits(body, "google")


def _parse_searxng(body: str | None) -> list[tuple[str, str]] | None:
    return _json_hits(body, "searxng")
