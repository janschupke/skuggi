"""GitHub public-repository collector (passive, keyless by default, shared).

Lists an organization's (or user's) public repositories via the GitHub REST API --
names, languages, descriptions, stars -- the public side of a subject's footprint
and tech stack. Shared by both loops: OSINT uses it for an org's footprint,
research for a project's language/stack. Unauthenticated by default (rate-limited);
a token in the source config raises the limit. Best-effort: any failure yields an
empty result.
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

_API = "https://api.github.com"


class GitHubCollector:
    """Public repositories (and their languages) for an org or user."""

    source: str = "github"

    def available(self, ctx: CollectContext) -> bool:  # noqa: ARG002 -- protocol shape
        """Always available: the public API works unauthenticated."""
        return True

    def collect(self, task: CollectTask, ctx: CollectContext) -> IntelResult:
        """List the subject org's public repositories (falling back to a user)."""
        headers = {"Accept": "application/vnd.github+json"}
        token = ctx.config_for("github").get("token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = ctx.fetch(
            HttpRequest(f"{_API}/orgs/{task.subject}/repos", headers=headers)
        )
        if not body:
            body = ctx.fetch(
                HttpRequest(f"{_API}/users/{task.subject}/repos", headers=headers)
            )
        if not body:
            return empty_result(task, "no public repositories found")
        return _parse(task, body)


def _parse(task: CollectTask, body: str) -> IntelResult:
    """Turn a GitHub repos JSON array into repo items."""
    try:
        repos = json.loads(body)
    except ValueError:
        return empty_result(task, "github response was not valid JSON")
    if not isinstance(repos, list):
        return empty_result(task, "github response was not a list")
    items = tuple(
        IntelItem(
            kind="repo",
            value=str(r.get("full_name", "")),
            attributes={
                "language": str(r.get("language") or ""),
                "stars": str(r.get("stargazers_count", 0)),
                "description": str(r.get("description") or "")[:200],
            },
        )
        for r in repos
        if isinstance(r, dict) and r.get("full_name")
    )
    return IntelResult(
        task_id=task.id,
        source="github",
        subject=task.subject,
        items=items,
        note=f"{len(items)} public repositories",
    )
