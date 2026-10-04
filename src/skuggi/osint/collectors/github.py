"""GitHub public-repository collector (passive, keyless by default).

Lists an organization's (or user's) public repositories via the GitHub REST API --
names, languages, descriptions, stars -- the public side of an org's footprint and
tech stack. Unauthenticated by default (rate-limited); a token in the source config
raises the limit. Best-effort: any failure yields an empty result.
"""

from __future__ import annotations

import json

from skuggi.engagement.scope import OsintSource
from skuggi.osint.collectors.base import CollectContext, HttpRequest, empty_result
from skuggi.osint.schema import OsintItem, OsintResult, OsintTask

_API = "https://api.github.com"


class GitHubCollector:
    """Public repositories (and their languages) for an org or user."""

    source: OsintSource = "github"

    def available(self, ctx: CollectContext) -> bool:  # noqa: ARG002 -- protocol shape
        """Always available: the public API works unauthenticated."""
        return True

    def collect(self, task: OsintTask, ctx: CollectContext) -> OsintResult:
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


def _parse(task: OsintTask, body: str) -> OsintResult:
    """Turn a GitHub repos JSON array into repo items."""
    try:
        repos = json.loads(body)
    except ValueError:
        return empty_result(task, "github response was not valid JSON")
    if not isinstance(repos, list):
        return empty_result(task, "github response was not a list")
    items = tuple(
        OsintItem(
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
    return OsintResult(
        task_id=task.id,
        source="github",
        subject=task.subject,
        items=items,
        note=f"{len(items)} public repositories",
    )
