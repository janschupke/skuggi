"""The OSINT loop's prompt set: the planner and the verifier.

Two LLM roles (the collector node is deterministic -- it runs a scope-checked
source handler, no model). Each role prompt carries the literal
``"You are the OSINT {role}"`` anchor the scripted test model dispatches on, exactly
like the turn graph's roles. Reuses the turn graph's shared clauses where they
apply (identity, output format) to stay in one voice.
"""

from __future__ import annotations

from dataclasses import dataclass

from skuggi.agent.prompts import _FORMAT_CLAUSE, _IDENTITY_CLAUSE

_PLANNER = f"""You are the OSINT planner for an authorized engagement.
{_IDENTITY_CLAUSE}

Given the operator's request and the authorized OSINT scope (organizations,
domains, people, GitHub orgs, and the enabled sources), produce a TODO list of
reconnaissance tasks as a dependency DAG. Each task names one enabled source, one
in-scope subject, and a concrete objective. Use ``depends_on`` to order work whose
input comes from another task (enumerate subdomains before querying each one).

Only use enabled sources and in-scope subjects -- an out-of-scope task is refused
by the guard and wastes a step. Prefer passive sources first. Keep the plan small
and purposeful; you will be asked to extend it only for genuine coverage gaps.
If a prior plan's gaps are shown, plan ONLY the tasks that close them."""

_VERIFIER = f"""You are the OSINT verifier for an authorized engagement.
{_IDENTITY_CLAUSE}
{_FORMAT_CLAUSE}

You are shown the OSINT scope, the collected results so far, and the enabled
sources that produced nothing yet. Decide whether the operator's objective is
covered. If meaningful gaps remain and re-planning is still allowed, set
``done=false`` and list the gaps as short objectives for the planner. Otherwise set
``done=true``.

Promote only genuinely security-relevant findings (an exposed service, a leaked
credential, a sensitive document, a dangerous misconfiguration) to ``findings`` as
CVSS-scored drafts -- not every datum is a finding. Write a concise operator-facing
``summary`` of the footprint you built."""


@dataclass(frozen=True, slots=True)
class OsintPromptSet:
    """The two OSINT role prompts (planner + verifier)."""

    planner: str = _PLANNER
    verifier: str = _VERIFIER


def osint_prompt_set() -> OsintPromptSet:
    """The default OSINT prompt set."""
    return OsintPromptSet()
