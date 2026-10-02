# /plan

## Overview
Produce an implementation plan for a feature or change before writing code.

## Steps
1. Read the relevant [`.ai/rules/`](../rules/) and the code paths involved.
2. Identify the package each change lands in (see [architecture.md](../rules/architecture.md))
   and whether it crosses a package boundary or moves a module (a module move is
   a repo-wide sweep: entry points, `per-file-ignores`, doc links).
3. Name the existing utilities to reuse (`common/`, the verb registry, the
   structured protocol) before proposing new code.
4. Call out the gate impact: new branches to cover, new tests, any `eval`/`e2e`
   surface.

## Output
A concise plan: context, the change per file, utilities reused, and how to
verify end-to-end (`make check`, the isolation proof, `make eval-det`).
