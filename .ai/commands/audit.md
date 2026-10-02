# /audit

## Overview
Analysis-only pass over a slice of the codebase. Produces findings; changes
nothing.

## Steps
1. Scope the audit to a package or concern.
2. Check against the rules: import-graph layering and lazy imports
   ([architecture.md](../rules/architecture.md)), no import-time path resolution
   ([storage.md](../rules/storage.md)), structured-protocol discipline
   ([protocol.md](../rules/protocol.md)).
3. Flag dead code, duplication, drifted constants, oversized grab-bag modules,
   and misplacements — with file:line and a severity.

## Output
A ranked findings list (file:line, one-line description, severity). No edits.
