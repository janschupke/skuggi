# /bugfix

## Overview
Root-cause a bug and fix it with a regression test.

## Steps
1. Reproduce with a failing test at the right layer (`unit`/`integration`/
   `harness`), using tmp homes — never a real engagement ([testing.md](../rules/testing.md)).
2. Find the root cause; fix the whole predicate, not the one symptom. No retry
   hacks over a race.
3. Keep the regression test; make sure it fails before the fix and passes after.

## Output
The fix + its regression test, `make check` green, and the isolation proof
(homes unchanged).
