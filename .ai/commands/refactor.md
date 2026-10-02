# /refactor

## Overview
Restructure without changing behaviour. Audit first, then apply on approval.

## Steps
1. Audit the target (see [/audit](audit.md)); write down what moves where.
2. **Extract, don't re-patch.** Pull a cohesive, testable kernel into its own
   module; leave stateful glue where it belongs. Don't invert the layering
   (`common/` stays leaf-only).
3. Preserve lazy imports. If a module moves, sweep every reference: imports
   across `src`/`tests`/`labs/_lib`, entry points, `per-file-ignores`, doc links.
4. Keep each extraction independently green and commit it on its own.

## Output
The refactor applied, `make check` green at each step, behaviour unchanged
(same tests pass), homes untouched.
