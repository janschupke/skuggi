# Gates

**`make check` is the gate, and it is the whole gate.** Run it before calling
any task done. It is, in order (the same order as
[.github/workflows/ci.yml](../../.github/workflows/ci.yml)):

```
ruff format --check     # never `ruff format` in the gate — a rewrite can't fail
ruff check              # the lint rule set is large; read pyproject before silencing one
mypy                    # strict, + pydantic plugin; no bare `# type: ignore`
pytest                  # --cov-fail-under=90, branch coverage
```

- **`make format`** rewrites (ruff format + `ruff check --fix`); the gate only
  verifies. Fix a finding at its root, don't widen a `per-file-ignores` entry.
- **Coverage is branch-based and floored at 90%** (measured ~92%). A new branch
  needs a test; don't drop the floor.
- **The gate is offline and isolated.** It never talks to a provider and never
  touches the operator's real homes. `eval` (real providers) and `e2e` (docker
  lab) are opt-in — deselected by `-m "not eval and not e2e"` — and run via
  `make eval` / `make e2e`. The offline deterministic eval tier runs inside the
  gate (and standalone as `make eval-det`).
- A green gate is **not** proof of storage isolation — see [storage.md](storage.md).

More: [docs/testing.md](../../docs/testing.md).
