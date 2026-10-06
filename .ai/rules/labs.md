# The practice range

`labs/` is a self-contained range of deliberately-vulnerable targets plus a
controller. Docs: [docs/labs.md](../../docs/labs.md), [docs/e2e-fixture.md](../../docs/e2e-fixture.md).

## Rules

- **Targets are loopback-only and driven through `labctl`** (`make lab-up`,
  `lab-down`, `lab-restore`, `lab-wipe`, `lab-verify` — `LAB=<id>`). Never bind a
  lab to a routable interface, and never point the harness at anything that is
  not a lab you brought up.
- **`labctl` / `labs/_lib` is real tooling** — typed (`mypy_path`) and linted.
  The numbered `labs/*-*/` build contexts are intentionally-insecure app code
  (PHP/JS/Go/Python) and are **excluded** from ruff and mypy on purpose; do not
  "fix" their vulnerabilities or lint them.
- `labctl` is standalone dev tooling, **not** a skuggi console script — it must
  never ship in the wheel.
- `lab-wipe` nukes the target **and** `./engagements/<lab>`; `lab-restore`
  reverts only the target and keeps your engagement work. Know which you want.
