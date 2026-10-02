# Testing

Layers (all under `tests/`): `unit`, `integration`, `harness` are offline and
run in the gate; `eval` (real providers) and `e2e` (docker lab) are opt-in. Full
map: [docs/testing.md](../../docs/testing.md).

## Rules

- **Isolation is non-negotiable, and the suite cannot self-report a leak.** The
  `conftest` fixture redirects `SKUGGI_CONFIG_HOME`/`SKUGGI_DATA_HOME` (and
  chdirs, because `engagements_dir` is cwd-relative). Get it wrong and tests
  read real credentials with everything green. Proof is an unchanged
  `ls ~/.config/skuggi ~/.local/share/skuggi` after a run — see [storage.md](storage.md).
- **Never automate the harness against the operator's real homes or a live
  engagement.** Use tmp homes and the frozen `e2e` fixture target, never a real
  host or profile.
- **The blanket blocks are opt-in to lift.** Network is blocked unless a test is
  marked `mock_http`; subprocess spawning unless marked `runs_commands`. Reach
  for the marker, don't disable the block.
- **A new branch needs a test** (90% branch floor). Interactive plumbing that
  needs a real tty/socket is `# pragma: no cover`; its pure core is tested.
- `pytest-timeout` guards the two tests that would hang rather than fail if a cap
  regressed — keep caps testable.
