# 05 · Ledgerline API — medium

A Go retail-payments gateway with **logic flaws only** (no injection): mass-assignment role
elevation, admin routes named only in a leaked OpenAPI doc at a non-obvious path, and a
TOCTOU double-spend on `/v1/transfer`. Read [briefing.md](briefing.md); [solution.md](solution.md) is the key.

> ⚠️ Intentionally insecure. Loopback-only (`127.0.0.1:8105`). Never expose it.

```sh
make lab-up     LAB=05-medium-ledgerline-api
make lab-verify LAB=05-medium-ledgerline-api
uv run python labs/labctl scope 05-medium-ledgerline-api --install
make lab-restore LAB=05-medium-ledgerline-api
make lab-wipe    LAB=05-medium-ledgerline-api
```
