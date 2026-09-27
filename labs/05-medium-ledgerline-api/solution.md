# Solution — 05 Ledgerline API (medium)

> Spoilers — instructor's answer key. No SQLi/LFI here; the flaws are logic.

## Discovery (non-obvious)

`/` loads `/app.js`, which names `/v1/_internal/openapi.json`. That spec lists the
admin routes `/v1/ledger/contracts` and `/v1/ops/config` (marked `x-role: admin`) — you
will not find them with `common.txt`/`raft`.

## Intended vectors

1. **Mass assignment → admin.** `POST /v1/customers` copies the whole JSON body into the
   user record, including `role`:
   ```sh
   curl -s http://127.0.0.1:8105/v1/customers -H 'content-type: application/json' \
     -d '{"username":"mallory","password":"x","role":"admin"}'
   ```
   returns an **admin** JWT. With it:
   - `GET /v1/ledger/contracts` → the **signed contracts** (Meridian Freight Ltd, …).
   - `GET /v1/ops/config` → the **contract signing key** `ledgerline-hmac-7c1f9a2e`.
2. **TOCTOU double-spend.** `POST /v1/transfer` checks the balance, waits, then debits.
   Fire concurrent transfers from `acct-1001` (balance 500): several succeed, driving it
   negative / over-crediting `acct-treasury` — a provable money-movement flaw.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `contract-signing-key` | `ledgerline-hmac-7c1f9a2e` | admin `/v1/ops/config` (seed.json) |
| `signed-contract` | `Meridian Freight Ltd`, `Halcyon Capital Partners` | admin `/v1/ledger/contracts` |
| `openapi-leak` | `/v1/ops/config` named in the spec | `/v1/_internal/openapi.json` |

## Reset

`make lab-restore LAB=05-medium-ledgerline-api` (recreate — in-memory state is reloaded
from `data/seed.json` on restart).
