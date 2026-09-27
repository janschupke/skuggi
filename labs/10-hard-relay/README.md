# 10 · Relay — hard

A bespoke line-based TCP spool service (no scanner signature) + an HTTP management console.
Fingerprint the protocol, recover service creds from a leaked client, exploit a `FETCH` path
traversal to read the console's admin password, then log in for the custody vault. Read
[briefing.md](briefing.md); [solution.md](solution.md) is the key.

> ⚠️ Intentionally insecure. Loopback-only (relay 8210, console 8110). Never expose it.

```sh
make lab-up     LAB=10-hard-relay
make lab-verify LAB=10-hard-relay
uv run python labs/labctl scope 10-hard-relay --install
make lab-restore LAB=10-hard-relay
make lab-wipe    LAB=10-hard-relay
```
