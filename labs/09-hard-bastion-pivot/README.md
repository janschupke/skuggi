# 09 · Bastion Pivot — hard

A segmented network: a DMZ portal with insecure-deserialization (pickle) RCE is the **only**
route onto the internal segment. Pivot from the foothold to an unauthenticated internal admin
console holding the crown-jewels ledger. Read [briefing.md](briefing.md);
[solution.md](solution.md) is the key.

> ⚠️ Intentionally insecure. Loopback-only (`127.0.0.1:8109`); the internal tier is unpublished. Never expose it.

```sh
make lab-up     LAB=09-hard-bastion-pivot
make lab-verify LAB=09-hard-bastion-pivot
uv run python labs/labctl scope 09-hard-bastion-pivot --install
make lab-restore LAB=09-hard-bastion-pivot
make lab-wipe    LAB=09-hard-bastion-pivot
```
