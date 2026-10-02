# Engagement brief — Cirrus document portal

**Tier:** hard · **Target:** `portal.cirrus.lab` (`172.30.8.30`) · **Scope nets:** `172.30.8.0/24`, `169.254.169.0/24`

> **On macOS** reach it at the loopback-published ports `127.0.0.1:8108` (app), `:8308`
> (LocalStack) — Docker Desktop doesn't route container IPs; the IPs above are the
> Linux/direct-routing view.

## Scenario

Cirrus runs a customer document portal on a cloud instance with an attached role. The
platform team uses managed cloud services (object storage, a secrets vault). They want to
know whether a flaw in the portal could expose that cloud footprint. Everything is a local,
offline cloud emulation — no real provider is in scope or contacted.

## Rules of engagement

- In scope: the portal (`127.0.0.1:8108`), the cloud API endpoint (`127.0.0.1:8308`), and
  the instance metadata service on the instance's link-local range.
- Use of any credentials you recover against the in-scope cloud endpoint is authorized.
- No destructive changes (no deleting buckets/secrets). Reading and proving access are in scope.

## Objective

Determine whether the portal can be pivoted into the cloud account, and how far. Recover,
with evidence:

- the **instance role credentials**,
- the **customer contracts / data** in object storage,
- any **secret** (e.g. database credentials) in the secrets vault.

The portal ships a profile feature that fetches a URL server-side — think about what that
lets you reach from the instance itself.
