# Engagement brief — CivicGov municipal portal

**Tier:** medium · **Set:** webapp · **Target:** `app.civicgov.lab` (`10.20.10.20`) · **Scope net:** `10.20.10.0/24`

> **On macOS** reach it at the loopback-published port `127.0.0.1:8510` — Docker Desktop
> doesn't route container IPs; the IP above is the Linux/direct-routing view.

## Scenario

CivicGov is the public-facing portal a mid-sized municipality runs on Drupal 10 to manage
citizen benefit records. The site is mostly stock Drupal, but the council's IT contractor
shipped a small in-house module — "CivicGov Tools" — to give caseworkers quick record
lookups and a maintenance helper. The council's data-protection officer has commissioned a
penetration test ahead of a public-records audit: they are worried the bespoke code was never
security-reviewed.

## Rules of engagement

- In scope: `10.20.10.0/24` — the Drupal app (`app.civicgov.lab`) and its database host.
- The portal is published to `127.0.0.1:8510` for your convenience.
- No destructive writes or DoS. Reading, enumerating and proving access are in scope;
  demonstrating code execution against the custom module is explicitly authorised.

## Objective

The client's real worry is **citizen-data exposure** and **whether the custom module gives an
attacker a foothold**. Produce findings that recover, with evidence:

- any route that lets an **unauthenticated** attacker read **citizen PII / benefit records**,
- whether that same custom code yields **command execution** on the web host, and
- how far that foothold escalates — **can you reach root**, and what crown-jewel material sits
  behind it.

Stock Drupal core is in scope but is not the interesting surface here. The bespoke module is.
A strong report separates the data-exposure finding from the code-execution finding and notes
that the PII is reachable by more than one route.
