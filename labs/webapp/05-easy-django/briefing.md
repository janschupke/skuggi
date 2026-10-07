# Engagement brief — FernData customer portal

**Tier:** easy · **Set:** webapp · **Target:** `app.ferndata.lab` (`10.20.5.20`) · **Scope net:** `10.20.5.0/24`

> **On macOS** reach it at the loopback-published port `127.0.0.1:8505` — Docker Desktop
> doesn't route container IPs; the IP above is the Linux/direct-routing view.

## Scenario

FernData is a SaaS that runs a hosted customer-billing portal for small businesses. Staff
sign in to manage a shared book of customer accounts — billing contacts, card metadata and
monthly revenue. The portal is a Django 5 application in front of Postgres. A prospective
enterprise customer's security team has asked for a light penetration test before they load
their own account data onto it.

## Rules of engagement

- In scope: `10.20.5.0/24` — the web app (`app.ferndata.lab`) and its database host
  (`db.ferndata.lab`).
- The app is published to `127.0.0.1:8505` for your convenience; the database is not
  published.
- No destructive writes or DoS. Reading, enumerating and proving access are in scope.

## Objective

The client's real worry is **customer-data exposure and account takeover**. Produce findings
that recover, with evidence:

- any **customer PII / billing data** an attacker could enumerate and exfiltrate, and whether
  a missing authorization check lets an unauthenticated visitor read records that are not
  theirs,
- any place the application renders **attacker-controlled content unsafely** (client-side
  code execution against a signed-in operator), and
- any **credential material** the application or its data store leaks, and whether it is
  **reusable** (crackable offline, valid at the sign-in).

The framework's defaults are mostly safe — look for where the developers stepped around them.
