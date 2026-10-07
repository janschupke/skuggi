# Engagement brief — QuickDesk helpdesk portal

**Tier:** easy · **Set:** webapp · **Target:** `app.quickdesk.lab` (`10.20.1.20`) · **Scope net:** `10.20.1.0/24`

> **On macOS** reach it at the loopback-published port `127.0.0.1:8501` — Docker Desktop
> doesn't route container IPs; the IP above is the Linux/direct-routing view.

## Scenario

QuickDesk is a small SaaS that resells a hosted customer-helpdesk portal. Their agents sign
in to a web app to manage a shared customer book (billing contacts and card metadata). A
prospective enterprise customer's security team has asked for a light penetration test of the
portal before they migrate their account data onto it.

## Rules of engagement

- In scope: `10.20.1.0/24` — the web app (`app.quickdesk.lab`) and its database host.
- The app is published to `127.0.0.1:8501` for your convenience.
- No destructive writes or DoS. Reading, enumerating and proving access are in scope.

## Objective

The client's real worry is **account takeover and customer-data exposure**. Produce findings
that recover, with evidence:

- a path to **authenticate without valid credentials** (ideally as an administrator),
- any **customer PII / billing data** an attacker could exfiltrate,
- any **credential material** the application or its hosting leaks, and whether it is
  **reusable** (crackable offline, valid elsewhere).

More than one route reaches the same data — a strong report notes the alternates.
