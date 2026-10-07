# Engagement brief — SwiftCart order portal

**Tier:** easy · **Set:** webapp · **Target:** `app.swiftcart.lab` (`10.20.4.20`) · **Scope net:** `10.20.4.0/24`

> **On macOS** reach it at the loopback-published port `127.0.0.1:8504` — Docker Desktop
> doesn't route container IPs; the IP above is the Linux/direct-routing view.

## Scenario

SwiftCart is a small e-commerce shop that runs a Node/Express customer order portal: a
product catalogue, customer reviews, per-customer invoices and receipt downloads. They are
onboarding a payments partner whose security team requires a light penetration test of the
portal before the integration goes live.

## Rules of engagement

- In scope: `10.20.4.0/24` — the web app (`app.swiftcart.lab`). It is the only host.
- The app is published to `127.0.0.1:8504` for your convenience.
- No destructive writes or DoS. Reading, enumerating and proving access are in scope.

## Objective

The client's real worry is **customer-data exposure and key leakage**. Produce findings
that recover, with evidence:

- any **customer PII / billing data** an attacker could read without authorization,
- any **server-side files or credential material** the application leaks, and
- any path for an attacker to **persist content that runs in another user's browser**.

More than one route reaches customer data — a strong report notes the alternates.
