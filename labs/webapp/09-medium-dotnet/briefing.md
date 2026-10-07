# Engagement brief — NetLedger accounting API

**Tier:** medium · **Set:** webapp · **Target:** `app.netledger.lab` (`10.20.9.20`) · **Scope net:** `10.20.9.0/24`

> **On macOS** reach it at the loopback-published port `127.0.0.1:8509` — Docker Desktop
> doesn't route container IPs; the IP above is the Linux/direct-routing view.

## Scenario

NetLedger is a bookkeeping firm that runs a small in-house accounting API: their accountants
sign in to search a customer ledger (billing contacts, card metadata, balances) and pull
quarterly statements. They have rebuilt it on ASP.NET Core and want a penetration test before
they migrate client books onto the new stack. You are authorized to test the API host and the
network it sits on (a Postgres instance shares that network).

## Rules of engagement

- In scope: `10.20.9.0/24` — the API (`app.netledger.lab`) and its database host.
- The API is published to `127.0.0.1:8509` for your convenience.
- No destructive writes or DoS. Reading, enumerating, proving access and demonstrating code
  execution (a benign callback) are in scope.

## Objective

The client's real worry is **account takeover, data exposure, and whether the box itself can
be taken over**. Produce findings that recover, with evidence:

- a path to **authenticate without valid credentials** (ideally as an administrator),
- any **customer PII / billing data** an attacker could exfiltrate,
- any **secrets or credential material** the application or its hosting leaks, and what those
  secrets unlock, and
- whether any of it chains into **code execution** on the application host.

The strongest routes here **chain**: one finding leaks the key that unlocks the next. A strong
report shows the chain end-to-end and notes the alternates.
