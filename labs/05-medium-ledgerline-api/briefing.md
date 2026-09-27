# Engagement brief — Ledgerline payments API

**Tier:** medium · **Target:** `api.ledgerline.lab` (`10.13.5.20`) · **Scope net:** `10.13.5.0/24`

## Scenario

Ledgerline is a retail-payments startup. Their API backs a web console. They have already
had a basic scan (nothing obvious — no SQL injection, no default admin pages) and want a
deeper look at **business logic and access control** before an audit. You are authorized to
test the API host.

## Rules of engagement

- In scope: `api.ledgerline.lab` (`10.13.5.20`), published to `127.0.0.1:8105`.
- You may create test accounts and move test funds. No DoS.
- The interesting flaws are in *behaviour*, not in a scanner signature — read the app.

## Objective

Find a way to reach data and actions you should not, and prove it. Recover, with evidence:

- a route to **privileged (admin) access** without valid admin credentials,
- the **signed contracts** and any **signing key / secret** the platform holds,
- a **money-movement flaw** that lets an account spend more than its balance.

Default wordlists will not find the admin surface — the console tells you where it is.
