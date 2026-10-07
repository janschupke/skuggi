# Engagement brief — Brightwave Media blog

**Tier:** easy · **Set:** webapp · **Target:** `app.brightwave.lab` (`10.20.2.20`) · **Scope net:** `10.20.2.0/24`

> **On macOS** reach it at the loopback-published port `127.0.0.1:8502` — Docker Desktop
> doesn't route container IPs; the IP above is the Linux/direct-routing view.

## Scenario

Brightwave Media is a small content studio that just stood up a self-hosted **WordPress**
site as their company blog. It is running on a stock WordPress 6 / MariaDB stack. Marketing
set up the admin account in a hurry before a launch, and the studio has asked for a quick
pre-launch penetration test of the site and its host before they start publishing client work
and collecting newsletter sign-ups.

## Rules of engagement

- In scope: `10.20.2.0/24` — the WordPress app (`app.brightwave.lab`) and its database host.
- The site is published to `127.0.0.1:8502` for your convenience.
- No destructive writes or DoS. Enumerating, logging in, proving code execution and reading
  data are all in scope; leave the content intact.

## Objective

The studio's real worry is **someone taking over the site and reaching the server behind
it**. Produce findings that recover, with evidence:

- a path to **authenticate as an administrator** (their password hygiene is the concern),
- whether an authenticated admin can reach **code execution on the host**,
- any **credential material** the application or its database leaks, and whether it is
  **reusable** (crackable offline, valid for the login).

More than one route reaches the same place — a strong report notes the alternates (a wordlist
login and an offline hash crack both land you the admin password).
