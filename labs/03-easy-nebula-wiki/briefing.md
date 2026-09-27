# Engagement brief — Nebula internal wiki

**Tier:** easy · **Target:** `wiki.nebula.lab` (`203.0.113.20`) · **Scope net:** `203.0.113.0/24`

## Scenario

Nebula Robotics runs a small internal wiki for runbooks and HR notes. It was stood up on a
flat subnet alongside its cache and database and was never meant to be internet-facing, but
IT wants to know what an attacker who reaches that subnet could do. You are authorized to
assess everything on `203.0.113.0/24`.

## Rules of engagement

- In scope: the wiki, and the other services sharing its subnet.
- Published to loopback for convenience: web `8103`, redis `8203`, postgres `8303`.
- No destructive writes or DoS. Reading, enumerating and proving access are in scope.

## Objective

Show what sensitive data an attacker on this subnet can reach. Produce findings that
recover, with evidence:

- **employee/HR data** (the client is nervous about salary and PII exposure),
- any **credentials, keys or secrets** stored where they should not be,
- a path to **code execution or privileged access** on the wiki host.

Several independent weaknesses lead here — enumerate the whole subnet, not just the website.
