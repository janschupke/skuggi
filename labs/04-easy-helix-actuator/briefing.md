# Engagement brief — Helix Admin portal

**Tier:** easy · **Target:** `portal.helix.lab` (`10.13.4.20`) · **Scope net:** `10.13.4.0/24`

## Scenario

Helix Dynamics exposes an internal admin portal (a Spring Boot service). Ops recently
turned on some monitoring endpoints "to debug a production issue" and never turned them off.
You are authorized to assess the portal and its subnet (a database shares it).

## Rules of engagement

- In scope: `10.13.4.0/24` — the portal (`portal.helix.lab`) and the database host.
- Published to loopback: portal `8104`, postgres `8304`.
- No destructive writes or DoS. Reading, enumerating and proving access are in scope.

## Objective

Determine what those monitoring endpoints expose and how far it goes. Recover, with
evidence:

- any **application secrets / credentials** the service discloses,
- the **employee/HR data** the client is worried about (salaries), by using what you find.
