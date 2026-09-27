# Engagement brief — TaskFlow SaaS API

**Tier:** easy · **Target:** `app.taskflow.lab` (`198.51.100.20`) · **Scope net:** `198.51.100.0/24`

## Scenario

TaskFlow is an early-stage SaaS that sells team task-tracking. They handle real customer
records and billing metadata and are chasing their first enterprise deal, whose security
team requires a light penetration test of the API before signing. You are authorized to
test the API host and the network it sits on (a MongoDB instance shares that network).

## Rules of engagement

- In scope: `198.51.100.0/24` — the API (`app.taskflow.lab`) and the database host.
- The API is published to `127.0.0.1:8102` for your convenience.
- No destructive writes or DoS. Reading, enumerating and proving access are in scope.

## Objective

The client's real worry is **data exposure and account takeover**. Produce findings that
recover, with evidence:

- a path to **authenticate as another user** (ideally an administrator),
- any **customer PII / billing data** an attacker could exfiltrate,
- any **live credentials or keys** the application leaks.

More than one route reaches the same data — a strong report notes the alternates.
