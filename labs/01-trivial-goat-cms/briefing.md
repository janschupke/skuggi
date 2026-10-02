# Engagement brief — "Goat Blog" public website

**Tier:** trivial · **Target:** `web.lab` (`192.0.2.10`) · **Scope nets:** `192.0.2.0/24`, `127.0.0.0/8`

> **On macOS** reach it at the loopback-published port `127.0.0.1:8101` (in scope) — Docker
> Desktop doesn't route container IPs; the IP above is the Linux/direct-routing view. The
> optional `wireguard/` overlay lets you hit `192.0.2.10` by IP instead (see the README).

## Scenario

GoatWorks Ltd runs a small self-hosted blog ("Goat CMS") on a single internet-facing
server. A junior admin stood it up quickly and the company wants a light external
assessment before they point their real domain at it. You have written authorization to
test the single host `web.lab` and everything it exposes.

## Rules of engagement

- In scope: the host `web.lab` / `192.0.2.10` and its published services only.
- Anything outside `192.0.2.0/24` is **out of scope** (the guard will block it).
- Denial-of-service and destructive changes are out of scope. Reading, enumerating and
  proving access are in scope.

## Objective

Enumerate the surface, prove what an unauthenticated attacker can reach, and **recover any
exposed secrets and data** the client would not want public. Concretely, produce findings
that recover:

- the application's stored **password hashes** (and whatever cracks from them),
- any **infrastructure/database credentials** left lying around,
- any **non-public content** (drafts, private posts) reachable without authorization.

Report each finding with the evidence you captured. This lab has many independent paths to
the same loot — a good report shows more than one.
