# Engagement brief — TrackRails project tracker

**Tier:** medium · **Set:** webapp · **Target:** `app.trackrails.lab` (`10.20.8.20`) · **Scope nets:** `10.20.8.0/24`, `10.21.8.0/24`

> **On macOS** reach the web app at `127.0.0.1:8508` and the ops host's SSH at
> `127.0.0.1:8608` — Docker Desktop doesn't route container IPs, so the `10.20.8.*` /
> `10.21.8.*` addresses above are the Linux/direct-routing view. Use the loopback ports.

## Scenario

TrackRails is a small internal project-and-issue tracker a product team runs on Rails. It
sits on an application segment (`10.20.8.0/24`) with its database, and the app host also has
a leg onto an **internal ops segment** (`10.21.8.0/24`) where a release/deploy host lives. The
team has asked for a pre-audit of the tracker and, specifically, whether a foothold in the web
app lets an attacker move **laterally** onto the ops host.

## Rules of engagement

- In scope: `10.20.8.0/24` (app + database) and `10.21.8.0/24` (the internal ops host).
- The web app is published to `127.0.0.1:8508`. The ops host's SSH is published to
  `127.0.0.1:8608` for your convenience.
- Self-registration on the tracker is open — creating your own low-privilege account to get a
  foothold is in scope.
- No destructive writes or DoS. Reading, enumerating, escalating and proving access are in
  scope.

## Objective

**Lateral movement is the theme.** Produce findings, with evidence, that cover the whole
chain:

- a way to **escalate privilege inside the web app** from an ordinary account,
- any **credential material** the app or its configuration leaks, and whether it is
  **reusable** elsewhere on the network,
- a **foothold on the internal ops host** reached with that material, and
- any **local privilege escalation** to root there, plus the sensitive data it exposes.

A strong report connects each step to the next and names the single reused secret that ties
the web app to the ops host.
