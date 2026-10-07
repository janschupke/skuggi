# Engagement brief — Orionline deploy host

**Tier:** easy · **Set:** webapp · **Target:** `app.orionline.lab` (`10.20.3.20`) · **Scope net:** `10.20.3.0/24`

> **On macOS** reach it at the loopback-published port `127.0.0.1:8503` — Docker Desktop
> doesn't route container IPs; the IP above is the Linux/direct-routing view.

## Scenario

Orionline runs its internal Java web apps on a shared Apache Tomcat host that their small
platform team uses to push releases. During a migration the team stood the box up quickly and
left the admin tooling in place. They've asked for a light penetration test of the host before
it carries production traffic again — specifically, whether the deployment surface lets an
outsider reach code execution.

## Rules of engagement

- In scope: `10.20.3.0/24` — the Tomcat host `app.orionline.lab`.
- The server is published to `127.0.0.1:8503` for your convenience.
- Gaining a shell and demonstrating privilege escalation **are** in scope. No DoS; don't
  wreck the box — prove access and document it.

## Objective

The client's real worry is **remote code execution through the deployment tooling and what it
exposes on the host**. Produce findings that recover, with evidence:

- a path to **authenticate to the Tomcat management surface** without being handed credentials,
- **code execution** on the host through that surface (a deployed app / shell),
- any **privilege escalation** from the service account to root, and
- any **credential material** stored on the host that an attacker could reuse.

A small password list recovered from a Orionline laptop image ships alongside this brief
(`wordlist.txt`) — start there.
