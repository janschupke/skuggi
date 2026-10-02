# Engagement brief — Northwind file server

**Tier:** medium · **Targets:** `files.northwind.lab` (`10.13.6.10`), `pivot.northwind.lab` (`10.13.6.20`) · **Scope net:** `10.13.6.0/24`

> **On macOS** reach the services at the loopback-published ports `127.0.0.1:8106` (SMB),
> `:8206` (SSH) — Docker Desktop doesn't route container IPs; the IPs above are the
> Linux/direct-routing view.

## Scenario

Northwind Trading runs a small Windows-style file server (Samba) and a Linux "backup/pivot"
box on the same segment. They want to know what an attacker with a foothold on this subnet —
but **no credentials** — can reach. There is no domain controller in scope; just these two
hosts.

## Rules of engagement

- In scope: `10.13.6.0/24` — the file server and the pivot host.
- Published to loopback: SMB `8106`, SSH `8206`.
- Cracking planted credential material is in scope. No DoS.

## Objective

Get from "no creds on the subnet" to the client's sensitive data and prove the path.
Recover, with evidence:

- whatever a **null/guest SMB session** exposes,
- any **credential store** and the secrets inside it,
- the **customer contracts** the client believes are safely tucked away on the backup host.

The credential you need is not in a stock wordlist — the files on the share tell you how to
build the right one.
