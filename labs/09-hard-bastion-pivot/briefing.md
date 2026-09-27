# Engagement brief — Bastion Trust portal

**Tier:** hard · **Target:** `portal.bastion.lab` (`172.30.9.20`) · **Scope nets:** `172.30.9.0/24` (DMZ), `10.9.0.0/24` (internal)

## Scenario

Bastion Trust exposes a single customer portal in a DMZ. Behind it, on a separate internal
segment, sits back-office tooling the portal talks to. The client wants to know whether a
compromise of the DMZ portal leads to the internal systems and the ledger data they hold.

## Rules of engagement

- In scope: the DMZ portal (`127.0.0.1:8109`) and the internal segment behind it. The
  internal hosts are **not** directly reachable — reaching them requires the DMZ foothold.
- Achieving code execution and pivoting is authorized. No destructive changes; no DoS.

## Objective

Establish a foothold on the DMZ, then pivot to the internal tier and prove access to the
crown jewels. Recover, with evidence:

- **code execution** on the DMZ host,
- what that foothold reveals about the **internal network**,
- the **internal ledger / financial records** (accounts, IBANs, balances).

The portal's "remember me" mechanism is the way in — look at how it restores your session.
