# Engagement brief — VaultLine capstone (edge portal → internal vault)

**Tier:** medium · **Set:** webapp · **Edge target:** `edge.vaultline.lab` (`10.20.12.20`) ·
**Goal host:** `vault.vaultline.lab` (`10.21.12.30`, internal) · **Scope nets:**
`10.20.12.0/24`, `10.21.12.0/24`

> **On macOS** reach the services at their loopback-published ports — Docker Desktop doesn't
> route container IPs, so the `10.20/10.21` addresses above are the Linux/direct-routing view.
> The edge web portal is at `http://127.0.0.1:8512`; the goal host's SSH is published at
> `127.0.0.1:8712` for your convenience and to verify the credential-reuse pivot. The two hosts
> still reach each other only over the internal `10.21.12.0/24` segment.

## Scenario

VaultLine Inc. runs an internal **Deployment Asset Portal** — a small web app their release
engineers use to upload and preview artifacts (logos, banners, screenshots) for a delivery
dashboard. The portal sits at the edge of VaultLine's network; behind it, on a segmented
internal network, lives `vault.vaultline.lab`, the host that actually stores release secrets.
VaultLine has asked for a full-chain assessment: not just "is the web app exploitable?" but
"**if the edge falls, how far does an attacker get?**"

This is the set's **capstone**. Earlier labs each isolate one framework and one or two vectors;
here you chain them — a web **foothold** into **lateral movement** and **privilege escalation**,
ending at the crown jewels.

## Rules of engagement

- In scope: `10.20.12.0/24` (edge) and `10.21.12.0/24` (internal). Both VaultLine hosts.
- The edge app is published to `127.0.0.1:8512`; the goal host's SSH to `127.0.0.1:8712`.
- Proving access — reading files, landing a shell, demonstrating the pivot and the privesc — is
  in scope. No destructive writes or DoS.

## Objective

Demonstrate the complete kill chain, with evidence at each hop:

- a **foothold** on the edge portal (code execution, not just a finding),
- any **credential material** the edge host leaks and whether it is **reused** elsewhere,
- **lateral movement** onto the internal goal host using that material, and
- **privilege escalation** to root and recovery of the **crown-jewel** secrets it protects.

A strong report shows each link actually works — the upload that executes, the exact secret
recovered, the reused credential authenticating over SSH, and the root file it unlocks.
