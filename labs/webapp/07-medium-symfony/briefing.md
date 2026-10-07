# Engagement brief — CiviDoc document portal

**Tier:** medium · **Set:** webapp · **Target:** `app.cividoc.lab` (`10.20.7.20`) · **Scope net:** `10.20.7.0/24`

> **On macOS** reach it at the loopback-published port `127.0.0.1:8507` — Docker Desktop
> doesn't route container IPs; the IP above is the Linux/direct-routing view.

## Scenario

CiviDoc is a multi-tenant document-management SaaS: professional-services firms keep their
contracts, invoices and documents in one place, isolated per account ("tenant"). It is a
Symfony application backed by PostgreSQL. Several tenants share one instance, so the whole
product rests on one promise — **one tenant can never see another tenant's data**.

A prospective enterprise customer (Nordvik Maritime) is about to migrate its books onto
CiviDoc and has commissioned a focused penetration test of the portal first.

## Rules of engagement

- In scope: `10.20.7.0/24` — the web app (`app.cividoc.lab`) and its database host
  (`db.cividoc.lab`).
- The app is published to `127.0.0.1:8507` for your convenience.
- No destructive writes or DoS. Reading, enumerating and proving access are in scope.

## Objective

The client's real worry is **tenant isolation and data exposure**. Produce findings that
recover, with evidence:

- a path to **authenticate without valid credentials** (ideally as the platform admin),
- any way to **read one tenant's invoices or documents while acting as another** (a broken
  access-control / IDOR finding),
- any **file off the host the application should never hand out**, and any **credential or
  secret** such a leak exposes — and whether it is reusable.

The endpoints are not guessable from a stock wordlist. Read what the app itself tells you:
the landing page advertises its own API and download routes. More than one route reaches the
same tenant data — a strong report notes the alternates.
