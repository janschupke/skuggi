# Engagement brief — LumenPay merchant platform

**Tier:** medium · **Set:** webapp · **Target:** `app.lumenpay.lab` (`10.20.6.20`) · **Scope net:** `10.20.6.0/24`

> **On macOS** reach it at the loopback-published port `127.0.0.1:8506` — Docker Desktop
> doesn't route container IPs; the IP above is the Linux/direct-routing view.

## Scenario

LumenPay is a billing SaaS: merchants sign up to accept recurring subscription payments, and
LumenPay handles the cards and payouts. New merchants go through a short self-service
onboarding where they submit business details and upload verification documents. The platform
runs on a modern PHP framework. LumenPay's security team has asked for a pre-launch
penetration test of the public merchant-facing web tier before they open onboarding to the
public.

## Rules of engagement

- In scope: `10.20.6.0/24` — the web app (`app.lumenpay.lab`) and its database host.
- The app is published to `127.0.0.1:8506` for your convenience.
- Gaining code execution on the application server **is** in scope — that is the client's
  stated worry. If you land a shell, enumerate local privilege escalation and prove what an
  attacker could reach. No destructive writes to customer data, and no DoS.

## Objective

The client's real worry is **server compromise through the merchant-facing app** and what an
attacker reaches afterwards. Produce findings that recover, with evidence:

- a path to **execute code on the application server** from the public web tier,
- a stable **remote shell** proving that execution,
- any **local privilege escalation** available once you have a foothold, and
- the **secrets and credential material** the app and its host leak (framework config,
  database credentials, payment-gateway signing keys).

The interesting entry point is **not** on a stock wordlist — read the application the way a
merchant would and let it tell you where things go.
