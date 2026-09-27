# Engagement brief — Bazaar marketplace

**Tier:** medium · **Target:** `shop.bazaar.lab` (`172.30.7.20`) · **Scope nets:** `172.30.7.0/24` (edge), `10.7.0.0/24` (internal)

## Scenario

Bazaar is an online marketplace. Only the storefront API is internet-facing; its order
system and internal services sit on a separate, non-routable network. The client wants to
know whether the edge can be used to reach that internal tier and the customer data it holds.

## Rules of engagement

- In scope: the edge API (`shop.bazaar.lab`, published to `127.0.0.1:8107`) and the internal
  segment behind it. The internal hosts are **not** directly reachable — that is the point.
- No destructive writes or DoS. Reading and proving reach are in scope.

## Objective

Prove whether the edge can be turned into a doorway to the internal tier. Recover, with
evidence:

- a **server-side request** primitive on the edge,
- any **internal service credentials/tokens** it exposes,
- the **customer orders / PII** held by the internal order service.

The storefront doesn't advertise the internal endpoints in its UI — but the code it ships
to the browser does.
