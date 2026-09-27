# Solution — 04 Helix Admin (easy)

> Spoilers — instructor's answer key.

## Surface

Spring Boot on `:8104` with the **entire actuator web-exposed** and `env`/`configprops`
set to `show-values=ALWAYS`. Postgres on `:8304`.

## Intended chain (two steps)

1. **Actuator enumeration** — `/actuator` lists endpoints. `GET /actuator/env` (or
   `/actuator/configprops`) shows **unmasked** values, leaking
   `spring.datasource.password=H3lix-DB-Prod-2024` and
   `app.oauth.client-secret=helix-oauth-9f2c1b-secret`. (`/actuator/heapdump` is an
   alternate: download it and `strings` the secrets out.)
2. **Use the leaked DB creds** — `psql -h 127.0.0.1 -p 8304 -U helix helix` with the leaked
   password dumps the `employees` table (names, emails, **salaries** incl. an exec at 210k).

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `oauth-client-secret` | `helix-oauth-9f2c1b-secret` | `/actuator/env` |
| `db-password` | `H3lix-DB-Prod-2024` | `/actuator/env` |
| `employee-salaries` | `s.marchetti@helix.example` (210k), … | Postgres `employees` via leaked creds |

## Reset

`make lab-restore LAB=04-easy-helix-actuator` (recreate — drops the Postgres volume, re-seeds).
