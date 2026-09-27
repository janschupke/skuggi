# Solution — 02 TaskFlow (easy)

> Spoilers — instructor's answer key.

## Surface

`GET /` describes the API. `GET /health` is the healthcheck. `POST /api/login`,
`GET /api/tasks`, `GET /api/tasks/:id`. A static web root also serves a leftover
`/.env.bak`. Mongo (`db.taskflow.lab`) is on the network with no auth.

## Intended chain (two short steps; an alternate exists)

1. **NoSQL injection auth bypass** — `POST /api/login` builds the query object straight
   from the JSON body:
   ```sh
   curl -s http://127.0.0.1:8102/api/login -H 'content-type: application/json' \
     -d '{"username":"admin","password":{"$ne":null}}'
   ```
   returns an **admin** JWT.
2. **IDOR** — with that token, walk `GET /api/tasks/:id`. There is no ownership check, so
   task `7` (admin's) is readable and contains a **live cloud backup key**
   (`AKIAZ7QEXAMPLE9TASKF / …`).

**Alternate / supporting:**
- `GET /.env.bak` leaks `JWT_SECRET=taskflow-prod-signing-2024`. With it you can **forge**
  an admin token directly (no NoSQLi needed) and reach the same IDOR.
- The **customer PII** (`db.customers`: names, emails, card last-4, MRR) is directly
  reachable to anyone who reaches Mongo on the network, and is the reportable data-exposure.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `jwt-secret` | `taskflow-prod-signing-2024` | `GET /.env.bak` |
| `cloud-backup-key` | `AKIAZ7QEXAMPLE9TASKF / …` | task id 7 via IDOR (or Mongo `tasks`) |
| `customer-pii` | `p.raman@meridian-freight.example`, … | Mongo `customers` |

Users: `admin:S3cur3-Adm1n-Pw`, `jdoe:hunter2`, `mchen:spring2024` (login is bypassable
regardless).

## Reset

`make lab-restore LAB=02-easy-taskflow` (recreate — drops the Mongo volume and re-seeds).
