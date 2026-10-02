# The skuggi practice range

Ten independent engagement exercises on a difficulty ladder, under [`labs/`](../labs). Each
is a realistic-but-simplified scenario with real reportable surface and **planted loot** —
not a single-flag path. You drive them with skuggi exactly like a real engagement; you
manage them with `labctl` (via the `make lab-*` targets).

This range is separate from the frozen e2e fixture in `tests/e2e/fixtures/lab/`
([lab.md](lab.md)), which CI drives and which never changes as these labs evolve.

> ⚠️ Every lab is **intentionally insecure** and loopback-only. Nothing calls out at
> **runtime** — LocalStack stands in for AWS, Samba for a Windows DC, and every
> cloud-metadata/IMDS endpoint is a local mock. (Base images are pulled from registries at
> build time; the one exception at runtime is lab 01's **optional** WireGuard overlay, which
> fetches a third-party image — see [macOS reachability](#macos-reachability).)

## The ladder

| # | Lab | Tier | Stack / area | Non-obvious hook |
|---|-----|------|--------------|------------------|
| 01 | `01-trivial-goat-cms` | trivial | PHP/MariaDB blog | — (textbook baseline) |
| 02 | `02-easy-taskflow` | easy | Node/Express + MongoDB | NoSQLi + JWT from a leaked `.env.bak` |
| 03 | `03-easy-nebula-wiki` | easy | Flask + Redis + Postgres | SSTI → RCE; Flask session forgery |
| 04 | `04-easy-helix-actuator` | easy | Java/Spring Boot | actuator env/heapdump → DB creds |
| 05 | `05-medium-ledgerline-api` | medium | Go REST | mass-assignment + TOCTOU race; hidden endpoints |
| 06 | `06-medium-northwind-smb` | medium | Samba + Linux pivot | null-session loot; non-rockyou crack; cred reuse |
| 07 | `07-medium-bazaar-microservices` | medium | SPA + Node + Python, segmented | SSRF → internal-only admin |
| 08 | `08-hard-cirrus-cloud` | hard | LocalStack (S3/IAM/STS/Secrets) | SSRF → IMDS → assume-role → S3 |
| 09 | `09-hard-bastion-pivot` | hard | 3 hosts / 2 networks | deserialization → pivot → crown jewels |
| 10 | `10-hard-relay` | hard | bespoke TCP service | fingerprint + protocol-reversing |

Trivial/easy use standard, scanner-visible vectors (easy still needs ~2 chained steps).
**Medium and hard are deliberately non-obvious**: no default-seclist path (invented endpoint
and share names, discoverable only from leaked specs/bundles/source), no textbook single
vector (logic flaws, chains, segmented networks), and any crackable secret is derivable only
from in-lab context — never stock `rockyou`.

## The workflow

```sh
make lab-list                                 # every lab, tier, ports, up/down state
make lab-up      LAB=01-trivial-goat-cms       # build + start (loopback-only)
make lab-verify  LAB=01-trivial-goat-cms       # assert the planted loot seeded
uv run python labs/labctl scope 01-trivial-goat-cms --install   # -> ./engagements/<id>/scope.json
export SKUGGI_ENGAGEMENT=01-trivial-goat-cms
uv run skuggi                                  # run the engagement
make lab-restore LAB=01-trivial-goat-cms       # revert the TARGET to pristine, keep your work
make lab-wipe    LAB=01-trivial-goat-cms       # nuke the target AND ./engagements/<id>
```

Read each lab's `briefing.md` for its scenario, objective and rules of engagement.
`solution.md` in each lab is the instructor's answer key (intended chain + loot manifest).

## wipe vs restore

- **`restore`** reverts the *target* to its pristine planted state and **keeps** your
  engagement work (`./engagements/<id>` — ledger, recon, reports). Use it to undo changes you
  made to the target mid-engagement, or to re-attempt a path.
- **`wipe`** tears the target down, drops its volumes, and **also removes**
  `./engagements/<id>`, so you start completely fresh. It confirms first (`--yes` skips).

`labctl` reads each lab's `manifest.json` and shells `docker compose`. The controller is
standalone dev tooling under `labs/_lib` — deliberately **not** a `skuggi` console script, so
it never ships in the wheel. `tests/unit/test_labs_static.py` validates every lab's manifest
and scope offline, inside `make check`.

## macOS reachability

On macOS, Docker Desktop does not route to container IPs, so reach each lab at its
loopback-published port (`127.0.0.1:81NN`). Every lab's scope authorises loopback, so this
is the supported path — the briefings name an in-network IP for the Linux/direct-routing
view. On Linux the bridge is directly routable, so you can target that IP directly.

Only **lab 01** ships an optional `wireguard/` overlay, for operators who specifically want
to hit its in-network IP (`192.0.2.10`) by IP from a macOS host; it is not required to run
the lab, and it pulls a third-party image (see
[labs/01-trivial-goat-cms/README.md](../labs/01-trivial-goat-cms/README.md)).
