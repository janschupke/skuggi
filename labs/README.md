# skuggi practice range

Ten independent, self-contained pentest engagement exercises on a difficulty ladder. Each
lab is a realistic-but-simplified scenario with **real reportable surface and planted loot**
(hashes, credentials, contracts, customer data) — not a single-flag path. Drive them with
skuggi like a real engagement; manage them with `labctl`.

> ⚠️ Every lab is **intentionally insecure**. Run only on a machine you control, for
> authorized offline practice. All ports bind to `127.0.0.1` only. Nothing calls a
> third-party or external API — the "cloud" lab uses LocalStack, the "AD/SMB" lab uses
> Samba, and every metadata/IMDS endpoint is a local mock.

Full guide (topology, credentials, the `labctl` workflow, per-lab intent): [../docs/labs.md](../docs/labs.md).
This is separate from the frozen automated-test target in `tests/e2e/fixtures/lab/`, which
CI drives and which never changes as these labs evolve.

## The ladder

| # | Lab | Tier | Stack / area | Non-obvious hook |
|---|-----|------|--------------|------------------|
| 01 | `01-trivial-goat-cms` | trivial | PHP/MariaDB blog | — (textbook baseline) |
| 02 | `02-easy-taskflow` | easy | Node/Express + MongoDB | NoSQLi + JWT from a leaked `.env.bak` |
| 03 | `03-easy-nebula-wiki` | easy | Flask + Redis + Postgres | SSTI → RCE; session forgery |
| 04 | `04-easy-helix-actuator` | easy | Java/Spring Boot | actuator env/heapdump → DB creds |
| 05 | `05-medium-ledgerline-api` | medium | Go REST | mass-assignment + TOCTOU race; hidden endpoints |
| 06 | `06-medium-northwind-smb` | medium | Samba + Linux pivot | null-session loot; non-rockyou crack; cred reuse |
| 07 | `07-medium-bazaar-microservices` | medium | SPA + Node + Python, segmented | SSRF → internal-only admin |
| 08 | `08-hard-cirrus-cloud` | hard | LocalStack (S3/IAM/STS/Secrets) | SSRF → IMDS → assume-role → S3 |
| 09 | `09-hard-bastion-pivot` | hard | 3 hosts / 2 networks | deserialization → pivot → crown jewels |
| 10 | `10-hard-relay` | hard | bespoke TCP service | fingerprint + protocol-reversing |

Trivial/easy use standard vectors (easy still needs ~2 chained steps). **Medium and hard are
deliberately non-obvious**: no default-seclist path, no textbook single vector — hidden
endpoints, custom-wordlist cracks, logic flaws, and segmented networks.

## Using labctl (from the repo root)

```sh
make lab-list                              # every lab, tier, ports, up/down
make lab-up      LAB=01-trivial-goat-cms   # build + start (loopback-only)
make lab-verify  LAB=01-trivial-goat-cms   # assert the planted loot seeded
make lab-restore LAB=01-trivial-goat-cms   # revert the TARGET to pristine, keep your work
make lab-wipe    LAB=01-trivial-goat-cms   # nuke the target AND ./engagements/<lab>
make lab-down    LAB=01-trivial-goat-cms   # stop, keep planted data

uv run python labs/labctl scope 01-trivial-goat-cms --install   # drop scope.json into ./engagements/
```

## Anatomy of a lab

```
NN-tier-name/
  manifest.json     # machine-readable: tier, networks, ports, health, restore, loot[]
  scope.json        # drop-in skuggi EngagementConfig authorizing exactly this lab
  briefing.md       # the client scenario + rules of engagement + objective
  solution.md       # the answer key: intended chain + loot manifest
  docker-compose.yml
  <build contexts>  # web/, api/, db/, services/ ...
```

`labctl` reads only `manifest.json`; `tests/unit/test_labs_static.py` validates every
manifest and scope offline, so a malformed lab fails `make check` without booting docker.

## Conventions (see `_common/CONVENTIONS.md`)

- **One isolated network per lab** (two for segmented labs), from private/TEST-NET ranges so
  a stray route can never hit real infrastructure. In a segmented lab the goal host lives on
  the internal-only network, unpublished.
- **Loopback-only published ports**: HTTP on `81NN`, auxiliary services on `82NN`/`83NN`
  (NN = lab number). Only one lab is expected up at a time; distinct ports let two coexist.
- **Unique compose project + image names** per lab (`skuggi-lab-NN…`) so no two stacks or the
  e2e fixture collide.
- **Planted loot with stable fingerprints** in `manifest.json`, so `labctl verify` proves a
  restore re-seeded and a future scoring harness can auto-grade.
