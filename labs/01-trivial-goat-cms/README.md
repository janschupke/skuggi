# 01 · Goat CMS — trivial

The teaching baseline of the skuggi practice range: a deliberately vulnerable PHP/MariaDB
blog on one host. Read [briefing.md](briefing.md) for the scenario and objective;
[solution.md](solution.md) is the answer key. Range-wide docs: [../../docs/labs.md](../../docs/labs.md).

> ⚠️ Intentionally insecure. Run only on a machine you control, for authorized offline
> practice. Ports bind to `127.0.0.1` only; never expose this.

## Quickstart (via labctl, from the repo root)

```sh
make lab-up LAB=01-trivial-goat-cms       # build + start (http on 127.0.0.1:8101)
make lab-verify LAB=01-trivial-goat-cms   # confirm the planted loot seeded
make lab-restore LAB=01-trivial-goat-cms  # revert the target to pristine
make lab-wipe LAB=01-trivial-goat-cms     # tear down + drop your engagement workspace
```

## Point skuggi at it

```sh
uv run python labs/labctl scope 01-trivial-goat-cms --install   # -> ./engagements/01-trivial-goat-cms/scope.json
export SKUGGI_ENGAGEMENT=01-trivial-goat-cms
uv run skuggi
```

## Manual bring-up (equivalent)

```sh
cp .env.example .env
docker compose up -d --build
curl -s http://127.0.0.1:8101/
```

On macOS, use the loopback port above (`127.0.0.1:8101`) — it is in scope and is the
supported path. The WireGuard overlay below is **optional**: it only lets you reach
`192.0.2.10` by IP, and it pulls a third-party image from lscr.io (needs network, may
rate-limit). Details in [../../docs/labs.md](../../docs/labs.md):

```sh
docker compose -f docker-compose.yml -f wireguard/docker-compose.wg.yml up -d
```

Tear down: `docker compose down -v`.
