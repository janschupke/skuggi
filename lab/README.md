# skuggi practice lab

A deliberately vulnerable target network for exercising skuggi end-to-end.
**Full documentation — topology, credentials, the vulnerability catalog, skuggi
wiring, and the WireGuard setup — is in [../docs/lab.md](../docs/lab.md).**

> ⚠️ Intentionally insecure. Run only on a machine you control, for authorized
> offline practice. Ports bind to `127.0.0.1` only; never expose this.

## Quickstart

```sh
cp .env.example .env
docker compose up -d --build      # Apache/PHP + MariaDB on one host, 192.0.2.10
curl -s http://127.0.0.1:8080/    # sanity check
```

Point skuggi at it:

```sh
mkdir -p ../engagements/lab
cp scope.json ../engagements/lab/scope.json
export SKUGGI_ENGAGEMENT=lab
uv run skuggi
```

macOS only — to reach `192.0.2.10` by IP, bring up the WireGuard overlay and
import the generated peer config (details in [../docs/lab.md](../docs/lab.md)):

```sh
docker compose -f docker-compose.yml -f wireguard/docker-compose.wg.yml up -d
```

Tear down: `docker compose down -v`.
