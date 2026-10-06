# The e2e fixture target

`tests/e2e/fixtures/lab/` is the **frozen, deliberately-vulnerable target** the L5 e2e suite
drives. It is intentionally separate from the user-facing practice range in `labs/` (see
[labs.md](labs.md)): the range grows and changes, this fixture stays pinned to the oracles
the e2e tests assert. If you want to *practice*, use the range; this doc is about the
automated test target only.

> ⚠️ Intentionally insecure. Loopback-published only (`127.0.0.1`). Never expose it.

## Topology

One host, one container: Apache/PHP 8.2 on `:80` and MariaDB on `:3306` co-located under
supervisord, static IP `192.0.2.10` (hostname `web.lab`) on the `192.0.2.0/24` bridge
(`skuggi-lab`). Ports publish to `127.0.0.1:8080` (HTTP) and `127.0.0.1:3306` (MySQL). On a
Linux CI runner the bridge is directly routable, so both the loopback and the `192.0.2.10`
cases run; on macOS the `192.0.2.10` cases skip (this fixture ships no reachability overlay)
and only the loopback cases run.

## The pinned oracles

The seed data is a stable contract — changing `web/db/seed.sql` breaks
`tests/e2e/test_lab_engagement.py`:

- `admin` / `password123` → md5 `482c811da5d5b4bc6d497ffa98491e38` (the SQLi / backup oracle).
- Draft post id=4 body contains `remove /backup/db_dump.sql before launch` (the IDOR oracle).
- `/backup/db_dump.sql` exposes all four user md5 hashes and the DB creds.
- A 7-column UNION on `post.php?id=` dumps `users`; an out-of-scope `curl http://8.8.8.8/`
  is blocked by the guard (proving the boundary is live).

## Bring it up

```sh
docker compose -f tests/e2e/fixtures/lab/docker-compose.yml up -d --wait
curl -s http://127.0.0.1:8080/
make e2e            # runs the L5 suite; skips cleanly if the fixture is down
docker compose -f tests/e2e/fixtures/lab/docker-compose.yml down -v
```

Or set `SKUGGI_E2E_COMPOSE_UP=1` and let the `lab` fixture start and tear it down. The
published HTTP port is discovered from `docker compose port web 80`, so a collision remap is
handled automatically. See [testing.md](testing.md) for the full L5 layer description.

## Network isolation (coexisting with the practice range)

The lab network, gateway and in-container IP are parameterized
(`LAB_SUBNET`/`LAB_GATEWAY`/`LAB_HOST_IP`, defaulting to `192.0.2.0/24` /
`192.0.2.1` / `192.0.2.10`). The user-facing practice range in `labs/` defaults
to the *same* TEST-NET-1 block, so a running practice lab would otherwise block
this fixture's bring-up with a `pool overlaps` error. The `SKUGGI_E2E_COMPOSE_UP`
path therefore tries a short list of non-overlapping candidate subnets (RFC 5737
documentation ranges) in order and starts on the first free one, so the e2e
fixture coexists with `labs/` without ever touching it. The loopback
(`127.0.0.1:8080`) cases are unaffected by the remap; the direct-`192.0.2.10`
cases use whichever IP the stack actually started on.
