# 05-easy-django — FernData (webapp set)

Django 5 + Postgres customer-billing portal, served by gunicorn. **Intentionally insecure**,
loopback-only (`127.0.0.1:8505`). Covers: IDOR (numeric route + `/api/profile` query param),
customer-PII exposure, stored XSS via `|safe`, and a legacy unsalted-MD5 auth row that cracks
offline next to the normal pbkdf2 users.

```sh
make lab-up      LAB=05-easy-django
make lab-verify  LAB=05-easy-django
uv run python labs/labctl scope 05-easy-django --install
make lab-restore LAB=05-easy-django
make lab-down    LAB=05-easy-django
```

The database is Django-managed: there is no mounted SQL seed. On first boot the app
container's entrypoint runs `migrate` and an idempotent `seed_portal` management command;
`restore` (recreate) drops the Postgres volume and reseeds.

Scenario and objective: [briefing.md](briefing.md). Answer key: [solution.md](solution.md).
Part of the **webapp** set — see [../README.md](../README.md).
