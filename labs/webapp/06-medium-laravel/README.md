# 06-medium-laravel — LumenPay (webapp set)

Genuine Laravel 11 billing SaaS on `php:8.2-apache` + MySQL. **Intentionally insecure**,
loopback-only (`127.0.0.1:8506`). Covers: merchant document upload with insufficient
validation (client-MIME only, original extension kept under the web root) → PHP webshell →
RCE → reverse shell, framework `.env` credential leak, and a sudoers-NOPASSWD privilege
escalation to a root-only payment-gateway key.

The Laravel skeleton is built at image-build time with `composer create-project
laravel/laravel:^11.0`; the vulnerable controller, routes, views and a seeded `.env` are then
copied over it, so the running app is authentically Laravel (artisan, `routes/web.php`,
`app/Http/Controllers`, `bootstrap/app.php`, the stock `/up` health route) with its
DocumentRoot pointed at `public/`.

```sh
make lab-up      LAB=06-medium-laravel
make lab-verify  LAB=06-medium-laravel
uv run python labs/labctl scope 06-medium-laravel --install
make lab-restore LAB=06-medium-laravel
make lab-down    LAB=06-medium-laravel
```

Scenario and objective: [briefing.md](briefing.md). Answer key: [solution.md](solution.md).
Part of the **webapp** set — see [../README.md](../README.md).
