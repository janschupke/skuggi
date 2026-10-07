# 07-medium-symfony — CiviDoc (webapp set)

Genuine Symfony 6.4 app on PHP 8.2/Apache (DocumentRoot `public/`) backed by PostgreSQL 16.
**Intentionally insecure**, loopback-only (`127.0.0.1:8507`). Covers: SQLi auth bypass on a
legacy login repository (A), path-traversal document exfiltration (D), and tenant-scoping
IDOR on the JSON API via route and query param (G).

```sh
make lab-up      LAB=07-medium-symfony
make lab-verify  LAB=07-medium-symfony
uv run python labs/labctl scope 07-medium-symfony --install
make lab-restore LAB=07-medium-symfony
make lab-down    LAB=07-medium-symfony
```

The app's PHP dependencies are resolved from packagist at **image-build time** (network is
allowed for the build only); the running lab makes no external calls. First boot warms the
Symfony prod cache, so give the app healthcheck its `start_period` before verifying.

Scenario and objective: [briefing.md](briefing.md). Answer key: [solution.md](solution.md).
Part of the **webapp** set — see [../README.md](../README.md).
