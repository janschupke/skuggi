# 10-medium-drupal — CivicGov (webapp set)

Drupal 10 municipal portal on Postgres, auto-installed on first boot by a one-shot `drush`
init container that enables a **planted vulnerable custom module** (`civicgov_tools`).
**Intentionally insecure**, loopback-only (`127.0.0.1:8510`). Covers: SQLi → citizen-PII
dump (A, F), a token-guarded `shell_exec` RCE foothold (J), and a NOPASSWD-`find` root privesc
to a crown-jewel key (K).

```sh
make lab-up      LAB=10-medium-drupal
make lab-verify  LAB=10-medium-drupal
uv run python labs/labctl scope 10-medium-drupal --install
make lab-restore LAB=10-medium-drupal
make lab-down    LAB=10-medium-drupal
```

> First boot is slow: the init container runs `drush site:install` before the portal is
> usable (~90s). `make lab-verify` is green only once init has finished and the site is up.

Scenario and objective: [briefing.md](briefing.md). Answer key: [solution.md](solution.md).
Part of the **webapp** set — see [../README.md](../README.md).
