# 01-easy-php-plain — QuickDesk (webapp set)

Plain PHP/Apache helpdesk on MariaDB. **Intentionally insecure**, loopback-only
(`127.0.0.1:8501`). Covers: SQLi auth bypass, exposed web-root SQL dump, unsalted-MD5 crack,
customer-PII exposure.

```sh
make lab-up      LAB=01-easy-php-plain
make lab-verify  LAB=01-easy-php-plain
uv run python labs/labctl scope 01-easy-php-plain --install
make lab-restore LAB=01-easy-php-plain
make lab-down    LAB=01-easy-php-plain
```

Scenario and objective: [briefing.md](briefing.md). Answer key: [solution.md](solution.md).
Part of the **webapp** set — see [../README.md](../README.md).
