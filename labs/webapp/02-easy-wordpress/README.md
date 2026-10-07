# 02-easy-wordpress — Brightwave Media (webapp set)

Stock WordPress 6 / MariaDB company blog. **Intentionally insecure**, loopback-only
(`127.0.0.1:8502`). Covers: wordlist brute of the admin login (B), authenticated Theme/Plugin
editor → PHP webshell → reverse shell (J), and a `wp_users` phpass dump that cracks offline to
the same weak password (E).

```sh
make lab-up      LAB=02-easy-wordpress
make lab-verify  LAB=02-easy-wordpress
uv run python labs/labctl scope 02-easy-wordpress --install
make lab-restore LAB=02-easy-wordpress
make lab-down    LAB=02-easy-wordpress
```

First boot runs an extra one-shot `init` container (`wordpress:cli`) that waits for the DB and
web root, then `wp core install` + seeds the `admin`/`editor` users and a post — so the very
first `lab-up` takes a little longer than lab 01 (hence the 60s health `start_period`). The
in-lab `wordlist.txt` holds the weak admin password among decoys.

Scenario and objective: [briefing.md](briefing.md). Answer key: [solution.md](solution.md).
Part of the **webapp** set — see [../README.md](../README.md).
