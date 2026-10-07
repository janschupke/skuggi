# 11-medium-moodle — LearnHub (webapp set)

A Moodle LMS ("LearnHub") on MariaDB, both **Bitnami** images. **Intentionally insecure**,
loopback-only (`127.0.0.1:8511`). Covers: **H** stored XSS (profile/forum HTML), **G** IDOR on
the `?id=`/`?userid=` user and resource endpoints, **F** db-dump of student PII + bcrypt
(`$2y$`) hashes.

```sh
make lab-up      LAB=11-medium-moodle
make lab-verify  LAB=11-medium-moodle
uv run python labs/labctl scope 11-medium-moodle --install
make lab-restore LAB=11-medium-moodle
make lab-down    LAB=11-medium-moodle
```

> ⚠️ **Moodle first boot is slow (~120s).** The app healthcheck uses a generous
> `start_period`; `lab-verify` may need a minute or two after `lab-up` before the Moodle
> install finishes and the one-shot `seed` sidecar plants the student rows.

Scenario and objective: [briefing.md](briefing.md). Answer key: [solution.md](solution.md).
Part of the **webapp** set — see [../README.md](../README.md).
