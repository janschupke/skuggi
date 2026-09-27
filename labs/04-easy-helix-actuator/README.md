# 04 · Helix Admin — easy

A Spring Boot portal with a fully-exposed actuator (unmasked `env`/`configprops`):
`/actuator/env` leaks the DB password and an OAuth client secret, opening the Postgres of
employee salaries. Read [briefing.md](briefing.md); [solution.md](solution.md) is the key.

> ⚠️ Intentionally insecure. Loopback-only (portal 8104, postgres 8304). Never expose it.

```sh
make lab-up     LAB=04-easy-helix-actuator
make lab-verify LAB=04-easy-helix-actuator
uv run python labs/labctl scope 04-easy-helix-actuator --install
make lab-restore LAB=04-easy-helix-actuator
make lab-wipe    LAB=04-easy-helix-actuator
```
