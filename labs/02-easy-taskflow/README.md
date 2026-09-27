# 02 · TaskFlow — easy

Node/Express SaaS API on MongoDB. NoSQL-injection auth bypass → IDOR → a leaked cloud key,
with a JWT secret left in a web-root `.env.bak` as an alternate path. Read
[briefing.md](briefing.md); [solution.md](solution.md) is the answer key.

> ⚠️ Intentionally insecure. Loopback-only (`127.0.0.1:8102`). Never expose it.

```sh
make lab-up     LAB=02-easy-taskflow
make lab-verify LAB=02-easy-taskflow
uv run python labs/labctl scope 02-easy-taskflow --install
make lab-restore LAB=02-easy-taskflow
make lab-wipe    LAB=02-easy-taskflow
```
