# 03 · Nebula Wiki — easy

A Flask internal wiki over Redis + Postgres (three hosts). SSTI-to-RCE in the preview, an
unauthenticated Redis on the network, and a Flask `SECRET_KEY` leaked by a `/debug` route
(session forgery). Read [briefing.md](briefing.md); [solution.md](solution.md) is the key.

> ⚠️ Intentionally insecure. Loopback-only (web 8103, redis 8203, postgres 8303). Never expose it.

```sh
make lab-up     LAB=03-easy-nebula-wiki
make lab-verify LAB=03-easy-nebula-wiki
uv run python labs/labctl scope 03-easy-nebula-wiki --install
make lab-restore LAB=03-easy-nebula-wiki
make lab-wipe    LAB=03-easy-nebula-wiki
```
