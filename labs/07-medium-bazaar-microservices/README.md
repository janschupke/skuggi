# 07 · Bazaar — medium

Segmented microservices: an edge API with an SSRF link-preview bridges into an internal-only
mesh. SSRF → mock metadata (service token) → internal order API → customer PII. The SSRF sink
and internal hostnames live only in the SPA bundle. Read [briefing.md](briefing.md);
[solution.md](solution.md) is the key.

> ⚠️ Intentionally insecure. Loopback-only (`127.0.0.1:8107`); the internal tier is unpublished. Never expose it.

```sh
make lab-up     LAB=07-medium-bazaar-microservices
make lab-verify LAB=07-medium-bazaar-microservices
uv run python labs/labctl scope 07-medium-bazaar-microservices --install
make lab-restore LAB=07-medium-bazaar-microservices
make lab-wipe    LAB=07-medium-bazaar-microservices
```
