# 04-easy-node — SwiftCart (webapp set)

Node/Express order portal with an in-memory seeded store (no database, no native modules).
**Intentionally insecure**, loopback-only (`127.0.0.1:8504`). Covers: path-traversal file
exfiltration, IDOR (route param + query param) exposing customer PII, and stored XSS in
product reviews.

```sh
make lab-up      LAB=04-easy-node
make lab-verify  LAB=04-easy-node
uv run python labs/labctl scope 04-easy-node --install
make lab-restore LAB=04-easy-node
make lab-down    LAB=04-easy-node
```

Scenario and objective: [briefing.md](briefing.md). Answer key: [solution.md](solution.md).
Part of the **webapp** set — see [../README.md](../README.md).
