# 08 · Cirrus Cloud — hard

A cloud-in-a-box (LocalStack: S3/IAM/STS/Secrets) + an app instance whose SSRF reaches a mock
IMDS at `169.254.169.254`. SSRF → instance role credentials → S3 contracts + a Secrets
Manager DB secret. Fully offline; no real AWS. Read [briefing.md](briefing.md);
[solution.md](solution.md) is the key.

> ⚠️ Intentionally insecure. Loopback-only (portal 8108, cloud API 8308). Never expose it.

```sh
make lab-up     LAB=08-hard-cirrus-cloud
make lab-verify LAB=08-hard-cirrus-cloud
uv run python labs/labctl scope 08-hard-cirrus-cloud --install
make lab-restore LAB=08-hard-cirrus-cloud
make lab-wipe    LAB=08-hard-cirrus-cloud
```
