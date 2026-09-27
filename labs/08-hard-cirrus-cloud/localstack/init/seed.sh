#!/bin/bash
# Seed S3 + Secrets Manager once LocalStack is ready. awslocal ships in the image.
set -e
awslocal s3 mb s3://cirrus-contracts

cat > /tmp/contracts.json <<'JSON'
{
  "contracts": [
    { "id": "CIR-7001", "counterparty": "Meridian Freight Ltd", "value_usd": 250000, "signed": "2026-02-11" },
    { "id": "CIR-7002", "counterparty": "Halcyon Capital Partners", "value_usd": 90000, "signed": "2026-04-03" }
  ]
}
JSON
cat > /tmp/customers.csv <<'CSV'
customer,email,plan,card_last4
Priya Raman,p.raman@meridian-freight.example,enterprise,4485
Tomas Berg,t.berg@nordlys.example,pro,1029
CSV
awslocal s3 cp /tmp/contracts.json s3://cirrus-contracts/contracts/contracts.json
awslocal s3 cp /tmp/customers.csv  s3://cirrus-contracts/customers/customers.csv

awslocal secretsmanager create-secret --name cirrus/db/prod \
  --secret-string '{"engine":"postgres","host":"cirrus-prod.internal","username":"cirrus_app","password":"C1rrus-RDS-Prod-2026"}'

# Cosmetic IAM: the role the instance assumes (community LocalStack does not
# enforce policies — the finding is that these creds grant full data access).
awslocal iam create-role --role-name cirrus-web-instance \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[]}' || true
echo "cirrus seed complete"
