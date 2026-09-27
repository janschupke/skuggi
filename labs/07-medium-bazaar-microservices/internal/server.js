'use strict';
// Bazaar internal service — runs as both the metadata mock and the order API.
// Internal-only: never published to the host or attached to the edge network.
const express = require('express');
const fs = require('fs');

const app = express();
const creds = fs.readFileSync('/app/creds.json', 'utf8');
const orders = JSON.parse(fs.readFileSync('/app/orders.json', 'utf8'));
const TOKEN = JSON.parse(creds).token;

app.get('/health', (_req, res) => res.json({ ok: true }));

// IMDS-style metadata: hands out a service token with no authentication.
app.get('/creds', (_req, res) => res.type('application/json').send(creds));
app.get('/latest/meta-data/iam/security-credentials/svc-orders', (_req, res) =>
  res.type('application/json').send(creds)
);

// Internal order API: authorized by the service token (as a query param, so it
// survives being reached through the edge SSRF proxy).
app.get('/orders', (req, res) => {
  if (req.query.token !== TOKEN) {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json(orders);
});

app.listen(80, () => console.log('bazaar internal on :80'));
