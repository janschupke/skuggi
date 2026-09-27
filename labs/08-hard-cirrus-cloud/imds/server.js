'use strict';
// Mock EC2 Instance Metadata Service (IMDS). Hands out the instance role's
// temporary credentials with NO authentication — the SSRF payoff.
const express = require('express');
const fs = require('fs');

const app = express();
const creds = fs.readFileSync('/app/creds.json', 'utf8');
const ROLE = 'cirrus-web-instance';

app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/latest/meta-data/iam/security-credentials/', (_req, res) =>
  res.type('text/plain').send(ROLE)
);
app.get(`/latest/meta-data/iam/security-credentials/${ROLE}`, (_req, res) =>
  res.type('application/json').send(creds)
);
app.get('/', (_req, res) => res.type('text/plain').send('latest\n'));

app.listen(80, () => console.log('imds on :80'));
