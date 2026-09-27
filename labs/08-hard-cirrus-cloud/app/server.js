'use strict';
// Cirrus web app — DELIBERATELY VULNERABLE practice target.
// Runs on an "instance" that has an attached role; an SSRF in the avatar/link
// fetcher lets an attacker reach the instance metadata service (IMDS).
const express = require('express');
const path = require('path');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (_req, res) => res.json({ ok: true }));

// VULN (SSRF): fetches an arbitrary URL server-side (avatar/link preview).
app.get('/api/avatar', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'url required' });
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(4000) });
    const body = await r.text();
    return res.status(r.status).type('text/plain').send(body);
  } catch (e) {
    return res.status(502).json({ error: String(e) });
  }
});

app.listen(3000, () => console.log('cirrus app on :3000'));
