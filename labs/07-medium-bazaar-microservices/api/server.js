'use strict';
// Bazaar edge API — DELIBERATELY VULNERABLE practice target.
// It sits on BOTH the edge and internal networks and offers a "link preview"
// that fetches an arbitrary URL server-side (SSRF) — the pivot into the
// internal-only services.
const express = require('express');
const path = require('path');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (_req, res) => res.json({ ok: true }));

// VULN (SSRF): no allowlist, no scheme/host checks. Fetches whatever it is told
// and returns the body — reaching internal-only hosts the caller cannot.
app.get('/api/fetch', async (req, res) => {
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

app.listen(3000, () => console.log('bazaar api on :3000'));
