'use strict';
// SwiftCart order portal — DELIBERATELY VULNERABLE practice target.
// Easy tier, webapp set. Vectors: D (path traversal), G (IDOR), H (stored XSS).
//
// Data lives in a small in-memory store seeded at startup (no database
// container, no native modules) so a plain `node server.js` on node:20-alpine
// comes up clean and a restart is a pristine reseed.

const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());

// --- seeded store (reset on every process start = pristine restore) ----------

// Customer accounts. Account 1 ("you") is the signed-in shopper in the UI;
// accounts 2 and 3 belong to OTHER customers.
const accounts = [
  {
    id: 1,
    name: 'Jordan Lee',
    email: 'jordan.lee@swiftcart.example',
    phone: '+1-206-555-0133',
    card_last4: '1180',
    address: '55 Pike St, Seattle, WA',
  },
  {
    id: 2,
    name: 'Amara Okonkwo',
    email: 'a.okonkwo@brightwater-logistics.example',
    phone: '+1-415-555-0142',
    card_last4: '4417',
    address: '2200 Market St, San Francisco, CA',
  },
  {
    id: 3,
    name: 'Priya Raman',
    email: 'p.raman@meridian-freight.example',
    phone: '+1-312-555-0178',
    card_last4: '9021',
    address: '401 N Wabash Ave, Chicago, IL',
  },
];

// Invoices, one per account. Invoice 2 is Amara's (another customer's).
const invoices = [
  {
    id: 1,
    account_id: 1,
    customer: 'Jordan Lee',
    email: 'jordan.lee@swiftcart.example',
    total: 89.97,
    card_last4: '1180',
    receipt: 'receipt-1001.txt',
    items: [
      { sku: 'SC-EARBUD-01', name: 'Aurora Wireless Earbuds', qty: 1, price: 79.99 },
      { sku: 'SC-CABLE-02', name: 'USB-C Braided Cable', qty: 2, price: 4.99 },
    ],
  },
  {
    id: 2,
    account_id: 2,
    customer: 'Amara Okonkwo',
    email: 'a.okonkwo@brightwater-logistics.example',
    total: 1299.0,
    card_last4: '4417',
    receipt: 'receipt-1002.txt',
    items: [
      { sku: 'SC-LAPTOP-14', name: 'SwiftBook Pro 14"', qty: 1, price: 1299.0 },
    ],
  },
  {
    id: 3,
    account_id: 3,
    customer: 'Priya Raman',
    email: 'p.raman@meridian-freight.example',
    total: 249.5,
    card_last4: '9021',
    receipt: 'receipt-1003.txt',
    items: [
      { sku: 'SC-CHAIR-09', name: 'Ergo Mesh Chair', qty: 1, price: 249.5 },
    ],
  },
];

const products = [
  {
    id: 1,
    name: 'Aurora Wireless Earbuds',
    price: 79.99,
    description: 'Active-noise-cancelling earbuds with a 24-hour charging case.',
  },
  {
    id: 2,
    name: 'SwiftBook Pro 14"',
    price: 1299.0,
    description: 'Thin-and-light laptop for work on the move.',
  },
  {
    id: 3,
    name: 'Ergo Mesh Chair',
    price: 249.5,
    description: 'Breathable mesh office chair with lumbar support.',
  },
];

// Stored product reviews. SEEDED with a raw <script> payload on product 1 so
// the stored-unsanitised finding is verifiable in a pristine lab without any
// exploitation step. POST /api/reviews appends here.
const reviews = [
  {
    id: 1,
    productId: 1,
    author: 'happy_shopper',
    body: 'Great sound for the price, battery lasts all day.',
  },
  {
    id: 2,
    productId: 1,
    author: 'mallory',
    // VULN (stored XSS): persisted verbatim and rendered raw on /product/:id.
    body: '<script>alert(document.domain)</script>',
  },
];
let nextReviewId = 3;

// --- tiny helpers ------------------------------------------------------------

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function page(title, bodyHtml) {
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<title>' +
    esc(title) +
    '</title></head><body>' +
    bodyHtml +
    '</body></html>'
  );
}

// --- routes ------------------------------------------------------------------

app.get('/health', (_req, res) => res.type('text').send('ok'));

app.get('/', (_req, res) => {
  const list = products
    .map(
      (p) =>
        '<li><a href="/product/' +
        p.id +
        '">' +
        esc(p.name) +
        '</a> — $' +
        p.price.toFixed(2) +
        '</li>'
    )
    .join('');
  res.type('html').send(
    page(
      'SwiftCart',
      '<h1>SwiftCart</h1><p>Your order portal. Browse the catalogue, read reviews, ' +
        'and download your receipts from your account.</p><ul>' +
        list +
        '</ul><p><a href="/account?id=1">My account</a></p>'
    )
  );
});

// Product detail + stored reviews.
// VULN (stored XSS): each review body is interpolated RAW into the page — no
// escaping — so a persisted <script>…</script> executes in the visitor's
// browser. Product fields are escaped; the review body is the sink.
app.get('/product/:id', (req, res) => {
  const id = Number(req.params.id);
  const product = products.find((p) => p.id === id);
  if (!product) return res.status(404).type('html').send(page('Not found', '<p>No such product.</p>'));
  const rvs = reviews.filter((r) => r.productId === id);
  const rvHtml = rvs
    .map(
      (r) =>
        '<li><strong>' +
        esc(r.author) +
        '</strong>: ' +
        r.body + // VULN: raw, unescaped
        '</li>'
    )
    .join('');
  res.type('html').send(
    page(
      product.name,
      '<h1>' +
        esc(product.name) +
        '</h1><p>$' +
        product.price.toFixed(2) +
        '</p><p>' +
        esc(product.description) +
        '</p><h2>Reviews</h2><ul>' +
        rvHtml +
        '</ul>' +
        '<form method="post" action="/api/reviews">' +
        '<p>Leave a review (JSON API: POST /api/reviews)</p></form>'
    )
  );
});

// VULN (stored XSS, write side): a review body is stored verbatim with no
// sanitisation and surfaces raw on /product/:id.
app.post('/api/reviews', (req, res) => {
  const { productId, author, body } = req.body || {};
  const pid = Number(productId);
  if (!products.find((p) => p.id === pid)) {
    return res.status(400).json({ error: 'unknown productId' });
  }
  const review = {
    id: nextReviewId++,
    productId: pid,
    author: author || 'anonymous',
    body: body || '',
  };
  reviews.push(review);
  return res.status(201).json(review);
});

// VULN (IDOR, route param): returns ANY invoice by id with no authentication
// and no ownership check, so invoice 2 (another customer's) is readable.
app.get('/api/invoices/:id', (req, res) => {
  const id = Number(req.params.id);
  const invoice = invoices.find((inv) => inv.id === id);
  if (!invoice) return res.status(404).json({ error: 'not found' });
  return res.json(invoice);
});

// VULN (IDOR, query param): returns ANY account by id with no authentication
// and no ownership check. The UI only ever links id=1 ("your" account), but
// id=2 / id=3 expose other customers' PII.
app.get('/account', (req, res) => {
  const id = Number(req.query.id);
  const account = accounts.find((a) => a.id === id);
  if (!account) return res.status(404).json({ error: 'not found' });
  return res.json(account);
});

// VULN (path traversal): req.query.file is path.join'd onto the downloads dir
// with NO sanitisation, so "../secrets/app.env" or "../../etc/passwd" escape
// the intended directory and exfiltrate arbitrary files.
const DOWNLOAD_DIR = path.join(__dirname, 'downloads');
app.get('/download', (req, res) => {
  const file = req.query.file || '';
  const target = path.join(DOWNLOAD_DIR, file); // no normalisation / containment check
  fs.readFile(target, (err, data) => {
    if (err) return res.status(404).type('text').send('file not found');
    res.type('text').send(data);
  });
});

const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, () => console.log('swiftcart listening on :' + PORT));
