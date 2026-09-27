'use strict';
// TaskFlow API — DELIBERATELY VULNERABLE practice target.
const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
const MONGO_URL = process.env.MONGO_URL || 'mongodb://mongo:27017/taskflow';

const app = express();
app.use(express.json());

// VULN (info leak): the web root was deployed with a leftover ".env.bak".
// dotfiles:'allow' serves it, exposing the JWT signing secret.
app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'allow' }));

let db = null;

app.get('/health', (_req, res) => res.json({ ok: true }));

app.get('/', (_req, res) => {
  res
    .type('html')
    .send(
      '<h1>TaskFlow</h1><p>Internal task-tracking API. ' +
        'POST /api/login, then GET /api/tasks/:id.</p>'
    );
});

// VULN (NoSQL injection): the credentials object is built straight from the
// JSON body, so {"password": {"$ne": null}} bypasses authentication.
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = await db.collection('users').findOne({ username, password });
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  const token = jwt.sign({ sub: user.username, role: user.role }, JWT_SECRET, {
    expiresIn: '1h',
  });
  return res.json({ token, role: user.role });
});

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'bad token' });
  }
}

// The caller's own tasks.
app.get('/api/tasks', auth, async (req, res) => {
  const tasks = await db
    .collection('tasks')
    .find({ owner: req.user.sub })
    .project({ _id: 0 })
    .toArray();
  return res.json(tasks);
});

// VULN (IDOR): any authenticated user reads ANY task by numeric id — no
// ownership check. Task 7 (admin's) holds a live cloud backup key.
app.get('/api/tasks/:id', auth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'bad id' });
  const task = await db.collection('tasks').findOne({ id }, { projection: { _id: 0 } });
  if (!task) return res.status(404).json({ error: 'not found' });
  return res.json(task);
});

MongoClient.connect(MONGO_URL)
  .then((client) => {
    db = client.db();
    app.listen(3000, () => console.log('taskflow listening on :3000'));
  })
  .catch((err) => {
    console.error('mongo connect failed', err);
    process.exit(1);
  });
