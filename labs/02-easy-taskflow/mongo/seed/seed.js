// First-boot seed for TaskFlow (runs once on an empty data volume).
db = db.getSiblingDB('taskflow');

db.users.insertMany([
  { username: 'admin', password: 'S3cur3-Adm1n-Pw', role: 'admin' },
  { username: 'jdoe', password: 'hunter2', role: 'user' },
  { username: 'mchen', password: 'spring2024', role: 'user' },
]);

// Customer PII — the crown jewels an assessment must flag as exposed.
db.customers.insertMany([
  {
    name: 'Priya Raman',
    email: 'p.raman@meridian-freight.example',
    plan: 'enterprise',
    card_last4: '4485',
    mrr_usd: 2400,
  },
  {
    name: 'Tomas Berg',
    email: 't.berg@nordlys.example',
    plan: 'pro',
    card_last4: '1029',
    mrr_usd: 199,
  },
  {
    name: 'Aiko Tanaka',
    email: 'aiko.tanaka@shirogane.example',
    plan: 'pro',
    card_last4: '7731',
    mrr_usd: 199,
  },
]);

db.tasks.insertMany([
  { id: 1, owner: 'jdoe', title: 'Fix login 500', body: 'Intermittent 500 on /api/login under load.' },
  { id: 2, owner: 'jdoe', title: 'Update onboarding docs', body: 'Screenshots are stale.' },
  { id: 3, owner: 'mchen', title: 'Design new dashboard', body: 'Wireframes due Friday.' },
  {
    id: 7,
    owner: 'admin',
    title: 'Rotate cloud backup key',
    body:
      'Nightly DB dump uploader still uses the old static key: ' +
      'AKIAZ7QEXAMPLE9TASKF / wJalrXUtnFEMI-K7MDENG-TASKFLOWbPxRfiCY. ' +
      'Move to a role before Q3.',
  },
]);
