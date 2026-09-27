-- First-boot seed for the Nebula Wiki (runs once on an empty data volume).

CREATE TABLE pages (
    slug  TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body  TEXT NOT NULL
);

CREATE TABLE employees (
    id     SERIAL PRIMARY KEY,
    name   TEXT NOT NULL,
    email  TEXT NOT NULL,
    dept   TEXT NOT NULL,
    salary INTEGER NOT NULL,
    ssn    TEXT NOT NULL
);

INSERT INTO pages (slug, title, body) VALUES
('welcome', 'Welcome', 'Welcome to the Nebula internal wiki. Browse the pages in the sidebar.'),
('coffee', 'Kitchen rota', 'Week A: Sam. Week B: Lin. Refill the beans.'),
('onboarding', 'Onboarding', 'New joiners: request laptop, VPN, and wiki access from IT.');

-- VULN (secret in content): an engineer pasted a deploy key into the runbook.
INSERT INTO pages (slug, title, body) VALUES
('infra-runbook', 'Infra runbook', $KEY$Deploy notes for the nightly job host.

The batch runner authenticates to the file server with this key (do NOT rotate
without updating cron):

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
NABLE-PRACTICE-LAB-KEY-DO-NOT-USE-nebula-infra-runbook-deploy-000000000
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END OPENSSH PRIVATE KEY-----

Host: files.nebula.lab   User: batch$KEY$);

INSERT INTO employees (name, email, dept, salary, ssn) VALUES
('Linnea Fowler', 'l.fowler@nebula.example', 'Engineering', 98000, '651-24-8890'),
('Marcus Webb', 'm.webb@nebula.example', 'Finance', 112000, '442-19-3317'),
('Yara Okafor', 'y.okafor@nebula.example', 'People', 87000, '703-55-1102');
