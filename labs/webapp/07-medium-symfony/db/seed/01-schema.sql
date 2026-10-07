-- CiviDoc schema + seed (PostgreSQL). Runs once, as POSTGRES_USER, on an empty
-- data volume (postgres:16 reads /docker-entrypoint-initdb.d/*.sql in order).
--
-- Three tenants share one CiviDoc instance. The app connects as the `cividoc`
-- role (the database owner) — deliberately broad for a teaching lab.

-- ---------------------------------------------------------------------------
-- Tenants (the SaaS customers). billing_email is the per-account billing PII.
-- ---------------------------------------------------------------------------
CREATE TABLE tenant (
    id            INTEGER PRIMARY KEY,
    name          VARCHAR(128) NOT NULL,
    billing_email VARCHAR(128) NOT NULL,
    plan          VARCHAR(32)  NOT NULL
);

INSERT INTO tenant (id, name, billing_email, plan) VALUES
    (1, 'Harbor Ledger Group', 'a.stein@harbor-ledger.example',        'business'),
    (2, 'Nordvik Maritime',    'g.halvorsen@nordvik-maritime.example', 'enterprise'),
    (3, 'Pike & Rosen Advisory','accounts@pike-rosen.example',         'business');

-- ---------------------------------------------------------------------------
-- Portal users. password_sha256 is an UNSALTED SHA-256 of the plaintext
-- (deliberately legacy). The login path concatenates `email` into raw SQL, so
-- the password column is not actually the weak link here — the query is.
-- ---------------------------------------------------------------------------
CREATE TABLE app_user (
    id              INTEGER PRIMARY KEY,
    email           VARCHAR(128) NOT NULL UNIQUE,
    display_name    VARCHAR(128) NOT NULL,
    password_sha256 CHAR(64)     NOT NULL,
    role            VARCHAR(16)  NOT NULL,
    tenant_id       INTEGER      NOT NULL REFERENCES tenant(id)
);

-- Plaintexts (NOT in stock wordlists — medium tier): see solution.md.
--   admin@cividoc.lab               -> Civi!Doc-Adm1n-26
--   j.okafor@harbor-ledger.example  -> Harbor-Ledger!7788
--   g.halvorsen@nordvik-maritime... -> Nordvik-Mar1time#42
--   m.rossi@pike-rosen.example      -> Pike&Rosen-2026
INSERT INTO app_user (id, email, display_name, password_sha256, role, tenant_id) VALUES
    (1, 'admin@cividoc.lab',               'CiviDoc Platform Admin', '9edf0a71c3b47e03f01c995a862c5657e02194ec2f71fd5062c38f2eb0753bfb', 'admin', 1),
    (2, 'j.okafor@harbor-ledger.example',  'Joy Okafor',             '06aea54876caaeef1652a312d021dea858c2ff75097f8f2ace09d364a4897c71', 'member', 1),
    (3, 'g.halvorsen@nordvik-maritime.example', 'Greta Halvorsen',   'fe949d9f620b1731dc0c37f46c5c53c36e1227600b2835f893b33cc3d7c23531', 'member', 2),
    (4, 'm.rossi@pike-rosen.example',      'Marco Rossi',            '91242c2e698c2a593465d9f3950e345f582bf91f3269b20eaa341328d3d36f32', 'member', 3);

-- ---------------------------------------------------------------------------
-- Invoices. Ids are a shared sequence across tenants — the /api/invoices/{id}
-- endpoint never scopes by tenant, so iterating ids walks every tenant's book.
-- ---------------------------------------------------------------------------
CREATE TABLE invoice (
    id            INTEGER PRIMARY KEY,
    tenant_id     INTEGER     NOT NULL REFERENCES tenant(id),
    number        VARCHAR(32) NOT NULL,
    customer_name VARCHAR(128) NOT NULL,
    billing_email VARCHAR(128) NOT NULL,
    amount_cents  INTEGER     NOT NULL,
    status        VARCHAR(16) NOT NULL,
    issued_on     DATE        NOT NULL
);

INSERT INTO invoice (id, tenant_id, number, customer_name, billing_email, amount_cents, status, issued_on) VALUES
    (1001, 1, 'HLG-2026-0007', 'Harbor Ledger Group', 'a.stein@harbor-ledger.example',        248000, 'paid',   '2026-01-14'),
    (1002, 2, 'NMA-2026-0031', 'Nordvik Maritime',    'g.halvorsen@nordvik-maritime.example', 912500, 'overdue','2026-02-02'),
    (1003, 3, 'PRA-2026-0004', 'Pike & Rosen Advisory','accounts@pike-rosen.example',          63000, 'sent',   '2026-02-19'),
    (1004, 1, 'HLG-2026-0009', 'Harbor Ledger Group', 'a.stein@harbor-ledger.example',        118000, 'sent',   '2026-03-01'),
    (1005, 2, 'NMA-2026-0033', 'Nordvik Maritime',    'g.halvorsen@nordvik-maritime.example', 455000, 'paid',   '2026-03-08');

-- ---------------------------------------------------------------------------
-- Documents. `filename` is the on-disk name the download controller joins to
-- its base dir (var/documents) — with no normalisation (path-traversal seam).
-- ---------------------------------------------------------------------------
CREATE TABLE document (
    id           INTEGER PRIMARY KEY,
    tenant_id    INTEGER      NOT NULL REFERENCES tenant(id),
    title        VARCHAR(128) NOT NULL,
    filename     VARCHAR(128) NOT NULL,
    confidential BOOLEAN      NOT NULL DEFAULT false
);

INSERT INTO document (id, tenant_id, title, filename, confidential) VALUES
    (2001, 1, 'Welcome to CiviDoc',          'welcome-cividoc.txt',   false),
    (2002, 1, 'Harbor Ledger — invoice 0007','invoice-HLG-2026-0007.txt', true),
    (2003, 2, 'Nordvik Maritime — MSA 2026', 'msa-nordvik-2026.txt',  true),
    (2004, 3, 'Pike & Rosen — engagement',   'engagement-pike-rosen.txt', true);
