-- NetLedger schema + seed. Runs once (as the POSTGRES_USER superuser
-- "netledger") on first boot of an empty data volume, inside the "netledger"
-- database created by POSTGRES_DB.

-- Accountant logins. password_md5 is unsalted MD5 (deliberately weak); the
-- login endpoint is SQL-injectable, so these are the bypass targets.
--   admin     : Sup3r-L3dger-2024
--   a.ferran  : autumn2024
--   t.osei    : Passw0rd!
CREATE TABLE users (
  id           SERIAL PRIMARY KEY,
  username     VARCHAR(64)  NOT NULL UNIQUE,
  password_md5 CHAR(32)     NOT NULL,
  role         VARCHAR(16)  NOT NULL,
  email        VARCHAR(128) NOT NULL
);

INSERT INTO users (username, password_md5, role, email) VALUES
  ('admin',    'a462d193b59580a1c7c299ba8bdce8e0', 'admin',      'admin@netledger.lab'),
  ('a.ferran', 'ead018281e009007d0bf712e5e447cf8', 'accountant', 'a.ferran@netledger.lab'),
  ('t.osei',   '47b7bfb65fa83ac9a71dcb0f6296bb6e', 'accountant', 't.osei@netledger.lab');

-- Customer ledger: names, billing emails, phone, card last-4, balance (PII).
CREATE TABLE customers (
  id         SERIAL PRIMARY KEY,
  name       VARCHAR(128)  NOT NULL,
  email      VARCHAR(128)  NOT NULL,
  phone      VARCHAR(32)   NOT NULL,
  card_last4 CHAR(4)       NOT NULL,
  balance    NUMERIC(12,2) NOT NULL
);

INSERT INTO customers (name, email, phone, card_last4, balance) VALUES
  ('Northwind Trading Co', 'treasury@northwind-trading.example', '+1-206-555-0133', '1180', 12250.00),
  ('Pont-Neuf Capital',    'a.delacroix@pont-neuf-capital.example', '+33-1-5550-0142', '4417', 50200.00),
  ('Harbor Civic Trust',   'ap@harbor-civic.example',            '+1-312-555-0178', '9021',  3380.00),
  ('Lindqvist & Sons AB',  'billing@lindqvist-sons.example',     '+46-8-5550-0991', '3376', 18940.00);
