-- QuickDesk schema + seed. Runs once on an empty data volume.
CREATE DATABASE IF NOT EXISTS quickdesk;
USE quickdesk;

-- Least-privilege app account the PHP front end connects as.
CREATE USER IF NOT EXISTS 'quickdesk_app'@'%' IDENTIFIED BY 'app-db-pw-2024';
GRANT SELECT ON quickdesk.* TO 'quickdesk_app'@'%';
FLUSH PRIVILEGES;

CREATE TABLE users (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password CHAR(32)    NOT NULL,      -- unsalted MD5 (deliberately weak)
  role     VARCHAR(16) NOT NULL,
  email    VARCHAR(128) NOT NULL
);

-- Passwords are unsalted MD5: letmein123 / batman / Summer2023.
INSERT INTO users (username, password, role, email) VALUES
  ('admin', '4ca7c5c27c2314eecc71f67501abb724', 'admin', 'admin@quickdesk.lab'),
  ('jdoe',  'ec0e2603172c73a8b644bb9456c1ff6e', 'agent', 'jdoe@quickdesk.lab'),
  ('mchen', 'fd56e30c3b64536939f3c4879f2b6946', 'agent', 'mchen@quickdesk.lab');

CREATE TABLE customers (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(128) NOT NULL,
  email      VARCHAR(128) NOT NULL,
  phone      VARCHAR(32)  NOT NULL,
  card_last4 CHAR(4)      NOT NULL,
  mrr        INT          NOT NULL
);

INSERT INTO customers (name, email, phone, card_last4, mrr) VALUES
  ('Brightwater Logistics', 'e.okonkwo@brightwater-logistics.example', '+1-415-555-0142', '4417', 2400),
  ('Meridian Freight',      'p.raman@meridian-freight.example',        '+1-312-555-0178', '9021', 1850),
  ('Harbour & Vale LLP',    'accounts@harbour-vale.example',           '+44-20-7946-0991','3376', 3200),
  ('Solstice Media Group',  'billing@solstice-media.example',          '+1-646-555-0119', '1180', 990);
