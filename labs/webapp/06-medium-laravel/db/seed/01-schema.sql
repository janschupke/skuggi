-- LumenPay schema + seed. Runs once on an empty MySQL data volume.
CREATE DATABASE IF NOT EXISTS lumenpay;
USE lumenpay;

-- Least-privilege app account the Laravel front end connects as
-- (matches DB_USERNAME / DB_PASSWORD in the app's .env).
CREATE USER IF NOT EXISTS 'lumenpay_app'@'%' IDENTIFIED BY 'lumenpay-db-pw-2024';
GRANT SELECT, INSERT, UPDATE, DELETE ON lumenpay.* TO 'lumenpay_app'@'%';
FLUSH PRIVILEGES;

-- Merchants onboarded onto the billing platform.
CREATE TABLE merchants (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(128) NOT NULL,
  contact_email VARCHAR(128) NOT NULL,
  plan          VARCHAR(32)  NOT NULL,
  status        VARCHAR(16)  NOT NULL
);

INSERT INTO merchants (name, contact_email, plan, status) VALUES
  ('Brightwater Logistics', 'e.okonkwo@brightwater-logistics.example', 'Scale',   'active'),
  ('Meridian Freight',      'p.raman@meridian-freight.example',        'Growth',  'active'),
  ('Harbour & Vale LLP',    'accounts@harbour-vale.example',           'Scale',   'active'),
  ('Solstice Media Group',  'billing@solstice-media.example',          'Starter', 'past_due'),
  ('Northwind Analytics',   'ops@northwind-analytics.example',         'Growth',  'active');

-- End customers these merchants bill (card metadata + MRR).
CREATE TABLE customers (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  merchant_id INT          NOT NULL,
  name        VARCHAR(128) NOT NULL,
  email       VARCHAR(128) NOT NULL,
  card_last4  CHAR(4)      NOT NULL,
  mrr         INT          NOT NULL
);

INSERT INTO customers (merchant_id, name, email, card_last4, mrr) VALUES
  (1, 'Okonkwo Holdings',    'e.okonkwo@brightwater-logistics.example', '4417', 2400),
  (2, 'Raman Imports',       'p.raman@meridian-freight.example',        '9021', 1850),
  (3, 'Harbour & Vale LLP',  'accounts@harbour-vale.example',           '3376', 3200),
  (4, 'Solstice Media Group','billing@solstice-media.example',          '1180', 990),
  (5, 'Northwind Analytics', 'ops@northwind-analytics.example',         '5562', 1500);
