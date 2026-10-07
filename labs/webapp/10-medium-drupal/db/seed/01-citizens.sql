-- CivicGov citizen benefit records — seeded PII (vector F).
--
-- Runs twice, idempotently: once by Postgres on first boot (from
-- /docker-entrypoint-initdb.d), then again by the init container AFTER
-- `drush site:install` (which drops every table in the schema to install
-- Drupal). The post-install run is the one that makes the table pristine.
--
-- The table lives in Drupal's own database, so the civicgov_tools SQLi route
-- (which queries via \Drupal::database()) reads it directly.
DROP TABLE IF EXISTS civicgov_citizens;
CREATE TABLE civicgov_citizens (
  id             SERIAL PRIMARY KEY,
  full_name      TEXT NOT NULL,
  national_id    TEXT NOT NULL,
  email          TEXT NOT NULL,
  address        TEXT NOT NULL,
  benefit_status TEXT NOT NULL
);

INSERT INTO civicgov_citizens (full_name, national_id, email, address, benefit_status) VALUES
  ('Maeve O''Halloran', 'IRL-8841-20193',  'm.ohalloran@mailbox.example',  '14 Coombe Street, Dublin 8',    'housing-assistance'),
  ('Tomas Lindqvist',   'SE-640512-8821',  't.lindqvist@postbox.example',  '3 Vasagatan, Gothenburg',       'unemployment'),
  ('Priya Raman',       'UK-NI-RJ882190C', 'p.raman@mailworks.example',    '27 Elm Row, Leeds LS2',         'disability-support'),
  ('Dmitri Volkov',     'DE-1988-553102',  'd.volkov@inbox.example',       '9 Kastanienallee, Berlin',      'child-benefit'),
  ('Aisha Nurse',       'US-SSN-5521903',  'a.nurse@webmail.example',      '118 Franklin Ave, Newark NJ',   'pension-credit');
