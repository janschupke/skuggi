#!/usr/bin/env bash
# LearnHub seeder (one-shot). Runs after Moodle's first-boot install.
#
# Why a sidecar and not a docker-entrypoint-initdb.d SQL file: the mdl_* schema
# does not exist until Moodle finishes installing, which happens long AFTER the
# MariaDB init phase. So we poll for the admin row, then INSERT.
#
# Plants (vectors F + H):
#   - extra low-priv student accounts with realistic PII (names, emails),
#     dumpable straight from mdl_user.email  (loot: student-pii).
#   - bcrypt ($2y$) password hashes on those accounts (loot: password-hashes;
#     the Moodle admin row already carries a $2y$ hash, so this holds even if
#     seeding is skipped).
#   - a raw <script> payload in one student's profile DESCRIPTION field — the
#     seeded stored-XSS record (vector H). Whether it survives to the rendered
#     /user/profile.php page depends on Moodle's output sanitizer; see solution.md.
set -euo pipefail

DB_HOST="${DB_HOST:-db}"
DB_NAME="${DB_NAME:-bitnami_moodle}"
DB_ROOT_PW="${DB_ROOT_PW:-root-learnhub-2024}"

mysql() { mariadb -h "$DB_HOST" -uroot -p"$DB_ROOT_PW" "$DB_NAME" "$@"; }

echo "[seed] waiting for Moodle install to finish (mdl_user + admin row)..."
for i in $(seq 1 120); do
  if mysql -N -e "SELECT COUNT(*) FROM mdl_user WHERE username='admin'" 2>/dev/null | grep -q '^1$'; then
    echo "[seed] Moodle schema is ready (attempt $i)."
    break
  fi
  sleep 5
  if [ "$i" -eq 120 ]; then
    echo "[seed] ERROR: timed out waiting for the Moodle schema." >&2
    exit 1
  fi
done

# Idempotency guard: if the first seeded student already exists, do nothing.
if mysql -N -e "SELECT COUNT(*) FROM mdl_user WHERE username='mlindqvist'" 2>/dev/null | grep -q '^1$'; then
  echo "[seed] students already present — nothing to do."
  exit 0
fi

echo "[seed] inserting student PII + stored-XSS profile record..."
mysql <<'SQL'
SET @mnet = (SELECT value FROM mdl_config WHERE name = 'mnet_localhost_id');
SET @now  = UNIX_TIMESTAMP();

-- Four realistic student accounts. Passwords are bcrypt ($2y$) — the hashes are
-- fake-but-well-formed; these accounts are PII targets, not login targets.
-- descriptionformat = 1 (FORMAT_HTML).
INSERT INTO mdl_user
  (auth, confirmed, policyagreed, deleted, suspended, mnethostid,
   username, password, idnumber, firstname, lastname, email,
   city, country, lang, calendartype, timezone,
   description, descriptionformat, maildisplay,
   timecreated, timemodified)
VALUES
  -- The low-priv student test account the engagement was issued (see briefing.md).
  -- Real bcrypt of 'Student!2026' (htpasswd -B, cost 10) so the login genuinely works.
  ('manual',1,1,0,0,@mnet,
   'jrowan','$2y$10$Yju5EeKqpT1nBuIroMRs.eoBkozVEipkIHAMJR4d9dmpA4Sb3ISA.','S100001',
   'Jess','Rowan','jess.rowan@northvale-students.example',
   'Bristol','GB','en','gregorian','99',
   'Pentest test account.',1,1,
   @now,@now),

  ('manual',1,1,0,0,@mnet,
   'mlindqvist','$2y$10$N9kPq2WmXrLtZbVcDfHjGueO3sT1yR7wQ5aB9cD2fE4gH6iJ8kL0m','S100423',
   'Maya','Lindqvist','maya.lindqvist@northvale-students.example',
   'Gothenburg','SE','en','gregorian','99',
   'Second-year data science. Reach me about the stats study group.',1,1,
   @now,@now),

  ('manual',1,1,0,0,@mnet,
   'dokafor','$2y$10$Tp7Rk3LmQw9ZbVcDfHjGuNeO1sT5yR2wQ8aB4cD6fE0gH3iJ7kL9mP','S100887',
   'Daniel','Okafor','daniel.okafor@northvale-students.example',
   'Leeds','GB','en','gregorian','99',
   'Exchange student, MSc Networks.',1,1,
   @now,@now),

  ('manual',1,1,0,0,@mnet,
   'achaudhry','$2y$10$Zb2VcDfHjGuNeO3sT1yR7.wQ5aB9cD2fE4gH6iJ8kL0mPq7RkLmQw','S101295',
   'Aisha','Chaudhry','aisha.chaudhry@northvale-students.example',
   'Manchester','GB','en','gregorian','99',
   'TA for Intro to Programming.',1,1,
   @now,@now),

  -- The stored-XSS record (vector H): a raw <script> payload in the profile bio.
  ('manual',1,1,0,0,@mnet,
   'tnovak','$2y$10$Fh5JkLmN2pQrStUvWxYz0.eCdEfGhIjKlMnOpQrStUvWxYz01234ab','S101640',
   'Tomas','Novak','tomas.novak@northvale-students.example',
   'Brno','CZ','en','gregorian','99',
   '<p>Hi all!</p><script>alert(document.domain)</script><p>DM me about the robotics club.</p>',1,1,
   @now,@now);
SQL

echo "[seed] done. Seeded students:"
mysql -N -e "SELECT username, email FROM mdl_user WHERE idnumber LIKE 'S10%'"
