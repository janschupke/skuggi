#!/usr/bin/env bash
# CivicGov one-shot installer.
#
# Waits for the shared Drupal codebase, installs Drupal against Postgres with a
# known admin account via drush, enables the planted civicgov_tools module, and
# (re)seeds the citizen PII table. Idempotent: a second boot is a no-op. Exits 0
# and stays down (compose: restart "no").
set -euo pipefail

cd /opt/drupal

echo "[civicgov-init] waiting for the Drupal codebase on the shared volume..."
for _ in $(seq 1 60); do
  [ -f web/sites/default/default.settings.php ] && break
  sleep 2
done

# If a previous boot already installed the site, do nothing.
if drush status --field=bootstrap 2>/dev/null | grep -qiE 'success'; then
  echo "[civicgov-init] site already installed; nothing to do."
  exit 0
fi

echo "[civicgov-init] preparing a writable settings.php for the installer..."
install -d -m 0755 web/sites/default
cp -n web/sites/default/default.settings.php web/sites/default/settings.php || true
chmod 0666 web/sites/default/settings.php

echo "[civicgov-init] installing Drupal (drush site:install)..."
# The 'minimal' profile (not 'standard') keeps the install lean and avoids the
# standard profile's node/comment field config, whose orphaned 'comment' field
# type otherwise breaks the subsequent `pm:enable`. The lab's SQLi target is our
# own civicgov_citizens table (and a UNION pivot into users_field_data), so no
# content types are needed.
drush site:install minimal \
  --yes \
  --db-url="pgsql://${DB_USER}:${DB_PASS}@db:5432/${DB_NAME}" \
  --site-name="CivicGov Municipal Portal" \
  --account-name="${DRUPAL_ADMIN_USER}" \
  --account-pass="${DRUPAL_ADMIN_PASS}" \
  --account-mail="admin@civicgov.lab"

echo "[civicgov-init] enabling the planted civicgov_tools module..."
drush pm:enable civicgov_tools --yes

echo "[civicgov-init] seeding citizen PII (drush drops tables during install, so reseed now)..."
drush sql:query --file=/civicgov-seed.sql

echo "[civicgov-init] fixing permissions so apache (www-data) can serve the site..."
chown -R www-data:www-data web/sites/default
chmod 0444 web/sites/default/settings.php

drush cache:rebuild
echo "[civicgov-init] done."
