#!/bin/sh
set -e

# Wait for Postgres (compose depends_on also gates this, but be defensive).
echo "[entrypoint] waiting for database..."
until pg_isready -d "$DATABASE_URL" >/dev/null 2>&1; do
  sleep 1
done

# Create the DB (if new), run migrations, and seed on a fresh database.
# On `restore` (recreate) the pgdata volume is dropped, so this re-seeds cleanly.
echo "[entrypoint] preparing database..."
bin/rails db:prepare

rm -f /app/tmp/pids/server.pid 2>/dev/null || true

echo "[entrypoint] starting rails..."
exec "$@"
