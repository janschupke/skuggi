#!/bin/sh
# First-boot: build migrations from the models, apply them, seed the portal,
# then serve with gunicorn. The seed is idempotent, so a restart is a no-op;
# a `restore` (recreate) drops the pgdata volume and reseeds from scratch.
set -e

# The compose `depends_on: condition: service_healthy` already gates us on a
# healthy Postgres, but keep a short guard so a slow socket never races migrate.
echo "[entrypoint] waiting for database ${DB_HOST}:5432 ..."
i=0
until python -c "import socket,os,sys; s=socket.socket(); s.settimeout(2); s.connect((os.environ['DB_HOST'],5432)); s.close()" 2>/dev/null; do
  i=$((i+1))
  if [ "$i" -ge 30 ]; then
    echo "[entrypoint] database never came up" >&2
    exit 1
  fi
  sleep 1
done

echo "[entrypoint] makemigrations + migrate ..."
python manage.py makemigrations billing --noinput
python manage.py migrate --noinput

echo "[entrypoint] seeding portal (idempotent) ..."
python manage.py seed_portal

echo "[entrypoint] starting gunicorn on :8000 ..."
exec gunicorn fernportal.wsgi:application --bind 0.0.0.0:8000 --workers 2 --access-logfile - --error-logfile -
