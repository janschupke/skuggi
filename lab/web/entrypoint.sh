#!/bin/bash
# First-boot: initialize MariaDB data dir and seed the blog database against a
# temporary server (grants are rejected in --bootstrap mode), then hand off to
# supervisord which runs mariadbd + apache together on this one host.
set -euo pipefail

# Dedicated datadir (see mariadb-lab.cnf) — kept off the image's pre-initialized
# /var/lib/mysql so a fresh volume starts empty and triggers the seed below.
DATADIR=/var/lib/mysql-lab
SOCK=/run/mysqld/mysqld.sock

mkdir -p "$DATADIR"
chown -R mysql:mysql "$DATADIR"

# /run is ephemeral, so recreate the socket dir on every boot.
mkdir -p /run/mysqld
chown mysql:mysql /run/mysqld

if [ ! -d "$DATADIR/mysql" ]; then
    echo "[entrypoint] initializing MariaDB data directory"
    mariadb-install-db --user=mysql --datadir="$DATADIR" \
        --auth-root-authentication-method=normal >/dev/null

    echo "[entrypoint] starting temporary server for seeding"
    mariadbd --user=mysql --datadir="$DATADIR" --skip-networking --socket="$SOCK" &
    tmppid=$!
    for _ in $(seq 1 60); do
        mariadb-admin --socket="$SOCK" ping --silent >/dev/null 2>&1 && break
        sleep 1
    done

    echo "[entrypoint] seeding blog database (schema + data + accounts)"
    {
        echo "CREATE DATABASE IF NOT EXISTS blog;"
        echo "USE blog;"
        cat /seed/schema.sql
        cat /seed/seed.sql
        # Application account (weak on purpose; documented in docs/lab.md).
        echo "CREATE USER IF NOT EXISTS 'bloguser'@'localhost' IDENTIFIED BY 'blogpass123';"
        echo "CREATE USER IF NOT EXISTS 'bloguser'@'%'         IDENTIFIED BY 'blogpass123';"
        echo "GRANT ALL PRIVILEGES ON blog.* TO 'bloguser'@'localhost';"
        echo "GRANT ALL PRIVILEGES ON blog.* TO 'bloguser'@'%';"
        # A remotely-usable root with a trivial password — extra loot for the
        # MySQL service on :3306 (hydra/nmap mysql-brute).
        echo "CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY 'toor';"
        echo "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;"
        # Drop the password-less loopback root entries install-db creates, so all
        # TCP connections fall through to root@'%' (root/toor). root@localhost is
        # kept password-less for local socket administration.
        echo "DROP USER IF EXISTS 'root'@'127.0.0.1';"
        echo "DROP USER IF EXISTS 'root'@'::1';"
        echo "DROP USER IF EXISTS 'root'@'web.lab';"
        echo "FLUSH PRIVILEGES;"
    } | mariadb --socket="$SOCK"

    echo "[entrypoint] stopping temporary server"
    mariadb-admin --socket="$SOCK" shutdown
    wait "$tmppid" 2>/dev/null || true
    echo "[entrypoint] database ready"
else
    echo "[entrypoint] existing MariaDB data dir found — skipping seed"
fi

# The base image symlinks the access log to /dev/stdout; replace it with a real
# on-disk file so the LFI -> log-poisoning RCE path has a file to include, and
# make it readable/traversable by the PHP worker (www-data). error.log stays a
# symlink to /dev/stderr so container errors still surface in `docker logs`.
mkdir -p /var/log/apache2
rm -f /var/log/apache2/access.log /var/log/apache2/other_vhosts_access.log
touch /var/log/apache2/access.log
chmod 755 /var/log/apache2
chmod 644 /var/log/apache2/access.log
chown www-data:www-data /var/log/apache2/access.log

echo "[entrypoint] starting supervisord (mariadb + apache)"
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
