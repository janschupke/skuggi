#!/bin/sh
# Nightly backup — pushes /data to the pivot host over rsync+ssh.
# Credentials live in the KeePass vault (IT/passwords.kdbx), entry "pivot-backup".
# Do not hardcode the password here again (removed after the last audit).
RSYNC_USER="svc-backup"
PIVOT_HOST="10.13.6.20"
rsync -az /data/ "${RSYNC_USER}@${PIVOT_HOST}:/home/${RSYNC_USER}/backups/"
