#!/bin/sh
set -e
ssh-keygen -A
# Reused service account — its password is what the KeePass vault protects.
id svc-backup >/dev/null 2>&1 || useradd -m -s /bin/bash svc-backup
echo 'svc-backup:b7-KZ2p-Wq9x' | chpasswd
mkdir -p /home/svc-backup/contracts /home/svc-backup/backups
cp /seed/2026-Q3-customer-contracts.csv /home/svc-backup/contracts/
chown -R svc-backup:svc-backup /home/svc-backup
exec /usr/sbin/sshd -D -e
