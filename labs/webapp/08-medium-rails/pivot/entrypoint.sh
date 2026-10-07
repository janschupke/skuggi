#!/bin/sh
set -e
ssh-keygen -A

# The 'deploy' ops account. Its password is the SAME secret the Rails app leaks
# in /app/config/ops_credentials.yml -> classic credential reuse (vector I).
id deploy >/dev/null 2>&1 || useradd -m -s /bin/bash deploy
echo 'deploy:D3ploy-0ps-Tr4ck-2026' | chpasswd

# Easy privesc (vector K): deploy may run find as root with NO password.
#   sudo find . -exec /bin/sh \; -quit    -> root shell (GTFOBins)
printf 'deploy ALL=(root) NOPASSWD: /usr/bin/find\n' > /etc/sudoers.d/deploy
chmod 0440 /etc/sudoers.d/deploy

# Crown jewel: readable only by root (reached after the find privesc).
install -m 0600 -o root -g root /seed/crown_jewels.txt /root/crown_jewels.txt

# A breadcrumb in deploy's home that points at the rest of the ops estate.
mkdir -p /home/deploy
cat > /home/deploy/README.ops <<'EOF'
TrackRails ops host (ops.trackrails.lab).
Release pipeline runs as 'deploy'. Root tasks go through the limited sudo rule
(see `sudo -l`). Production master key lives in /root/crown_jewels.txt.
EOF
chown -R deploy:deploy /home/deploy

exec /usr/sbin/sshd -D -e
