FROM debian:12-slim

# openssh-server: the lateral-movement target. sudo + findutils: the privesc
# path. netcat-openbsd: container healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server passwd sudo findutils netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# The svc account. Its password is the SAME string stored in the edge host's
# /opt/vaultline/deploy.conf (DEPLOY_PASSWORD) — the whole point of vector I.
RUN useradd -m -s /bin/bash svc \
    && echo 'svc:V4ultL1ne-deploy-7e2a9c' | chpasswd

# VULN (vector K): svc may run find as root without a password. GTFOBins:
#   sudo find . -exec /bin/sh \; -quit   -> instant root shell.
RUN echo 'svc ALL=(ALL) NOPASSWD: /usr/bin/find' > /etc/sudoers.d/svc \
    && chmod 0440 /etc/sudoers.d/svc

# Crown jewels — root-only until the privesc above lands.
COPY crown_jewels.txt /root/crown_jewels.txt
RUN chmod 0600 /root/crown_jewels.txt \
    # Password SSH for svc; no root login (forces the privesc path).
    && sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -ri 's/^#?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
