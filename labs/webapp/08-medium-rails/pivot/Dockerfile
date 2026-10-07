FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server passwd sudo findutils \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
COPY crown_jewels.txt /seed/crown_jewels.txt
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
