FROM php:8.2-apache

# curl: healthcheck. openssh-client: lets the operator pivot from an edge
# foothold straight to the internal vault host over 10.21.12.0/24.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY src/ /var/www/html/

# The release-asset directory must be writable by the web user so an upload
# (vector C) can land a webshell there.
RUN mkdir -p /var/www/html/uploads \
    && chown -R www-data:www-data /var/www/html/uploads

# Deploy-agent config holding the svc password that is REUSED on the vault host.
# World-readable so a www-data webshell can exfiltrate it.
COPY deploy.conf /opt/vaultline/deploy.conf
RUN chmod 0644 /opt/vaultline/deploy.conf

EXPOSE 80
