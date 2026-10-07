FROM drupal:10-apache

# Build-time only (no runtime egress): drush for the one-shot installer, curl for
# the healthcheck, sudo for the planted privesc misconfig, and the pg client.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl sudo postgresql-client; \
    rm -rf /var/lib/apt/lists/*; \
    composer require drush/drush --no-interaction; \
    composer clear-cache

# ── planted easy-privesc (vector K) ──────────────────────────────────────────
# www-data (the account a web RCE lands as) may run find as root with no
# password — a textbook GTFOBins escalation once a foothold exists.
RUN printf 'www-data ALL=(root) NOPASSWD: /usr/bin/find\n' > /etc/sudoers.d/civicgov \
    && chmod 0440 /etc/sudoers.d/civicgov

# ── crown jewel: root-only municipal master key, readable only after privesc ──
RUN printf 'CIVICGOV-MASTER-KEY: %s\n' 'mk_live_7f3c9a21e8b64d05a1f29c4e' > /root/master.key \
    && chmod 0600 /root/master.key

EXPOSE 80
