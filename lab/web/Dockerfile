# One host: Apache + PHP + MariaDB, managed by supervisord.
FROM php:8.2-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        mariadb-server \
        mariadb-client \
        supervisor \
        iputils-ping \
        curl \
        ca-certificates \
    && docker-php-ext-install mysqli \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

# Apache vhost (directory indexes on, for recon realism), MariaDB listens on all
# interfaces so 192.0.2.10:3306 is a scannable service, supervisor runs both.
COPY apache-vhost.conf /etc/apache2/sites-available/000-default.conf
COPY mariadb-lab.cnf   /etc/mysql/mariadb.conf.d/99-lab.cnf
COPY supervisord.conf  /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh     /usr/local/bin/entrypoint.sh

# Seed SQL, imported on first boot by the entrypoint.
COPY db/schema.sql /seed/schema.sql
COPY db/seed.sql   /seed/seed.sql

# The vulnerable application.
COPY app/ /var/www/html/

RUN chmod +x /usr/local/bin/entrypoint.sh \
    && chown -R www-data:www-data /var/www/html \
    && chmod 0777 /var/www/html/uploads

EXPOSE 80 3306
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
