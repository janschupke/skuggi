# CiviDoc — a genuine Symfony 6.4 app on php:8.2-apache, DocumentRoot = public/.
# Dependencies are resolved from packagist at BUILD time (network is allowed for
# the build only; the running lab makes no external calls).
FROM php:8.2-apache

# PHP extensions + build tools. pdo_pgsql is what Doctrine DBAL connects with.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpq-dev unzip git curl ca-certificates \
    && docker-php-ext-install pdo pdo_pgsql \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

# Composer (pinned major) straight from the official image.
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
ENV COMPOSER_ALLOW_SUPERUSER=1

WORKDIR /var/www/app

# Install PHP dependencies first so the layer caches independently of app code.
COPY composer.json ./
RUN composer install --no-interaction --no-progress --prefer-dist --no-scripts

# Application source.
COPY bin ./bin
COPY config ./config
COPY public ./public
COPY src ./src
COPY templates ./templates
COPY var ./var
COPY .env ./.env

# Seeded secret OUTSIDE the document root — the path-traversal exfiltration
# target (loot: db password in DATABASE_URL).
COPY secrets/cividoc.env /var/secrets/cividoc.env

# Serve public/ as the Apache document root.
COPY docker/000-default.conf /etc/apache2/sites-available/000-default.conf

# Writable runtime dirs (prod cache/log) + finalise autoload.
RUN mkdir -p var/cache var/log \
    && composer dump-autoload --optimize --no-interaction \
    && chown -R www-data:www-data var /var/secrets \
    && chmod -R 0770 var \
    && chmod 0640 /var/secrets/cividoc.env

EXPOSE 80
