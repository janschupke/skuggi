# LumenPay (medium) — a genuine Laravel app on php:8.2-apache + MySQL.
# The Laravel skeleton is created at BUILD time with `composer create-project`
# (network is permitted during build), then our vulnerable controller, routes,
# views and .env are copied over it — so the result is authentically Laravel
# (artisan, routes/web.php, app/Http/Controllers, bootstrap/app.php, /up).
#
# INTENTIONALLY insecure. Loopback-only. Never expose this.

FROM php:8.2-apache

# --- PHP extensions + build tooling ------------------------------------------
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        curl unzip git sudo libzip-dev libonig-dev libsqlite3-dev; \
    docker-php-ext-install pdo_mysql mysqli zip pdo_sqlite; \
    rm -rf /var/lib/apt/lists/*

# Composer (pinned major) straight from the official image.
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# --- Create a real Laravel project at build time -----------------------------
# Pin to a recent, stable Laravel 11.x line for a deterministic build.
# --no-security-blocking: composer 2 now refuses, by default, to install any
# package with a published security advisory. Every current laravel/framework
# 11.x release carries one, so resolution fails without this flag — expected and
# fine here: insecure dependencies are rather the point of a practice target.
# cd / first: the base image's WORKDIR is /var/www/html, and removing the cwd
# out from under the shell yields "Could not determine the current working
# directory" before composer even starts.
RUN set -eux; \
    cd /; \
    rm -rf /var/www/html; \
    COMPOSER_ALLOW_SUPERUSER=1 composer create-project \
        laravel/laravel:^11.0 /var/www/html \
        --no-interaction --prefer-dist --no-progress --no-security-blocking

WORKDIR /var/www/html

# --- Point Apache's DocumentRoot at Laravel's public/ ------------------------
ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
RUN set -eux; \
    sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf; \
    sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf; \
    a2enmod rewrite; \
    printf '<Directory ${APACHE_DOCUMENT_ROOT}>\n    Options -Indexes +FollowSymLinks\n    AllowOverride All\n    Require all granted\n</Directory>\n' > /etc/apache2/conf-available/laravel.conf; \
    a2enconf laravel

# --- Overlay the intentionally-vulnerable application code -------------------
# (controller + routes + views + a seeded .env). Authentically Laravel: these
# files sit in the standard skeleton locations.
COPY overlay/app/Http/Controllers/MerchantDocumentController.php /var/www/html/app/Http/Controllers/MerchantDocumentController.php
COPY overlay/routes/web.php /var/www/html/routes/web.php
COPY overlay/resources/views/welcome.blade.php /var/www/html/resources/views/welcome.blade.php
COPY overlay/resources/views/onboarding.blade.php /var/www/html/resources/views/onboarding.blade.php
COPY overlay/resources/views/directory.blade.php /var/www/html/resources/views/directory.blade.php
COPY overlay/bootstrap/app.php /var/www/html/bootstrap/app.php
COPY overlay/.env /var/www/html/.env

# The web-reachable document store the upload controller writes into.
RUN set -eux; \
    install -d -o www-data -g www-data /var/www/html/public/uploads/kyc; \
    chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache /var/www/html/public/uploads

# --- Planted privilege-escalation misconfig (vector K) -----------------------
# A left-behind deploy sudoers drop-in lets the web user (www-data, which the
# uploaded webshell runs as) become root without a password. The gateway
# signing key is root-only, so it is only reachable AFTER the privesc.
COPY secrets/payment_gateway.key /opt/lumenpay/secrets/payment_gateway.key
RUN set -eux; \
    chown -R root:root /opt/lumenpay; \
    chmod 700 /opt/lumenpay/secrets; \
    chmod 600 /opt/lumenpay/secrets/payment_gateway.key; \
    printf 'www-data ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/90-lumenpay-deploy; \
    chmod 440 /etc/sudoers.d/90-lumenpay-deploy

EXPOSE 80
