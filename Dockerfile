# ============================================================
#  SimCity — Image Docker (PHP 8.3 + Apache)
#  Extensions : pdo_mysql (base) + ldap (authentification AD)
# ============================================================
FROM php:8.3-apache

# Extension ldap : nécessite les en-têtes OpenLDAP à la compilation
RUN apt-get update \
 && apt-get install -y --no-install-recommends libldap2-dev \
 && docker-php-ext-configure ldap --with-libdir=lib/$(uname -m)-linux-gnu \
 && docker-php-ext-install -j"$(nproc)" pdo_mysql ldap \
 && rm -rf /var/lib/apt/lists/*

# Modules Apache utilisés par le .htaccess (règles de réécriture + en-têtes)
RUN a2enmod rewrite headers

COPY . /var/www/html/

# Active la protection Apache (le dépôt versionne « htaccess » sans point)
RUN mv /var/www/html/htaccess /var/www/html/.htaccess \
 && mkdir -p /var/www/html/uploads /var/www/html/backups \
 && chown -R www-data:www-data /var/www/html/uploads /var/www/html/backups
