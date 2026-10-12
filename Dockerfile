# ============================================================
#  SimCity — Image Docker (PHP 8.3 + Apache)
#  Extensions : pdo_mysql (base) + ldap (authentification AD)
# ============================================================
FROM php:8.3-apache

# Extension ldap : nécessite les en-têtes OpenLDAP à la compilation.
# poppler-utils fournit pdftotext, utilisé par le module Facturation / Contrôle
# pour extraire le texte des factures PDF de l'opérateur.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libldap2-dev poppler-utils \
 && docker-php-ext-configure ldap --with-libdir=lib/$(uname -m)-linux-gnu \
 && docker-php-ext-install -j"$(nproc)" pdo_mysql ldap \
 && rm -rf /var/lib/apt/lists/*

# Modules Apache utilisés par le .htaccess (règles de réécriture + en-têtes)
RUN a2enmod rewrite headers

# Limites d'upload : import CSV (10 Mo) et dépôt groupé de factures PDF
# (plusieurs mois d'un coup) dépassent les 2 Mo / 8 Mo par défaut de PHP.
RUN printf 'upload_max_filesize = 20M\npost_max_size = 64M\nmax_file_uploads = 40\n' \
      > /usr/local/etc/php/conf.d/simcity-uploads.ini

# L'image php:apache honore le .htaccess, mais une base Apache configurée en
# « AllowOverride None » l'ignorerait silencieusement — config.php, reset.php
# et backups/ seraient alors servis en clair. On fixe donc explicitement la
# directive. « Options -Indexes » supprime le listing des répertoires.
RUN printf '<Directory /var/www/html>\n    AllowOverride All\n    Options -Indexes\n</Directory>\n' \
      > /etc/apache2/conf-available/simcity.conf \
 && a2enconf simcity

COPY . /var/www/html/

# Active la protection Apache (le dépôt versionne « htaccess » sans point)
RUN mv /var/www/html/htaccess /var/www/html/.htaccess \
 && mkdir -p /var/www/html/uploads /var/www/html/backups \
 && chown -R www-data:www-data /var/www/html/uploads /var/www/html/backups
