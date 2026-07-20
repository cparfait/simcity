<?php
// ============================================================
//  SimCity — Configuration centralisée
//  ⚠️  Ce fichier contient des informations sensibles.
//      Placez-le HORS du répertoire public (webroot) si possible,
//      ou protégez-le via .htaccess (voir ci-dessous).
// ============================================================

// ─── Version de l'application ─────────────────────────────────
define('APP_VERSION', '1.0');

// ─── Connexion MySQL ──────────────────────────────────────────
// Les identifiants sont lus depuis les variables d'environnement si elles
// existent, sinon on utilise les valeurs de repli (pratique en local).
// → Un SEUL config.php fonctionne en local ET en conteneur Docker :
//    • Laragon / WAMP / XAMPP : aucune variable définie → repli localhost/root/(vide)
//    • Docker : injectez DB_HOST, DB_USER, DB_PASS… via docker-compose (environment:)
//      Exemple :  environment: { DB_HOST: simcity_db, DB_USER: simcity, DB_PASS: secret }
define('DB_HOST',    getenv('DB_HOST') ?: 'localhost');
define('DB_NAME',    getenv('DB_NAME') ?: 'simcity_db');
define('DB_USER',    getenv('DB_USER') ?: 'root');
define('DB_PASS',    getenv('DB_PASS') ?: '');
define('DB_CHARSET', 'utf8mb4');

// ─── Session ─────────────────────────────────────────────────
define('SESSION_LIFETIME', 3600);   // Durée de session en secondes (1 heure)
define('SESSION_NAME',     'simcity_sess');

// ─── Localisation ─────────────────────────────────────────────
// Fuseau horaire appliqué à tous les horodatages (bons, signatures, logs).
define('APP_TIMEZONE', 'Europe/Paris');

// ─── HTTPS ────────────────────────────────────────────────────
// true = force la redirection http → https (serveur direct avec certificat).
// Derrière un reverse proxy qui termine le TLS : laisser false (le proxy gère
// la redirection) et s'assurer qu'il transmet l'en-tête X-Forwarded-Proto.
// Surchargeable par la variable d'environnement FORCE_HTTPS (true/false).
define('FORCE_HTTPS', filter_var(getenv('FORCE_HTTPS') ?: 'false', FILTER_VALIDATE_BOOLEAN));

// ─── Sécurité ─────────────────────────────────────────────────
define('CSRF_TOKEN_NAME', '_csrf');

// ─── Authentification LDAP / Active Directory ─────────────────
// Cohabite avec les comptes locaux : on tente d'abord le mot de passe local,
// puis (si activé) un bind LDAP. Un utilisateur AD valide est provisionné
// automatiquement (jamais super-admin). Mêmes variables que Sentinelle.
// Nécessite l'extension PHP « ldap » (php.ini : extension=ldap).
define('LDAP_ENABLED',      filter_var(getenv('LDAP_ENABLED') ?: 'false', FILTER_VALIDATE_BOOLEAN));
define('LDAP_SERVER',       getenv('LDAP_SERVER') ?: '');        // ex: dc.chatillon.lan ou ldaps://dc.chatillon.lan
define('LDAP_PORT',         (int)(getenv('LDAP_PORT') ?: 0));    // 0 = auto (389, ou 636 en LDAPS)
define('LDAP_USE_SSL',      filter_var(getenv('LDAP_USE_SSL') ?: 'false', FILTER_VALIDATE_BOOLEAN)); // LDAPS
// Validation du certificat serveur en LDAPS (false si CA interne/auto-signée)
define('LDAP_VALIDATE_CERT', filter_var(getenv('LDAP_VALIDATE_CERT') ?: 'true', FILTER_VALIDATE_BOOLEAN));
define('LDAP_CA_CERT',      getenv('LDAP_CA_CERT') ?: '');       // chemin d'un fichier CA (PEM), optionnel
define('LDAP_DOMAIN',       getenv('LDAP_DOMAIN') ?: '');        // ex: chatillon.lan (bind UPN user@domaine)
define('LDAP_BASE_DN',      getenv('LDAP_BASE_DN') ?: '');       // ex: DC=chatillon,DC=lan
// Restriction d'accès à un groupe AD (fortement conseillé) : DN complet ou nom simple (cn)
define('LDAP_REQUIRED_GROUP',   getenv('LDAP_REQUIRED_GROUP') ?: '');
define('LDAP_USER_DN_TEMPLATE', getenv('LDAP_USER_DN_TEMPLATE') ?: ''); // alternative au bind UPN, ex: CN={username},OU=Users,DC=...
// Compte de service (optionnel) : utilisé uniquement par le bouton « Tester »
define('LDAP_BIND_USER',     getenv('LDAP_BIND_USER') ?: '');    // ex: svc-simcity@chatillon.lan
define('LDAP_BIND_PASSWORD', getenv('LDAP_BIND_PASSWORD') ?: '');

// ─── Uploads ─────────────────────────────────────────────────
define('UPLOAD_DIR',        'uploads/');
define('UPLOAD_MAX_BYTES',  1 * 1024 * 1024);  // 1 Mo
define('UPLOAD_ALLOWED_MIME', ['image/png','image/jpeg','image/gif','image/webp']);
// Les SVG sont retirés des MIME autorisés pour éviter les injections XSS via SVG

// ─── Sauvegardes ──────────────────────────────────────────────
// Dossier des sauvegardes SQL sur le serveur (protégé du web par .htaccess).
define('BACKUP_DIR',        'backups/');
define('BACKUP_RETENTION',  7);   // Nombre de sauvegardes conservées (jours glissants)

// Sauvegarde automatique « sans cron » : déclenchée par le trafic web.
// Idéal en conteneur (pas de crontab). Une seule sauvegarde est créée par
// intervalle, quel que soit le nombre de visiteurs (verrou atomique en base).
define('BACKUP_AUTO',          true);
define('BACKUP_AUTO_INTERVAL', 86400);   // Intervalle minimal en secondes (86400 = 24 h)

// ─── Environnement ────────────────────────────────────────────
// false en production pour masquer les erreurs PHP.
// Surchargeable par la variable d'environnement APP_DEBUG (true/false).
define('APP_DEBUG', filter_var(getenv('APP_DEBUG') ?: 'false', FILTER_VALIDATE_BOOLEAN));
