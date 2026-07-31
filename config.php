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

// Le repli « root / mot de passe vide » ne subsiste que pour un serveur MySQL
// local (Laragon, WAMP, XAMPP). Hors de ce cas — donc en conteneur, où DB_HOST
// désigne un autre hôte — une variable DB_USER oubliée doit faire échouer le
// démarrage bruyamment plutôt que de tenter silencieusement une connexion root
// sans mot de passe.
$__dbLocal = in_array(DB_HOST, ['localhost', '127.0.0.1', '::1'], true);
$__dbUser  = getenv('DB_USER');
$__dbPass  = getenv('DB_PASS');
if ($__dbUser === false || $__dbUser === '') {
    if (!$__dbLocal) {
        http_response_code(500);
        die('Configuration incomplète : la variable d\'environnement DB_USER est requise (DB_HOST=' . DB_HOST . ').');
    }
    $__dbUser = 'root';
    $__dbPass = '';
}
define('DB_USER',    $__dbUser);
define('DB_PASS',    $__dbPass === false ? '' : $__dbPass);
unset($__dbLocal, $__dbUser, $__dbPass);

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
// Se configure dans l'interface : Référentiels → Paramètres → carte
// « Authentification Active Directory » (stockage en base, table settings).
// En Docker, les variables d'environnement LDAP_* (mêmes noms que Sentinelle :
// LDAP_ENABLED, LDAP_SERVER, LDAP_PORT, LDAP_USE_SSL, LDAP_VALIDATE_CERT,
// LDAP_CA_CERT, LDAP_DOMAIN, LDAP_BASE_DN, LDAP_REQUIRED_GROUP, LDAP_ADMIN_GROUP,
// LDAP_BIND_USER, LDAP_BIND_PASSWORD) PRIMENT sur la
// base : le champ correspondant est alors verrouillé dans l'interface.
// Nécessite l'extension PHP « ldap » (php.ini : extension=ldap).

// ─── Uploads ─────────────────────────────────────────────────
define('UPLOAD_DIR',        'uploads/');
define('UPLOAD_MAX_BYTES',  1 * 1024 * 1024);  // 1 Mo
define('UPLOAD_ALLOWED_MIME', ['image/png','image/jpeg','image/gif','image/webp']);
// Les SVG sont retirés des MIME autorisés pour éviter les injections XSS via SVG

// ─── Sauvegardes ──────────────────────────────────────────────
// Dossier des sauvegardes SQL sur le serveur (protégé du web par .htaccess).
define('BACKUP_DIR',        'backups/');
define('BACKUP_RETENTION',  7);   // Nombre de sauvegardes conservées (jours glissants)

// Fichiers téléversés (PDF de factures, pièces jointes, logo) : archivés en
// tar.gz à côté du dump SQL du même horodatage. Sans cette archive, restaurer
// une sauvegarde désynchronise la base et le disque — lignes sans fichier
// d'un côté, fichiers orphelins de l'autre.
define('BACKUP_INCLUDE_FILES',   true);
// Rétention distincte : ces archives pèsent bien plus lourd qu'un dump SQL
// (les PDF de factures ne se compressent presque pas).
define('BACKUP_FILES_RETENTION', 3);
// Garde-fou : au-delà de cette taille, l'archive est ignorée et la sauvegarde
// SQL signale l'avertissement plutôt que de saturer le disque en silence.
define('BACKUP_FILES_MAX_BYTES', 500 * 1024 * 1024);   // 500 Mo

// Sauvegarde automatique « sans cron » : déclenchée par le trafic web.
// Idéal en conteneur (pas de crontab). Une seule sauvegarde est créée par
// intervalle, quel que soit le nombre de visiteurs (verrou atomique en base).
define('BACKUP_AUTO',          true);
define('BACKUP_AUTO_INTERVAL', 86400);   // Intervalle minimal en secondes (86400 = 24 h)

// ─── Environnement ────────────────────────────────────────────
// false en production pour masquer les erreurs PHP.
// Surchargeable par la variable d'environnement APP_DEBUG (true/false).
define('APP_DEBUG', filter_var(getenv('APP_DEBUG') ?: 'false', FILTER_VALIDATE_BOOLEAN));
