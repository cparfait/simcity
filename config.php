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
define('DB_HOST',    'simcity_db');
define('DB_NAME',    'simcity_db');
define('DB_USER',    'root');       // ← À modifier
define('DB_PASS',    'root');           // ← À modifier
define('DB_CHARSET', 'utf8mb4');

// ─── Session ─────────────────────────────────────────────────
define('SESSION_LIFETIME', 3600);   // Durée de session en secondes (1 heure)
define('SESSION_NAME',     'simcity_sess');

// ─── Localisation ─────────────────────────────────────────────
// Fuseau horaire appliqué à tous les horodatages (bons, signatures, logs).
define('APP_TIMEZONE', 'Europe/Paris');

// ─── HTTPS ────────────────────────────────────────────────────
// Passer à true en production : force la redirection http → https.
// Laisser false en développement local (Laragon en http).
define('FORCE_HTTPS', false);

// ─── Sécurité ─────────────────────────────────────────────────
define('CSRF_TOKEN_NAME', '_csrf');

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
// Passer à false en production pour masquer les erreurs PHP
define('APP_DEBUG', false);
