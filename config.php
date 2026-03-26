<?php
// ============================================================
//  SimCity — Configuration centralisée
//  ⚠️  Ce fichier contient des informations sensibles.
//      Placez-le HORS du répertoire public (webroot) si possible,
//      ou protégez-le via .htaccess (voir ci-dessous).
// ============================================================

// ─── Connexion MySQL ──────────────────────────────────────────
define('DB_HOST',    'localhost');
define('DB_NAME',    'telephonie_mobile');
define('DB_USER',    'root');       // ← À modifier
define('DB_PASS',    '');           // ← À modifier
define('DB_CHARSET', 'utf8mb4');

// ─── Session ─────────────────────────────────────────────────
define('SESSION_LIFETIME', 3600);   // Durée de session en secondes (1 heure)
define('SESSION_NAME',     'simcity_sess');

// ─── Sécurité ─────────────────────────────────────────────────
define('CSRF_TOKEN_NAME', '_csrf');

// ─── Uploads ─────────────────────────────────────────────────
define('UPLOAD_DIR',        'uploads/');
define('UPLOAD_MAX_BYTES',  1 * 1024 * 1024);  // 1 Mo
define('UPLOAD_ALLOWED_MIME', ['image/png','image/jpeg','image/gif','image/webp']);
// Les SVG sont retirés des MIME autorisés pour éviter les injections XSS via SVG

// ─── Environnement ────────────────────────────────────────────
// Passer à false en production pour masquer les erreurs PHP
define('APP_DEBUG', false);
