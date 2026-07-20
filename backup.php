<?php
// ============================================================
//  SimCity — Sauvegarde automatique (tâche planifiée / cron)
//
//  Crée une sauvegarde SQL dans BACKUP_DIR et applique la rotation
//  (BACKUP_RETENTION fichiers, cf. config.php).
//
//  ── Utilisation en CLI (recommandé pour le cron) ──
//    php /chemin/vers/simcity/backup.php
//
//    Exemple cron (chaque nuit à 2 h) :
//      0 2 * * * /usr/bin/php /var/www/simcity/backup.php >> /var/log/simcity_backup.log 2>&1
//
//    Sous Windows (Planificateur de tâches) :
//      php.exe C:\chemin\simcity\backup.php
//
//  ── Déclenchement HTTP (si le cron ne peut appeler PHP en CLI) ──
//    Définissez un jeton dans la variable d'environnement BACKUP_TOKEN
//    (ou ci-dessous) puis appelez :  https://votre-site/backup.php?token=XXXX
// ============================================================

require __DIR__ . '/config.php';
require __DIR__ . '/backup_lib.php';
date_default_timezone_set(defined('APP_TIMEZONE') ? APP_TIMEZONE : 'Europe/Paris');

$isCli = (PHP_SAPI === 'cli');

// ─── Protection de l'accès HTTP ───────────────────────────────
if (!$isCli) {
    // Jeton attendu : variable d'environnement BACKUP_TOKEN (non vide).
    $expected = getenv('BACKUP_TOKEN') ?: '';
    $given    = $_GET['token'] ?? '';
    if ($expected === '' || !hash_equals($expected, (string)$given)) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Accès refusé. Définissez la variable d'environnement BACKUP_TOKEN et appelez ?token=…\n";
        exit;
    }
    header('Content-Type: text/plain; charset=utf-8');
}

// ─── Exécution ────────────────────────────────────────────────
try {
    $pdo = new PDO(
        "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET,
        DB_USER, DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
    $name = simcity_backup_to_disk($pdo);
    $kept = count(simcity_list_backups());
    $msg  = "[" . date('Y-m-d H:i:s') . "] OK — sauvegarde créée : $name ($kept fichier(s) conservé(s)).";
    if ($isCli) { fwrite(STDOUT, $msg . "\n"); } else { echo $msg . "\n"; }
    exit(0);
} catch (Throwable $e) {
    $err = "[" . date('Y-m-d H:i:s') . "] ERREUR — " . $e->getMessage();
    if ($isCli) { fwrite(STDERR, $err . "\n"); } else { http_response_code(500); echo $err . "\n"; }
    exit(1);
}
