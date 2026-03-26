<?php
// ============================================================
//  SimCity — Installation / Réinstallation complète
//  ⚠️  Protégez ou supprimez ce fichier après installation.
// ============================================================

require_once __DIR__ . '/config.php';

// ─── Contrôle d'accès par IP ──────────────────────────────────
// $allowedIPs = ['127.0.0.1', '::1'];
// if (!in_array($_SERVER['REMOTE_ADDR'] ?? '', $allowedIPs, true)) {
//     http_response_code(403); die("Accès refusé.");
// }

try {
    $pdo = new PDO("mysql:host=" . DB_HOST, DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    echo "<div style='font-family:sans-serif;padding:20px;max-width:700px;margin:40px auto;background:#fff;border:1px solid #e2e8f0;border-radius:12px;'>";
    echo "<h2 style='color:#4361ee;border-bottom:2px solid #f1f5f9;padding-bottom:10px;'>🚀 Installation de SimCity</h2>";

    $dbname = DB_NAME;

    // ── 1. Base de données ──────────────────────────────────────
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `$dbname` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    $pdo->exec("USE `$dbname`");
    echo "<p style='color:#059669;'>✅ Base de données <b>$dbname</b> prête.</p>";

    // ── Application du schéma (source unique : schema.php) ──────
    // SIMCITY_SCHEMA_MANUAL empêche l'appel automatique à l'inclusion,
    // on appelle simcity_apply_schema() manuellement juste après.
    define('SIMCITY_SCHEMA_MANUAL', true);
    require_once __DIR__ . '/schema.php';

    $usersBefore = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
    simcity_apply_schema($pdo);

    // ── Affichage du résultat ───────────────────────────────────
    $tables = ['models','services','operators','plan_types','billing_accounts',
               'agents','history_logs','devices','mobile_lines','attachments',
               'sim_history','sign_tokens','signatures','users','settings'];
    foreach ($tables as $t) {
        echo "<p style='color:#059669;'>✅ Table <b>$t</b></p>";
    }

    // Afficher si le compte admin a été créé ou existait déjà
    $usersAfter = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
    if ($usersAfter > $usersBefore) {
        echo "<p style='color:#059669;'>✅ Compte <b>admin / admin</b> créé.</p>";
    } else {
        echo "<p style='color:#059669;'>✅ Comptes existants conservés.</p>";
    }

    echo "<div style='background:#f0fdf4;padding:15px;border-radius:8px;border:1px solid #bbf7d0;margin-top:20px;'>";
    echo "<b style='color:#166534;font-size:1.05rem;'>✅ Installation terminée !</b><br><br>";
    echo "<b>Compte par défaut :</b> admin / admin — <strong style='color:#dc2626;'>Changez ce mot de passe immédiatement.</strong><br><br>";
    echo "<b>Prochaine étape :</b> supprimez ou protégez install.php et reset.php via .htaccess.";
    echo "</div>";
    echo "<a href='index.php' style='display:block;text-align:center;margin-top:20px;padding:12px;background:#4361ee;color:white;text-decoration:none;border-radius:8px;font-weight:bold;'>▶️ Accéder à SimCity</a>";
    echo "</div>";

} catch (PDOException $e) {
    echo "<div style='font-family:sans-serif;padding:20px;max-width:700px;margin:40px auto;background:#fef2f2;border:1px solid #fecaca;border-radius:12px;'>";
    echo "<h2 style='color:#dc2626;'>❌ Erreur d'installation</h2>";
    // Ne pas exposer les détails de l'erreur en production
    echo "<p>Une erreur est survenue. Vérifiez vos paramètres de connexion dans config.php.</p>";
    echo "</div>";
}
?>
