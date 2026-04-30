<?php
// ============================================================
//  SimCity — Réinitialisation de la base de données
//  ⚠️  FICHIER DANGEREUX — À supprimer après utilisation
//      ou à protéger par IP dans .htaccess
// ============================================================

require_once __DIR__ . '/config.php';

// ─── Contrôle d'accès par IP ──────────────────────────────────
// Décommentez et adaptez la liste blanche d'IPs autorisées :
// $allowedIPs = ['127.0.0.1', '::1', '192.168.1.10'];
// if (!in_array($_SERVER['REMOTE_ADDR'] ?? '', $allowedIPs, true)) {
//     http_response_code(403);
//     die("<p style='font-family:sans-serif;color:#dc2626;padding:2rem;'>Accès refusé.</p>");
// }

// ─── Connexion DB ─────────────────────────────────────────────
try {
    $pdo = new PDO(
        "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET,
        DB_USER, DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (Exception $e) {
    die("<p style='font-family:sans-serif;color:#dc2626;padding:2rem;'>Erreur DB : impossible de se connecter.</p>");
}

// ─── Session & contrôle d'accès ──────────────────────────────
session_name(SESSION_NAME);
session_start();

if (empty($_SESSION['user_id']) || empty($_SESSION['is_admin'])) {
    http_response_code(403);
    die("<div style='font-family:sans-serif;padding:3rem;text-align:center;color:#dc2626;'><h2>⛔ Accès refusé</h2><p>Cette page est réservée aux super-administrateurs.</p><a href='index.php' style='color:#4361ee;'>← Retour à l'application</a></div>");
}

// ─── Jeton CSRF simple pour ce formulaire ─────────────────────
if (empty($_SESSION['reset_csrf'])) {
    $_SESSION['reset_csrf'] = bin2hex(random_bytes(32));
}

$done = false;
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Vérification CSRF
    if (!hash_equals($_SESSION['reset_csrf'], $_POST['_csrf'] ?? '')) {
        $error = 'Jeton CSRF invalide. Rechargez la page.';
    // Vérification du mot de confirmation
    } elseif (($_POST['confirm_word'] ?? '') !== 'SUPPRIMER') {
        $error = 'Vous devez saisir exactement SUPPRIMER pour confirmer.';
    } else {
        try {
            $pdo->exec("SET FOREIGN_KEY_CHECKS = 0;");
            $pdo->exec("DROP TABLE IF EXISTS `signatures`, `sign_tokens`, `sim_history`, `attachments`, `mobile_lines`, `devices`, `history_logs`, `agents`, `billing_accounts`, `plan_types`, `operators`, `models`, `services`, `settings`, `users`");
            $pdo->exec("SET FOREIGN_KEY_CHECKS = 1;");
            // Renouveler le jeton après usage
            $_SESSION['reset_csrf'] = bin2hex(random_bytes(32));
            $done = true;
        } catch (Exception $e) {
            $error = 'Erreur lors de la suppression.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Réinitialisation — SimCity</title>
    <style>
        body { font-family: sans-serif; display: flex; align-items: center; justify-content: center;
               min-height: 100vh; margin: 0; background: #fef2f2; }
        .box { background: #fff; padding: 2.5rem; border-radius: 12px; border: 2px solid #fecaca;
               max-width: 480px; width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,.1); }
        h2 { color: #dc2626; margin-top: 0; }
        .warn { background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px;
                padding: 1rem; color: #991b1b; font-size: .88rem; margin-bottom: 1.5rem; line-height: 1.6; }
        label { display: block; font-weight: 600; margin-bottom: .4rem; font-size: .85rem; color: #374151; }
        input[type=text] { width: 100%; padding: .65rem 1rem; border: 1px solid #d1d5db;
                           border-radius: 6px; font-size: 1rem; box-sizing: border-box; }
        input[type=text]:focus { outline: none; border-color: #dc2626; box-shadow: 0 0 0 3px rgba(220,38,38,.15); }
        button { width: 100%; padding: .85rem; background: #dc2626; color: #fff; border: none;
                 border-radius: 6px; font-weight: 700; font-size: 1rem; cursor: pointer; margin-top: 1.25rem; }
        button:hover { background: #b91c1c; }
        .success { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 1rem; color: #166534; }
        .error-msg { color: #dc2626; font-size: .88rem; margin-bottom: 1rem; font-weight: 600; }
        a.back { display: inline-block; margin-top: 1rem; color: #4361ee; font-size: .9rem; }
    </style>
</head>
<body>
<div class="box">
<?php if ($done): ?>
    <div class="success">
        <h2 style="color:#059669">✅ Base de données nettoyée</h2>
        <p>L'ancienne structure a été supprimée.</p>
        <p><a href="install.php">Relancer install.php pour recréer les tables →</a></p>
    </div>
<?php else: ?>
    <h2>⚠️ Réinitialisation complète</h2>
    <div class="warn">
        <strong>Cette opération est IRRÉVERSIBLE.</strong><br>
        Toutes les tables et données (lignes, matériels, agents, historique, comptes...) seront <strong>définitivement supprimées</strong>.<br><br>
        Effectuez une sauvegarde MySQL avant de continuer.
    </div>
    <?php if ($error): ?><div class="error-msg">❌ <?= htmlspecialchars($error, ENT_QUOTES) ?></div><?php endif; ?>
    <form method="post">
        <input type="hidden" name="_csrf" value="<?= htmlspecialchars($_SESSION['reset_csrf'], ENT_QUOTES) ?>">
        <div style="margin-bottom:1.25rem;">
            <label>Tapez <strong>SUPPRIMER</strong> pour confirmer :</label>
            <input type="text" name="confirm_word" autocomplete="off" placeholder="SUPPRIMER" required>
        </div>
        <button type="submit">Supprimer toutes les données</button>
    </form>
    <a class="back" href="index.php">← Retour à l'application</a>
<?php endif; ?>
</div>
</body>
</html>
