<?php
// ============================================================
//  SimCity — Installation / Réinstallation complète
//  ⚠️  Protégez ou supprimez ce fichier après installation.
// ============================================================

require_once __DIR__ . '/config.php';
date_default_timezone_set(defined('APP_TIMEZONE') ? APP_TIMEZONE : 'Europe/Paris');

// ─── Contrôle d'accès par IP ──────────────────────────────────
// $allowedIPs = ['127.0.0.1', '::1'];
// if (!in_array($_SERVER['REMOTE_ADDR'] ?? '', $allowedIPs, true)) {
//     http_response_code(403); die("Accès refusé.");
// }

// ─── Session + jeton CSRF (pour les formulaires d'install) ────
session_name(defined('SESSION_NAME') ? SESSION_NAME : 'simcity_sess');
session_start();
if (empty($_SESSION['install_csrf'])) $_SESSION['install_csrf'] = bin2hex(random_bytes(32));
$csrfOk = fn() => hash_equals($_SESSION['install_csrf'] ?? '', $_POST['_csrf'] ?? '');

$adminMsg = ''; $adminErr = '';
$htMsg = '';

try {
    $pdo = new PDO("mysql:host=" . DB_HOST, DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $dbname = DB_NAME;
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `$dbname` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    $pdo->exec("USE `$dbname`");

    // ── Application du schéma (source unique : schema.php) ──────
    define('SIMCITY_SCHEMA_MANUAL', true);
    require_once __DIR__ . '/schema.php';

    $usersBefore = 0;
    try { $usersBefore = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn(); } catch (Exception $e) {}
    simcity_apply_schema($pdo);
    $usersAfter = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();

    // ── ACTION : définir les identifiants du compte administrateur ──
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'set_admin') {
        if (!$csrfOk()) {
            $adminErr = "Session expirée. Rechargez la page et réessayez.";
        } else {
            $newUser = trim($_POST['admin_user'] ?? '') ?: 'admin';
            $newPass = (string)($_POST['admin_pass'] ?? '');
            $confirm = (string)($_POST['admin_pass2'] ?? '');
            if (strlen($newPass) < 8) {
                $adminErr = "Le mot de passe doit contenir au moins 8 caractères.";
            } elseif ($newPass !== $confirm) {
                $adminErr = "Les deux mots de passe ne correspondent pas.";
            } else {
                // Cible : le compte 'admin' initial, sinon le premier super-admin, sinon le premier compte
                $target = $pdo->query("SELECT id FROM users WHERE username='admin'")->fetchColumn();
                if (!$target) $target = $pdo->query("SELECT id FROM users WHERE is_admin=1 ORDER BY id LIMIT 1")->fetchColumn();
                if (!$target) $target = $pdo->query("SELECT id FROM users ORDER BY id LIMIT 1")->fetchColumn();
                // Refuser un identifiant déjà pris par un AUTRE compte
                $clash = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username=? AND id<>?");
                $clash->execute([$newUser, $target]);
                if ($clash->fetchColumn() > 0) {
                    $adminErr = "L'identifiant « $newUser » est déjà utilisé par un autre compte.";
                } else {
                    $pdo->prepare("UPDATE users SET username=?, password=?, is_admin=1, active=1 WHERE id=?")
                        ->execute([$newUser, password_hash($newPass, PASSWORD_DEFAULT), $target]);
                    $adminMsg = "Compte administrateur configuré : identifiant « <b>" . htmlspecialchars($newUser) . "</b> ».";
                    $_SESSION['install_csrf'] = bin2hex(random_bytes(32)); // renouvellement
                }
            }
        }
    }

    // ── ACTION : activer la protection .htaccess ──────────────────
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'enable_htaccess') {
        if (!$csrfOk()) {
            $htMsg = "❌ Session expirée, réessayez.";
        } elseif (file_exists(__DIR__ . '/.htaccess')) {
            $htMsg = "ℹ️ Un fichier .htaccess est déjà présent — inchangé.";
        } elseif (!file_exists(__DIR__ . '/htaccess')) {
            $htMsg = "❌ Fichier modèle « htaccess » introuvable.";
        } elseif (@copy(__DIR__ . '/htaccess', __DIR__ . '/.htaccess')) {
            $htMsg = "✅ Protection activée (.htaccess créé). config.php, install.php et reset.php sont désormais bloqués sous Apache.";
            $_SESSION['install_csrf'] = bin2hex(random_bytes(32));
        } else {
            $htMsg = "❌ Impossible de créer .htaccess (droits d'écriture ?). Renommez le fichier manuellement.";
        }
    }

    // ── Contrôles d'environnement / sécurité ──────────────────────
    if (!is_dir(UPLOAD_DIR)) @mkdir(UPLOAD_DIR, 0755, true);
    $htActive = file_exists(__DIR__ . '/.htaccess');
    $checks = [
        ['Extension PDO MySQL',          extension_loaded('pdo_mysql'),   'Requise pour la connexion à la base.'],
        ['Extension fileinfo',           extension_loaded('fileinfo'),    'Requise pour valider les fichiers uploadés (pièces jointes, logo).'],
        ["Dossier « " . UPLOAD_DIR . " » accessible en écriture", is_dir(UPLOAD_DIR) && is_writable(UPLOAD_DIR), 'Nécessaire aux pièces jointes et au logo.'],
        ['Affichage des erreurs désactivé (APP_DEBUG)', !(defined('APP_DEBUG') && APP_DEBUG), 'Doit être false en production (config.php).'],
        ['Identifiants MySQL personnalisés', !(DB_USER === 'root' && DB_PASS === 'root'), "Remplacez root/root par un compte dédié dans config.php."],
        ['Protection .htaccess active',  $htActive, 'Sans elle, config.php est téléchargeable en clair (Apache).'],
    ];
    $adminIsDefault = false;
    try {
        $adminRow = $pdo->query("SELECT password FROM users WHERE username='admin'")->fetch(PDO::FETCH_ASSOC);
        if ($adminRow && password_verify('admin', $adminRow['password'])) $adminIsDefault = true;
    } catch (Exception $e) {}

    // ─────────────────────────────────────────────────────────────
    //  RENDU HTML
    // ─────────────────────────────────────────────────────────────
    $csrf = htmlspecialchars($_SESSION['install_csrf'], ENT_QUOTES);
    ?>
    <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Installation — SimCity</title>
    <style>
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f1f5f9;margin:0;padding:2rem 1rem;color:#1e293b;}
        .wrap{max-width:720px;margin:0 auto;}
        .card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:1.75rem;margin-bottom:1.25rem;box-shadow:0 4px 16px rgba(0,0,0,.04);}
        h2{color:#4361ee;border-bottom:2px solid #f1f5f9;padding-bottom:10px;margin-top:0;}
        h3{margin:0 0 1rem;font-size:1.1rem;}
        .ok{color:#059669;} .bad{color:#dc2626;} .warn{color:#d97706;}
        table.checks{width:100%;border-collapse:collapse;font-size:.9rem;}
        table.checks td{padding:.5rem .25rem;border-bottom:1px solid #f1f5f9;vertical-align:top;}
        table.checks td.state{width:28px;font-size:1.1rem;}
        .hint{color:#64748b;font-size:.82rem;}
        label{display:block;font-weight:600;font-size:.85rem;margin:.75rem 0 .25rem;}
        input[type=text],input[type=password]{width:100%;padding:.6rem .75rem;border:1px solid #cbd5e1;border-radius:8px;box-sizing:border-box;font-size:.95rem;}
        .btn{margin-top:1rem;padding:.75rem 1.5rem;background:#4361ee;color:#fff;border:none;border-radius:8px;font-weight:700;cursor:pointer;font-size:.95rem;}
        .btn.secondary{background:#334155;}
        .msg{padding:.85rem 1rem;border-radius:8px;margin-bottom:1rem;font-size:.9rem;}
        .msg.ok{background:#f0fdf4;border:1px solid #bbf7d0;color:#166534;}
        .msg.err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;}
        .banner{background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;border-radius:8px;padding:.85rem 1rem;font-size:.88rem;margin-bottom:1rem;}
        a.go{display:block;text-align:center;margin-top:.5rem;padding:.85rem;background:#4361ee;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;}
    </style></head><body><div class="wrap">

    <div class="card">
        <h2>🚀 Installation de SimCity</h2>
        <p class="ok">✅ Base de données <b><?= htmlspecialchars($dbname) ?></b> prête, tables créées / mises à jour.</p>
        <p class="<?= $usersAfter > $usersBefore ? 'ok' : 'ok' ?>">
            <?= $usersAfter > $usersBefore ? '✅ Compte administrateur initial créé.' : '✅ Comptes existants conservés.' ?>
        </p>
    </div>

    <!-- ── Compte administrateur ─────────────────────────────── -->
    <div class="card">
        <h3>🔐 Compte administrateur</h3>
        <?php if ($adminMsg): ?><div class="msg ok"><?= $adminMsg ?></div><?php endif; ?>
        <?php if ($adminErr): ?><div class="msg err">⚠️ <?= htmlspecialchars($adminErr) ?></div><?php endif; ?>
        <?php if ($adminIsDefault && !$adminMsg): ?>
        <div class="banner">⚠️ Le compte par défaut <b>admin / admin</b> est actif. Définissez un mot de passe fort maintenant.</div>
        <?php endif; ?>
        <p class="hint">Configure le compte super-administrateur (remplace le mot de passe <code>admin</code> par défaut). Vous pourrez créer d'autres comptes ensuite depuis l'application.</p>
        <form method="post">
            <input type="hidden" name="_csrf" value="<?= $csrf ?>">
            <input type="hidden" name="action" value="set_admin">
            <label>Identifiant</label>
            <input type="text" name="admin_user" value="admin" autocomplete="username">
            <label>Nouveau mot de passe <span class="hint">(8 caractères minimum)</span></label>
            <input type="password" name="admin_pass" required autocomplete="new-password">
            <label>Confirmer le mot de passe</label>
            <input type="password" name="admin_pass2" required autocomplete="new-password">
            <button type="submit" class="btn">💾 Enregistrer le compte administrateur</button>
        </form>
    </div>

    <!-- ── Contrôles d'environnement ─────────────────────────── -->
    <div class="card">
        <h3>🩺 Contrôles avant mise en production</h3>
        <table class="checks">
            <?php foreach ($checks as [$label, $pass, $hint]): ?>
            <tr>
                <td class="state"><?= $pass ? '<span class="ok">✅</span>' : '<span class="bad">❌</span>' ?></td>
                <td><b><?= htmlspecialchars($label) ?></b><br><span class="hint"><?= htmlspecialchars($hint) ?></span></td>
            </tr>
            <?php endforeach; ?>
        </table>

        <?php if ($htMsg): ?><div class="msg <?= strpos($htMsg, '✅') === 0 ? 'ok' : 'err' ?>" style="margin-top:1rem;"><?= htmlspecialchars($htMsg) ?></div><?php endif; ?>
        <?php if (!$htActive): ?>
        <form method="post" style="margin-top:1rem;">
            <input type="hidden" name="_csrf" value="<?= $csrf ?>">
            <input type="hidden" name="action" value="enable_htaccess">
            <button type="submit" class="btn secondary">🛡️ Activer la protection .htaccess</button>
            <span class="hint">Crée <code>.htaccess</code> à partir du modèle fourni.</span>
        </form>
        <?php endif; ?>
    </div>

    <!-- ── Étapes manuelles restantes ────────────────────────── -->
    <div class="card">
        <h3>📋 À finaliser à la main</h3>
        <ul class="hint" style="line-height:1.9;margin:0;padding-left:1.25rem;">
            <li>Créer un compte MySQL dédié (pas <code>root</code>) et le renseigner dans <code>config.php</code>.</li>
            <li>Supprimer ou restreindre l'accès à <code>install.php</code> et <code>reset.php</code>.</li>
            <li>Une fois le certificat TLS en place : passer <code>FORCE_HTTPS</code> à <code>true</code> et décommenter la ligne HSTS du <code>.htaccess</code>.</li>
            <li>Planifier une sauvegarde <code>mysqldump</code> régulière.</li>
        </ul>
        <p class="hint" style="margin-top:1rem;">Détails complets : section « Mise en production » du <code>README.md</code>.</p>
    </div>

    <a href="index.php" class="go">▶️ Accéder à SimCity</a>

    </div></body></html>
    <?php

} catch (PDOException $e) {
    echo "<div style='font-family:sans-serif;padding:20px;max-width:700px;margin:40px auto;background:#fef2f2;border:1px solid #fecaca;border-radius:12px;'>";
    echo "<h2 style='color:#dc2626;'>❌ Erreur d'installation</h2>";
    echo "<p>Une erreur est survenue. Vérifiez vos paramètres de connexion dans config.php.</p>";
    echo "<p style='font-family:monospace;background:#fff;padding:10px;border-radius:6px;border:1px solid #fca5a5;font-size:.85rem;word-break:break-all;'><b>Détail :</b> " . htmlspecialchars($e->getMessage()) . "</p>";
    echo "</div>";
}
