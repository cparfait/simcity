<?php
// ============================================================
//  SimCity — Outil d'importation CSV (V5.0)
// ============================================================
session_name('simcity_sess');
session_start();

// ─── Vérification authentification ───────────────────────────
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib_format.php';
date_default_timezone_set(defined('APP_TIMEZONE') ? APP_TIMEZONE : 'Europe/Paris');

// ─── Connexion DB ─────────────────────────────────────────────
try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";charset=" . DB_CHARSET, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);
    // Toléré : un compte dédié (droits limités à simcity_db) n'a pas CREATE DATABASE.
    try { $pdo->exec("CREATE DATABASE IF NOT EXISTS `" . DB_NAME . "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); } catch (PDOException $e) {}
    $pdo->exec("USE `" . DB_NAME . "`");
} catch (Exception $e) {
    die("<div style='color:#ef4444;padding:2rem;font-family:sans-serif;'>Erreur DB : impossible de se connecter.</div>");
}

// ─── Token CSRF ───────────────────────────────────────────────
if (empty($_SESSION['import_csrf'])) {
    $_SESSION['import_csrf'] = bin2hex(random_bytes(32));
}

// ── Création / mise à jour du schéma (source unique) ─────────
define('SIMCITY_SCHEMA_MANUAL', true);
require_once __DIR__ . '/schema.php';

function createTables(PDO $pdo): void {
    simcity_apply_schema($pdo);
}

try { createTables($pdo); } catch(Exception $e) { /* tables existantes */ }

$message = '';
$csrfError = '';
$stats = ['services'=>0,'models'=>0,'devices'=>0,'lines'=>0,'agents'=>0,'plans'=>0,'billings'=>0,'operators'=>0];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // ─── Vérification CSRF ────────────────────────────────────
    if (!hash_equals($_SESSION['import_csrf'] ?? '', $_POST['_csrf'] ?? '')) {
        $csrfError = "Erreur de sécurité (jeton CSRF invalide). Rechargez la page et réessayez.";
    } else {
        // Renouveler le jeton après usage
        $_SESSION['import_csrf'] = bin2hex(random_bytes(32));

        if (isset($_POST['truncate']) && $_POST['truncate'] == '1') {
            // Purge = destruction totale : réservée aux super-administrateurs
            // (cohérent avec la « zone dangereuse » de index.php).
            if (empty($_SESSION['is_admin'])) {
                $message .= "<div class='alert alert-err'>⛔ La purge de la base est réservée aux super-administrateurs.</div>";
                goto render;
            }
            // Double confirmation requise pour la purge
            if (($_POST['confirm_purge'] ?? '') !== 'PURGER') {
                $message .= "<div class='alert alert-err'>⚠️ Vous devez saisir <strong>PURGER</strong> dans le champ de confirmation pour activer la purge.</div>";
                goto render;
            }
            $pdo->exec("SET FOREIGN_KEY_CHECKS = 0");
            $pdo->exec("DROP TABLE IF EXISTS bons, signatures, sign_tokens, sim_history, attachments, mobile_lines, devices, history_logs, agents, billing_accounts, plan_types, operators, models, services, settings");
            $pdo->exec("SET FOREIGN_KEY_CHECKS = 1");
            createTables($pdo);
            $message .= "<div class='alert alert-ok'><i class='bi bi-check-circle-fill'></i> Base purgée et structure V5.0 recréée.</div>";
        }

        $caches = ['models'=>[], 'services'=>[], 'plan_types'=>[], 'billing_accounts'=>[], 'agents'=>[], 'operators'=>[]];

        $getOrCreate = function($table, $col, $val, $extraCol=null, $extraVal=null) use ($pdo, &$caches, &$stats) {
            $val = trim($val);
            if ($val === '') return null;
            $key = strtolower($val . ($extraVal !== null ? '_'.$extraVal : ''));
            if (isset($caches[$table][$key])) return $caches[$table][$key];

            $sql = "SELECT id FROM `$table` WHERE `$col`=?";
            $params = [$val];
            if ($extraCol) { $sql .= " AND `$extraCol`=?"; $params[] = $extraVal; }
            $st = $pdo->prepare($sql); $st->execute($params);
            $id = $st->fetchColumn();
            if (!$id) {
                if ($extraCol) {
                    $pdo->prepare("INSERT INTO `$table` (`$col`, `$extraCol`) VALUES (?,?)")->execute([$val, $extraVal]);
                } else {
                    $pdo->prepare("INSERT INTO `$table` (`$col`) VALUES (?)")->execute([$val]);
                }
                $id = $pdo->lastInsertId();
                if (isset($stats[$table])) $stats[$table]++;
            }
            $caches[$table][$key] = $id;
            return $id;
        };

        $formatDate = function($dateStr) {
            $dateStr = trim($dateStr);
            if (empty($dateStr)) return null;
            $d = DateTime::createFromFormat('d/m/Y', $dateStr);
            if (!$d) $d = DateTime::createFromFormat('Y-m-d', $dateStr);
            return $d ? $d->format('Y-m-d') : null;
        };

        if (isset($_FILES['file_data']) && $_FILES['file_data']['error'] == 0) {

            // ─── Validation du fichier CSV ────────────────────
            $maxCsvSize = 10 * 1024 * 1024; // 10 Mo max
            if ($_FILES['file_data']['size'] > $maxCsvSize) {
                $message .= "<div class='alert alert-err'>Fichier trop volumineux (max 10 Mo).</div>";
                goto render;
            }
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $mime  = $finfo->file($_FILES['file_data']['tmp_name']);
            $allowedCsvMime = ['text/plain','text/csv','application/csv','application/vnd.ms-excel','text/comma-separated-values'];
            if (!in_array($mime, $allowedCsvMime, true)) {
                $message .= "<div class='alert alert-err'>Type de fichier non autorisé. Veuillez envoyer un fichier CSV.</div>";
                goto render;
            }

            $file = fopen($_FILES['file_data']['tmp_name'], 'r');
            $startReading = false;
            $known_brands = ['XIAOMI','APPLE','SAMSUNG','ALCATEL','OPPO','ALTICE','MOTOROLA','MOBIWIRE','CROSSCALL','HUAWEI','TP-LINK','ZTE','SIERRA','NOKIA'];

            while (($row = fgetcsv($file, 4000, ";")) !== false) {
                $row = array_map(fn($v) => mb_convert_encoding((string)$v, 'UTF-8', 'Windows-1252'), $row);

                if (!$startReading) {
                    if (isset($row[0]) && stripos($row[0], 'LIGNE') !== false) $startReading = true;
                    continue;
                }

                $phone   = preg_replace('/\s+/', '', $row[0] ?? '');
                $imei    = preg_replace('/[^0-9]/', '', $row[10] ?? '');
                if (empty($phone) && empty($imei)) continue;

                $nom     = (string) fmtLastName($row[2] ?? '');
                $prenom  = (string) fmtFirstName($row[3] ?? '');
                $notes   = trim($row[4] ?? '');
                $cf      = trim($row[5] ?? '');
                $service = trim($row[6] ?? '');
                $options = trim($row[7] ?? '');
                $dateAct = $formatDate($row[9] ?? '');
                $rawMod  = trim($row[11] ?? '');
                $plan    = trim($row[12] ?? '');
                $iccid   = preg_replace('/[^a-zA-Z0-9]/', '', $row[13] ?? '');
                $pin     = trim($row[14] ?? '');
                $puk2    = trim($row[15] ?? '');
                $operateur = trim($row[16] ?? '');

                $brand = 'Inconnu'; $modelName = $rawMod;
                foreach ($known_brands as $kb) {
                    if (stripos($rawMod, $kb) === 0) {
                        $brand = $kb; $modelName = trim(substr($rawMod, strlen($kb))); break;
                    }
                }

                $svcId  = $getOrCreate('services', 'name', $service);
                $modId  = $getOrCreate('models', 'name', $modelName, 'brand', $brand);
                $billId = $getOrCreate('billing_accounts', 'account_number', $cf);
                $opId   = $operateur ? $getOrCreate('operators', 'name', $operateur) : null;

                $planId = null;
                if ($plan !== '') {
                    $key = strtolower($plan . '_' . ($opId ?? '0'));
                    if (!isset($caches['plan_types'][$key])) {
                        $stP = $pdo->prepare("SELECT id FROM plan_types WHERE name=?" . ($opId ? " AND operator_id=?" : " AND (operator_id IS NULL OR operator_id=0)"));
                        $paramsP = [$plan]; if ($opId) $paramsP[] = $opId;
                        $stP->execute($paramsP);
                        $pid = $stP->fetchColumn();
                        if (!$pid) {
                            $pdo->prepare("INSERT INTO plan_types (name, operator_id) VALUES (?,?)")->execute([$plan, $opId]);
                            $pid = $pdo->lastInsertId(); $stats['plans']++;
                        }
                        $caches['plan_types'][$key] = $pid;
                    }
                    $planId = $caches['plan_types'][$key];
                }

                $agtId = null;
                if ($nom !== '' || $prenom !== '') {
                    $agtId = $getOrCreate('agents', 'last_name', $nom, 'first_name', $prenom);
                    if ($svcId) $pdo->prepare("UPDATE agents SET service_id=? WHERE id=? AND (service_id IS NULL OR service_id=0)")->execute([$svcId, $agtId]);
                }

                $devId = null;
                if ($imei !== '') {
                    $stD = $pdo->prepare("SELECT id FROM devices WHERE imei=?"); $stD->execute([$imei]);
                    $devId = $stD->fetchColumn();
                    if (!$devId) {
                        $devStatus = empty($phone) ? 'Stock' : 'Deployed';
                        $pdo->prepare("INSERT INTO devices (imei, model_id, service_id, status, agent_id) VALUES (?,?,?,?,?)")
                            ->execute([$imei, $modId, $svcId, $devStatus, $agtId]);
                        $devId = $pdo->lastInsertId(); $stats['devices']++;
                        if ($agtId) $pdo->prepare("INSERT INTO history_logs (entity_type, entity_id, action_desc, author) VALUES ('device',?,?,?)")
                            ->execute([$devId, "Import initial — attribué à $prenom $nom", 'Import CSV']);
                    } else {
                        $pdo->prepare("UPDATE devices SET status='Deployed', service_id=?, agent_id=? WHERE id=?")
                            ->execute([$svcId, $agtId, $devId]);
                    }
                }

                if ($phone !== '' && strlen($phone) >= 8) {
                    try {
                        $pdo->prepare("INSERT IGNORE INTO mobile_lines
                            (phone_number, agent_id, billing_id, plan_id, service_id, activation_date, device_id, iccid, pin, puk, options_details, status, notes)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,'Active',?)")
                            ->execute([$phone, $agtId, $billId, $planId, $svcId, $dateAct, $devId, $iccid, $pin, $puk2, $options, $notes]);
                        $lineId = $pdo->lastInsertId();
                        if ($lineId) {
                            $stats['lines']++;
                            if ($agtId) $pdo->prepare("INSERT INTO history_logs (entity_type, entity_id, action_desc, author) VALUES ('line',?,?,?)")
                                ->execute([$lineId, "Import initial — attribuée à $prenom $nom", 'Import CSV']);
                        }
                    } catch (Exception $e) { /* doublon ignoré */ }
                }
            }
            fclose($file);

            $message .= "
            <div class='alert alert-ok'>
                <strong><i class='bi bi-check-circle-fill'></i> Importation terminée avec succès !</strong>
                <ul class='stats-list'>
                    <li><b>{$stats['lines']}</b> lignes importées</li>
                    <li><b>{$stats['devices']}</b> matériels physiques</li>
                    <li><b>{$stats['agents']}</b> utilisateurs créés</li>
                    <li><b>{$stats['services']}</b> services créés</li>
                    <li><b>{$stats['models']}</b> modèles de téléphones</li>
                    <li><b>{$stats['plans']}</b> types de forfaits</li>
                    <li><b>{$stats['operators']}</b> opérateurs créés</li>
                    <li><b>{$stats['billings']}</b> comptes de facturation</li>
                </ul>
            </div>";
        } else {
            $message .= "<div class='alert alert-err'><i class='bi bi-exclamation-triangle-fill'></i> Veuillez sélectionner un fichier CSV valide.</div>";
        }
    }
}

render:
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Importation CSV – SimCity</title>
    <link rel="icon" type="image/svg+xml" href="assets/logo.svg">
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link href="vendor/bootstrap-icons.css" rel="stylesheet">
    <script>(function(){ if (localStorage.getItem('pm_theme') === 'dark') document.documentElement.setAttribute('data-theme','dark'); })();</script>
    <style>
    /* Design system aligné sur index.php (IBM Plex, indigo + slate, thème sombre) */
    :root{--bg:#f8fafc;--bg2:#ffffff;--bg3:#f1f5f9;--card:#ffffff;--card2:#f1f5f9;--border:#e2e8f0;--border2:#cbd5e1;--primary:#4f46e5;--primary-dark:#4338ca;--primary-dim:rgba(79,70,229,.08);--success:#059669;--success-dim:#d1fae5;--danger:#dc2626;--danger-dim:#fee2e2;--warning:#d97706;--warning-dim:#fef3c7;--info:#2563eb;--info-dim:#dbeafe;--text:#334155;--text-strong:#0f172a;--text2:#64748b;--text3:#94a3b8;--radius:10px;--radius-sm:7px;--radius-lg:14px;--shadow-lg:0 12px 28px rgba(15,23,42,.12),0 4px 10px rgba(15,23,42,.06);--ring:0 0 0 3px rgba(79,70,229,.35);--font:'IBM Plex Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;--font-mono:'IBM Plex Mono',ui-monospace,'SFMono-Regular','Consolas',monospace;}
    [data-theme="dark"]{--bg:#0b1120;--bg2:#111827;--bg3:#0f1b2d;--card:#1e293b;--card2:#233247;--border:#2b3a4f;--border2:#3a4a61;--primary:#818cf8;--primary-dark:#6366f1;--primary-dim:rgba(129,140,248,.14);--success:#34d399;--success-dim:#064e3b;--danger:#f87171;--danger-dim:#7f1d1d;--warning:#fbbf24;--warning-dim:#78350f;--info:#60a5fa;--info-dim:#1e3a5f;--text:#e2e8f0;--text-strong:#f8fafc;--text2:#94a3b8;--text3:#64748b;--shadow-lg:0 14px 32px rgba(0,0,0,.6);--ring:0 0 0 3px rgba(129,140,248,.35);}
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:.9rem;line-height:1.5;letter-spacing:-.005em;-webkit-font-smoothing:antialiased;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:2rem 1rem;transition:background-color .2s ease,color .2s ease;}
    h1,h2,h3,h4{color:var(--text-strong)}
    .card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius-lg);box-shadow:var(--shadow-lg);width:100%;max-width:720px;overflow:hidden;}
    .card-header{display:flex;align-items:center;gap:.9rem;padding:1.25rem 1.5rem;background:var(--bg2);border-bottom:1px solid var(--border);}
    .card-header .ic{display:flex;align-items:center;justify-content:center;width:42px;height:42px;flex-shrink:0;border-radius:var(--radius-sm);background:var(--primary-dim);color:var(--primary);font-size:1.25rem;}
    .card-header h1{font-size:1.05rem;font-weight:600;letter-spacing:-.01em;}
    .card-header p{font-size:.82rem;color:var(--text2);margin-top:.15rem;}
    .theme-btn{margin-left:auto;background:none;border:1px solid var(--border);color:var(--text2);border-radius:var(--radius-sm);width:34px;height:34px;cursor:pointer;font-size:.95rem;flex-shrink:0;}
    .theme-btn:hover{background:var(--bg3);color:var(--text);}
    .card-body{padding:1.5rem;}
    .field{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:1.1rem;margin-bottom:1rem;}
    .field > label{display:block;font-weight:600;color:var(--text-strong);margin-bottom:.35rem;}
    .field p{font-size:.82rem;color:var(--text2);margin:.25rem 0 .75rem;line-height:1.6;}
    .field code{font-family:var(--font-mono);font-size:.8rem;background:var(--card2);border:1px solid var(--border);border-radius:4px;padding:.05rem .3rem;}
    input[type=file]{width:100%;font-size:.85rem;color:var(--text2);background:var(--card);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.6rem;}
    input[type=file]::file-selector-button{font-family:var(--font);font-size:.82rem;font-weight:500;color:var(--text);background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:.35rem .75rem;margin-right:.75rem;cursor:pointer;}
    input[type=text]{width:100%;padding:.5rem .75rem;border:1px solid var(--border2);border-radius:var(--radius-sm);margin-top:.4rem;background:var(--card);color:var(--text);font-family:var(--font-mono);font-size:.85rem;}
    input:focus-visible{outline:none;box-shadow:var(--ring);border-color:var(--primary);}
    .danger-zone{background:var(--danger-dim);border:1px solid var(--danger);border-radius:var(--radius);padding:1.1rem;margin-bottom:1.25rem;font-size:.86rem;color:var(--danger);}
    .danger-zone strong{color:var(--danger);}
    .danger-zone small{color:var(--text2);display:block;margin-top:.3rem;}
    .alert{border-radius:var(--radius);padding:1rem 1.1rem;margin-bottom:1.25rem;font-size:.86rem;line-height:1.6;}
    .alert-err{background:var(--danger-dim);border:1px solid var(--danger);color:var(--danger);}
    .alert-ok{background:var(--success-dim);border:1px solid var(--success);color:var(--success);}
    .alert-ok strong{color:var(--success);}
    .stats-list{list-style:none;margin-top:.75rem;display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:.35rem .9rem;}
    .stats-list li{color:var(--text);background:var(--card);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.4rem .7rem;font-size:.83rem;}
    .stats-list b{font-family:var(--font-mono);color:var(--text-strong);}
    .note{background:var(--info-dim);border:1px solid var(--info);border-radius:var(--radius);padding:.9rem 1.1rem;font-size:.82rem;color:var(--text);margin-top:1.25rem;line-height:1.6;}
    .btn-primary,.btn-secondary{display:inline-flex;align-items:center;justify-content:center;gap:.5rem;padding:.7rem 1.25rem;border-radius:var(--radius-sm);font-family:var(--font);font-size:.9rem;font-weight:600;cursor:pointer;text-decoration:none;border:1px solid transparent;transition:background .15s ease;}
    .btn-primary{background:var(--primary);color:#fff;width:100%;}
    .btn-primary:hover{background:var(--primary-dark);}
    .btn-secondary{background:var(--card);color:var(--text);border-color:var(--border2);}
    .btn-secondary:hover{background:var(--bg3);}
    .actions{display:flex;gap:.75rem;flex-wrap:wrap;margin-top:1.25rem;padding-top:1.25rem;border-top:1px solid var(--border);}
    </style>
</head>
<body>
<div class="card">
    <div class="card-header">
        <div class="ic"><i class="bi bi-filetype-csv"></i></div>
        <div>
            <h1>Importation CSV</h1>
            <p>Reprise d'inventaire — réservé aux administrateurs</p>
        </div>
        <button type="button" class="theme-btn" id="theme-toggle" title="Basculer le thème clair / sombre"><i class="bi bi-moon-stars"></i></button>
    </div>
    <div class="card-body">

        <?php if ($csrfError): ?>
            <div class="alert alert-err"><i class="bi bi-shield-exclamation"></i> <?= htmlspecialchars($csrfError, ENT_QUOTES) ?></div>
        <?php endif; ?>

        <?php if ($message && strpos($message, 'succès') !== false): ?>
            <?= $message ?>
            <div class="actions">
                <a href="index.php" class="btn-primary"><i class="bi bi-box-arrow-in-right"></i> Accéder à SimCity</a>
            </div>

        <?php else: ?>
            <?php if ($message) echo $message; ?>

            <form method="post" enctype="multipart/form-data">
                <!-- Jeton CSRF -->
                <input type="hidden" name="_csrf" value="<?= htmlspecialchars($_SESSION['import_csrf'], ENT_QUOTES) ?>">

                <div class="field">
                    <label><i class="bi bi-file-earmark-arrow-up"></i> Fichier d'inventaire (.csv)</label>
                    <p>Fichier CSV séparé par <code>;</code>, encodage Windows-1252.<br>
                    <strong>Colonnes attendues :</strong> [0] Ligne, [2] Nom, [3] Prénom, [4] Notes, [5] CF Facturation, [6] Service, [7] Options, [9] Date activation, [10] IMEI, [11] Modèle, [12] Forfait, [13] ICCID, [14] PIN, [15] PUK, [16] Opérateur (optionnel)</p>
                    <input type="file" name="file_data" accept=".csv,text/csv" required>
                </div>

                <div class="danger-zone">
                    <label style="display:flex;align-items:flex-start;gap:.75rem;cursor:pointer;font-weight:400;">
                        <input type="checkbox" name="truncate" value="1" id="trunc"
                            style="width:16px;height:16px;accent-color:var(--danger);flex-shrink:0;margin-top:3px;"
                            onchange="document.getElementById('purge-confirm-block').style.display=this.checked?'block':'none'">
                        <span><strong><i class="bi bi-exclamation-triangle-fill"></i> Vider toute la base</strong> et recréer la structure V5.0 avant l'import
                        <small>Toutes les données seront supprimées définitivement, <strong>y compris les paramètres</strong> : configuration SMTP, logo et URL du site à reconfigurer.</small></span>
                    </label>
                    <div id="purge-confirm-block" style="display:none;margin-top:.75rem;">
                        <label style="font-size:.82rem;font-weight:600;">Tapez <strong>PURGER</strong> pour confirmer la suppression :</label>
                        <input type="text" name="confirm_purge" placeholder="PURGER" autocomplete="off">
                    </div>
                </div>

                <button type="submit" class="btn-primary"><i class="bi bi-play-fill"></i> Lancer l'importation</button>
            </form>

            <div class="note">
                <i class="bi bi-lightbulb"></i> <strong>Après l'import</strong>, pensez à renseigner les sites web de vos opérateurs dans <em>Référentiels → Opérateurs</em>.
            </div>

            <div class="actions">
                <a href="index.php?page=refs&tab=settings&sub=maintenance" class="btn-secondary"><i class="bi bi-arrow-left"></i> Retour aux paramètres</a>
            </div>
        <?php endif; ?>

    </div>
</div>
<script>
// Bascule de thème, partagée avec index.php via la clé localStorage « pm_theme ».
(function(){
  var btn = document.getElementById('theme-toggle');
  var sync = function(){
    var dark = document.documentElement.getAttribute('data-theme') === 'dark';
    btn.innerHTML = dark ? '<i class="bi bi-sun"></i>' : '<i class="bi bi-moon-stars"></i>';
  };
  btn.addEventListener('click', function(){
    var dark = document.documentElement.getAttribute('data-theme') === 'dark';
    document.documentElement.setAttribute('data-theme', dark ? 'light' : 'dark');
    localStorage.setItem('pm_theme', dark ? 'light' : 'dark');
    sync();
  });
  sync();
})();
</script>
</body>
</html>
