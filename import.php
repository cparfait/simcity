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

// ─── Connexion DB ─────────────────────────────────────────────
try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";charset=" . DB_CHARSET, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `" . DB_NAME . "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
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
            // Double confirmation requise pour la purge
            if (($_POST['confirm_purge'] ?? '') !== 'PURGER') {
                $message .= "<div style='background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:1rem;color:#dc2626;margin-top:1rem;'>⚠️ Vous devez saisir <strong>PURGER</strong> dans le champ de confirmation pour activer la purge.</div>";
                goto render;
            }
            $pdo->exec("SET FOREIGN_KEY_CHECKS = 0");
            $pdo->exec("DROP TABLE IF EXISTS signatures, sign_tokens, sim_history, attachments, mobile_lines, devices, history_logs, agents, billing_accounts, plan_types, operators, models, services, settings");
            $pdo->exec("SET FOREIGN_KEY_CHECKS = 1");
            createTables($pdo);
            $message .= "<p style='color:#059669;font-weight:bold;'>✅ Base purgée et structure V5.0 recréée.</p>";
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
                $message .= "<div style='background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:1rem;color:#dc2626;margin-top:1rem;'>Fichier trop volumineux (max 10 Mo).</div>";
                goto render;
            }
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $mime  = $finfo->file($_FILES['file_data']['tmp_name']);
            $allowedCsvMime = ['text/plain','text/csv','application/csv','application/vnd.ms-excel','text/comma-separated-values'];
            if (!in_array($mime, $allowedCsvMime, true)) {
                $message .= "<div style='background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:1rem;color:#dc2626;margin-top:1rem;'>Type de fichier non autorisé. Veuillez envoyer un fichier CSV.</div>";
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

                $nom     = trim($row[2] ?? '');
                $prenom  = trim($row[3] ?? '');
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
            <div style='background:#eff6ff;border:1px solid #bfdbfe;border-radius:10px;padding:1.25rem;margin-top:1rem;color:#1e40af;'>
                🎉 <strong>Importation terminée avec succès !</strong><br><br>
                <ul style='margin:.5rem 0 0 1.25rem;line-height:2;'>
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
            $message .= "<div style='background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:1rem;color:#dc2626;margin-top:1rem;'>Veuillez sélectionner un fichier CSV valide.</div>";
        }
    }
}

render:
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Importation CSV | SimCity</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@600;800&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root{--primary:#4361ee;--danger:#ef4444;}
        body{font-family:'DM Sans',sans-serif;background:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:1rem;}
        .card{background:#fff;border-radius:16px;box-shadow:0 10px 40px rgba(0,0,0,.1);width:100%;max-width:640px;overflow:hidden;border:1px solid #e2e8f0;}
        .card-header{background:var(--primary);padding:1.75rem;text-align:center;color:#fff;}
        .card-header h1{font-family:'Outfit',sans-serif;font-size:1.6rem;margin:0;}
        .card-header p{opacity:.8;font-size:.9rem;margin:.4rem 0 0;}
        .card-body{padding:2rem;}
        .field{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:1.25rem;margin-bottom:1rem;}
        .field label{display:block;font-weight:700;color:#334155;margin-bottom:.4rem;}
        .field p{font-size:.83rem;color:#64748b;margin:.25rem 0 .75rem;}
        input[type=file],input[type=text]{width:100%;font-size:.85rem;color:#64748b;box-sizing:border-box;}
        input[type=text]{padding:.5rem .75rem;border:1px solid #d1d5db;border-radius:6px;margin-top:.4rem;background:#fff;color:#111;}
        .warn{background:#fef2f2;border:1px solid #fecaca;border-radius:10px;padding:1rem;margin-bottom:1rem;font-size:.88rem;color:#991b1b;font-weight:600;}
        .csrf-error{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:1rem;color:#dc2626;margin-bottom:1rem;font-weight:600;}
        .btn{width:100%;padding:1rem;background:var(--primary);color:#fff;border:none;border-radius:10px;font-size:1.05rem;font-weight:700;cursor:pointer;}
        .btn:hover{background:#3451d1;}
        .btn-link{display:inline-block;margin-top:1.25rem;padding:.75rem 2rem;background:var(--primary);color:#fff;text-decoration:none;border-radius:8px;font-weight:700;text-align:center;width:100%;box-sizing:border-box;}
        .note{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:1rem;font-size:.82rem;color:#166534;margin-top:1rem;line-height:1.6;}
        .back{display:inline-block;margin-top:1rem;color:var(--primary);font-size:.88rem;text-decoration:none;}
    </style>
</head>
<body>
<div class="card">
    <div class="card-header">
        <div style="font-size:2.5rem;margin-bottom:.5rem;">📥</div>
        <h1>Importation CSV</h1>
        <p>SimCity V5.0 — Réservé aux administrateurs</p>
    </div>
    <div class="card-body">

        <?php if ($csrfError): ?>
            <div class="csrf-error">🔒 <?= htmlspecialchars($csrfError, ENT_QUOTES) ?></div>
        <?php endif; ?>

        <?php if ($message && strpos($message, 'succès') !== false): ?>
            <?= $message ?>
            <a href="index.php" class="btn-link">🚀 Accéder à SimCity</a>

        <?php else: ?>
            <?php if ($message) echo $message; ?>

            <form method="post" enctype="multipart/form-data">
                <!-- Jeton CSRF -->
                <input type="hidden" name="_csrf" value="<?= htmlspecialchars($_SESSION['import_csrf'], ENT_QUOTES) ?>">

                <div class="field">
                    <label>📄 Fichier d'inventaire (.csv)</label>
                    <p>Fichier CSV séparé par <code>;</code>, encodage Windows-1252.<br>
                    <strong>Colonnes attendues :</strong> [0] Ligne, [2] Nom, [3] Prénom, [4] Notes, [5] CF Facturation, [6] Service, [7] Options, [9] Date activation, [10] IMEI, [11] Modèle, [12] Forfait, [13] ICCID, [14] PIN, [15] PUK, [16] Opérateur (optionnel)</p>
                    <input type="file" name="file_data" accept=".csv,text/csv" required>
                </div>

                <div class="warn">
                    <label style="display:flex;align-items:flex-start;gap:.75rem;cursor:pointer;font-weight:400;">
                        <input type="checkbox" name="truncate" value="1" id="trunc"
                            style="width:18px;height:18px;accent-color:#dc2626;flex-shrink:0;margin-top:2px;"
                            onchange="document.getElementById('purge-confirm-block').style.display=this.checked?'block':'none'">
                        <span>⚠️ <strong>Vider toute la base</strong> et recréer la structure V5.0 avant l'import<br>
                        <small style="font-weight:400;">(Toutes les données existantes seront supprimées définitivement)</small></span>
                    </label>
                    <div id="purge-confirm-block" style="display:none;margin-top:.75rem;">
                        <label style="font-size:.82rem;font-weight:700;color:#991b1b;">Tapez <strong>PURGER</strong> pour confirmer la suppression :</label>
                        <input type="text" name="confirm_purge" placeholder="PURGER" autocomplete="off" style="margin-top:.35rem;">
                    </div>
                </div>

                <button type="submit" class="btn">▶️ Lancer l'importation</button>
            </form>

            <div class="note">
                💡 <strong>Après l'import</strong>, pensez à renseigner les sites web de vos opérateurs dans <em>Référentiels → Opérateurs</em>.
            </div>
        <?php endif; ?>

        <a href="index.php" class="back">← Retour à SimCity</a>
    </div>
</div>
</body>
</html>
