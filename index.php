<?php
// ============================================================
//  SimCity v5.0 – Flotte Mobile, Zéro Papier & Sécurité
// ============================================================
ob_start();

// ─── Configuration centralisée ────────────────────────────────
require_once __DIR__ . '/config.php';

// ─── Authentification LDAP / Active Directory (optionnelle) ───
require_once __DIR__ . '/ldap_auth.php';

// ─── Affichage des erreurs selon l'environnement ──────────────
if (defined('APP_DEBUG') && APP_DEBUG) {
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
} else {
    ini_set('display_errors', 0);
    error_reporting(0);
}

// ─── Fuseau horaire (horodatages cohérents) ───────────────────
date_default_timezone_set(defined('APP_TIMEZONE') ? APP_TIMEZONE : 'Europe/Paris');

// ─── Détection HTTPS (gère les reverse proxies) ───────────────
// Vrai si la connexion cliente est en HTTPS, y compris derrière un proxy
// qui transmet X-Forwarded-Proto (ex. nginx, Traefik, Cloudflare).
function isHttps(): bool {
    if (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') return true;
    if (($_SERVER['SERVER_PORT'] ?? '') === '443') return true;
    $xfp = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '';
    return strtolower(explode(',', $xfp)[0]) === 'https';
}

// ─── Redirection HTTPS forcée (production) ─────────────────────
if (defined('FORCE_HTTPS') && FORCE_HTTPS && PHP_SAPI !== 'cli' && !isHttps()) {
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $uri  = $_SERVER['REQUEST_URI'] ?? '/';
    header('Location: https://' . $host . $uri, true, 301);
    exit;
}

// ─── Session sécurisée ────────────────────────────────────────
session_name(SESSION_NAME);
ini_set('session.cookie_httponly', 1);   // Inaccessible au JS
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
ini_set('session.gc_maxlifetime', SESSION_LIFETIME);
session_set_cookie_params(['lifetime' => 0, 'httponly' => true, 'samesite' => 'Strict', 'secure' => isHttps()]);
// Cookie sécurisé activé automatiquement dès que le site est servi en HTTPS
if (isHttps()) {
    ini_set('session.cookie_secure', 1);
}
session_start();

// Renouveler l'ID de session à chaque connexion (anti-fixation)
// (effectué dans le bloc login ci-dessous)

// Création du dossier pour les pièces jointes
if (!is_dir(UPLOAD_DIR)) { mkdir(UPLOAD_DIR, 0755, true); }

// ─── 1. CONNEXION DB ──────────────────────────────────────────
try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";charset=" . DB_CHARSET, DB_USER, DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
    // Création tolérée : un compte MySQL dédié (droits limités à simcity_db) n'a pas
    // le privilège CREATE DATABASE. Si la base existe déjà, le USE suffit.
    try { $pdo->exec("CREATE DATABASE IF NOT EXISTS `" . DB_NAME . "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); } catch (PDOException $e) {}
    $pdo->exec("USE `" . DB_NAME . "`");
} catch (Exception $e) { die("<div style='color:#ef4444;padding:3rem;font-family:sans-serif'>Erreur DB : impossible de se connecter.</div>"); }

// ─── 2. CREATION ET MISE A JOUR DES TABLES ────────────────────
try {
    require_once __DIR__ . '/schema.php';
} catch (Exception $e) {
    $msg = (defined('APP_DEBUG') && APP_DEBUG) ? htmlspecialchars($e->getMessage()) : 'Erreur lors de la préparation de la base de données.';
    die("<div style='color:#ef4444;padding:3rem;font-family:sans-serif'>$msg</div>");
}

// ─── Configuration LDAP/AD (table settings, surcharge par env) ─
ldap_init($pdo);

// ─── Bibliothèque de sauvegarde / restauration ────────────────
require_once __DIR__ . '/backup_lib.php';

// ─── Bibliothèque d'importation CSV ───────────────────────────
require_once __DIR__ . '/import_lib.php';

// ─── Bibliothèque des factures opérateur (Facturation / Contrôle) ───
require_once __DIR__ . '/invoice_lib.php';

// ─── Bibliothèque de l'export de parc SFR (contrôle du référentiel) ───
require_once __DIR__ . '/sfr_parc_lib.php';

// ─── Sauvegarde automatique « sans cron » ─────────────────────
// Déclenchée par le trafic web (idéal en conteneur, sans crontab). Un verrou
// atomique en base garantit qu'un seul visiteur lance la sauvegarde par
// intervalle. Non bloquant : toute erreur est silencieuse pour l'utilisateur.
if (defined('BACKUP_AUTO') && BACKUP_AUTO && PHP_SAPI !== 'cli') {
    try {
        $interval  = defined('BACKUP_AUTO_INTERVAL') ? (int)BACKUP_AUTO_INTERVAL : 86400;
        $threshold = date('Y-m-d H:i:s', time() - $interval);
        // On « réclame » le créneau : l'UPDATE ne réussit que pour un seul
        // processus (ceux qui suivent voient déjà la valeur mise à jour).
        $claim = $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key='last_auto_backup' AND (setting_value='' OR setting_value < ?)");
        $claim->execute([date('Y-m-d H:i:s'), $threshold]);
        if ($claim->rowCount() === 1) {
            simcity_backup_to_disk($pdo);
        }
    } catch (Throwable $e) {
        error_log('SimCity auto-backup: ' . $e->getMessage());
    }
}


// ─── 2b. PAGE PUBLIQUE DE SIGNATURE MOBILE ────────────────────
if (isset($_GET['page']) && $_GET['page'] === 'sign') {
    $token = preg_replace('/[^a-zA-Z0-9]/', '', $_GET['token'] ?? '');
    $bon = null;
    if ($token) {
        $st = $pdo->prepare("SELECT * FROM bons WHERE token=?");
        $st->execute([$token]);
        $bon = $st->fetch();
    }

    // Traitement de la signature soumise
    $canSignNow = $bon && $bon['status'] === 'pending' && (!$bon['expires_at'] || strtotime($bon['expires_at']) >= time());
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && $canSignNow && isset($_POST['signature_data'])) {
        $sigData = $_POST['signature_data'];
        // Stocké brut : l'échappement est fait à l'affichage (h() / htmlspecialchars),
        // sinon un nom comme « D'Angelo » serait doublement encodé.
        $signerName = trim($_POST['signer_name'] ?? '');
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $justSigned = false;
        // Valider que c'est bien du base64 PNG
        if (strpos($sigData, 'data:image/png;base64,') === 0) {
            $pdo->beginTransaction();
            try {
                // Verrou + re-vérification : un bon ne peut être signé qu'une seule fois
                $lock = $pdo->prepare("SELECT id FROM bons WHERE id=? AND status='pending' FOR UPDATE");
                $lock->execute([$bon['id']]);
                if ($lock->fetchColumn()) {
                    $pdo->prepare("UPDATE bons SET status='signed', signed_at=NOW(), signer_name=?, signature_data=?, ip=? WHERE id=?")
                        ->execute([$signerName, $sigData, $ip, $bon['id']]);
                    $agentId = (int)$bon['agent_id'];
                    $items   = $bon['items'] ? json_decode($bon['items'], true) : null;
                    $log = $pdo->prepare("INSERT INTO history_logs (entity_type, entity_id, action_desc, agent_id, author) VALUES (?,?,?,?,'Système')");
                    $log->execute(['agent', $agentId, "✍️ Bon de {$bon['type']} {$bon['numero']} signé électroniquement par $signerName", $agentId]);

                    // Bon de REMISE signé → mise en service des équipements listés sur le bon
                    if ($bon['type'] === 'remise') {
                        foreach (($items['devices'] ?? []) as $it) {
                            if (empty($it['device_id'])) continue;
                            // Couvre aussi les téléphones liés uniquement via la ligne (agent_id NULL sur le device)
                            $up = $pdo->prepare("UPDATE devices SET status='Deployed', agent_id=? WHERE id=? AND archived=0 AND status!='Deployed'
                                AND (agent_id=? OR (agent_id IS NULL AND id IN (SELECT device_id FROM mobile_lines WHERE agent_id=? AND archived=0)))");
                            $up->execute([$agentId, (int)$it['device_id'], $agentId, $agentId]);
                            if ($up->rowCount()) $log->execute(['device', (int)$it['device_id'], "✅ Matériel mis en service — bon {$bon['numero']} signé par $signerName", $agentId]);
                        }
                        foreach (($items['lines'] ?? []) as $it) {
                            if (empty($it['line_id'])) continue;
                            $up = $pdo->prepare("UPDATE mobile_lines SET status='Active' WHERE id=? AND agent_id=? AND archived=0 AND sim_vierge=0 AND status!='Active'");
                            $up->execute([(int)$it['line_id'], $agentId]);
                            if ($up->rowCount()) $log->execute(['line', (int)$it['line_id'], "✅ Ligne activée — bon {$bon['numero']} signé par $signerName", $agentId]);
                        }
                    }

                    // Bon de RESTITUTION signé → retour en stock des seuls items du bon
                    if ($bon['type'] === 'restitution') {
                        if ($items !== null) {
                            foreach (($items['devices'] ?? []) as $it) {
                                if (empty($it['device_id'])) continue;
                                $up = $pdo->prepare("UPDATE devices SET status='Stock', agent_id=NULL, service_id=NULL WHERE id=? AND archived=0
                                    AND (agent_id=? OR id IN (SELECT device_id FROM mobile_lines WHERE agent_id=? AND archived=0))");
                                $up->execute([(int)$it['device_id'], $agentId, $agentId]);
                                if ($up->rowCount()) {
                                    $log->execute(['device', (int)$it['device_id'], "📦 Retour en stock — bon {$bon['numero']} signé par $signerName", $agentId]);
                                    // Dissocier les lignes qui référencent encore ce téléphone
                                    $affLines = $pdo->prepare("SELECT id FROM mobile_lines WHERE device_id=? AND archived=0");
                                    $affLines->execute([(int)$it['device_id']]);
                                    foreach ($affLines->fetchAll(PDO::FETCH_COLUMN) as $lid) {
                                        $pdo->prepare("UPDATE mobile_lines SET device_id=NULL WHERE id=?")->execute([$lid]);
                                        $log->execute(['line', (int)$lid, "Téléphone dissocié — restitué via le bon {$bon['numero']}", $agentId]);
                                    }
                                }
                            }
                            foreach (($items['lines'] ?? []) as $it) {
                                if (empty($it['line_id'])) continue;
                                $up = $pdo->prepare("UPDATE mobile_lines SET agent_id=NULL, service_id=NULL, device_id=NULL, status='Stock' WHERE id=? AND agent_id=? AND archived=0");
                                $up->execute([(int)$it['line_id'], $agentId]);
                                if ($up->rowCount()) $log->execute(['line', (int)$it['line_id'], "📦 SIM remise en stock — bon {$bon['numero']} signé par $signerName", $agentId]);
                            }
                        } else {
                            // Bon migré sans contenu enregistré : restitution complète (ancien comportement)
                            foreach ($pdo->query("SELECT id FROM devices WHERE agent_id=$agentId AND archived=0")->fetchAll() as $dr) {
                                $pdo->prepare("UPDATE devices SET status='Stock', agent_id=NULL, service_id=NULL WHERE id=?")->execute([$dr['id']]);
                                $log->execute(['device', (int)$dr['id'], "📦 Retour en stock — bon {$bon['numero']} signé par $signerName", $agentId]);
                            }
                            foreach ($pdo->query("SELECT id, device_id FROM mobile_lines WHERE agent_id=$agentId AND archived=0")->fetchAll() as $lr) {
                                if ($lr['device_id']) {
                                    $pdo->prepare("UPDATE devices SET status='Stock', agent_id=NULL, service_id=NULL WHERE id=? AND archived=0")->execute([$lr['device_id']]);
                                    $log->execute(['device', (int)$lr['device_id'], "📦 Retour en stock via ligne — bon {$bon['numero']} signé par $signerName", $agentId]);
                                }
                                $log->execute(['line', (int)$lr['id'], "📦 SIM remise en stock — bon {$bon['numero']} signé par $signerName", $agentId]);
                            }
                            $pdo->prepare("UPDATE mobile_lines SET agent_id=NULL, service_id=NULL, device_id=NULL, status='Stock' WHERE agent_id=? AND archived=0")->execute([$agentId]);
                        }
                    }
                    // Demande de téléphone liée à ce bon : la signature de la
                    // remise clôt le cycle → la demande passe en « livrée ».
                    if ($bon['type'] === 'remise') {
                        $pdo->prepare("UPDATE requests SET status='livree', delivered_at=NOW() WHERE bon_id=? AND status='validee'")
                            ->execute([(int)$bon['id']]);
                    }
                    $justSigned = true;
                }
                $pdo->commit();
            } catch (Exception $e) { $pdo->rollBack(); }
        }
        if ($justSigned) {
        ?><!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Signature enregistrée – SimCity</title>
        <style>
        *{box-sizing:border-box;margin:0;padding:0}
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;background:#f0fdf4;display:flex;align-items:center;justify-content:center;padding:1rem;}
        .box{text-align:center;padding:2.5rem 2rem;background:#fff;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.12);max-width:420px;width:100%;}
        .check{font-size:4rem;margin-bottom:.5rem;}
        h2{color:#10b981;font-size:1.4rem;margin-bottom:.75rem;}
        p{color:#555;line-height:1.5;}
        .ts{font-size:.8rem;color:#999;margin-top:.75rem;}
        .close-hint{margin-top:1.5rem;padding-top:1.25rem;border-top:1px solid #f1f5f9;color:#94a3b8;font-size:.9rem;}
        </style></head>
        <body>
          <div class="box">
            <div class="check">✅</div>
            <h2>Signature enregistrée</h2>
            <p>Merci <strong><?=htmlspecialchars($signerName)?></strong>.<br>Votre signature a bien été prise en compte.</p>
            <p class="ts">Signé le <?=date('d/m/Y à H:i')?></p>
            <p class="close-hint">👍 Vous pouvez fermer cet onglet.</p>
          </div>
          <script>
          // Prévient les autres onglets SimCity (Historique, fiche agent, tableau
          // de bord) qu'une signature vient d'aboutir → ils se rechargent.
          try { localStorage.setItem('simcity_bon_signed', String(Date.now())); } catch(e) {}
          </script>
        </body></html>
        <?php exit;
        }
        // Double soumission ou données invalides → réafficher l'état réel du bon
        $st = $pdo->prepare("SELECT * FROM bons WHERE token=?"); $st->execute([$token]); $bon = $st->fetch();
    }

    $agt = $bon ? $pdo->query("SELECT a.*, s.name as service_name FROM agents a LEFT JOIN services s ON a.service_id=s.id WHERE a.id=".(int)$bon['agent_id'])->fetch() : null;
    $alreadySigned = $bon && $bon['status'] === 'signed';
    $isCancelled   = $bon && $bon['status'] === 'cancelled';
    $isExpired     = $bon && $bon['status'] === 'pending' && $bon['expires_at'] && strtotime($bon['expires_at']) < time();
    $canSign       = $bon && $bon['status'] === 'pending' && !$isExpired;
    $bonItems      = ($bon && $bon['items']) ? json_decode($bon['items'], true) : null;

    // Bloquer la restitution tant que le bon de remise n'est pas signé
    $remiseNotSigned = false;
    if ($canSign && $bon['type'] === 'restitution') {
        if ($bon['parent_id']) {
            $p = $pdo->prepare("SELECT status FROM bons WHERE id=?");
            $p->execute([$bon['parent_id']]);
            $remiseNotSigned = ($p->fetchColumn() !== 'signed');
        } else {
            $p = $pdo->prepare("SELECT COUNT(*) FROM bons WHERE agent_id=? AND type='remise' AND status='signed'");
            $p->execute([$bon['agent_id']]);
            $remiseNotSigned = ($p->fetchColumn() == 0);
        }
    }
    // Chercher un motif d'archivage récent (perte/casse) pour afficher en rouge sur la restitution
    $archiveAlertMsg = '';
    if ($canSign && $bon['type'] === 'restitution' && !$remiseNotSigned) {
        $archiveAlert = $pdo->prepare("SELECT action_desc FROM history_logs
            WHERE agent_id=? AND (action_desc LIKE '%Archivé%' OR action_desc LIKE '%archivé%' OR action_desc LIKE '%Perdu%' OR action_desc LIKE '%Volé%' OR action_desc LIKE '%Cassé%')
            ORDER BY action_date DESC LIMIT 1");
        $archiveAlert->execute([$bon['agent_id']]);
        $archiveAlertRow = $archiveAlert->fetch();
        if ($archiveAlertRow) $archiveAlertMsg = $archiveAlertRow['action_desc'];
    }
    ?>
<!DOCTYPE html><html lang="fr"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<title>Signature – SimCity</title>
<?php echo uiPrimaryCssOverride($pdo); ?>
<style>
:root{--primary:#4f46e5;--primary-dark:#4338ca;--primary-glow:rgba(79,70,229,.25);}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f8fafc;min-height:100vh;padding:1rem;}
.card{background:#fff;border-radius:16px;padding:1.5rem;max-width:500px;margin:0 auto;box-shadow:0 4px 20px rgba(0,0,0,.08);}
h2{font-size:1.2rem;color:#1e293b;margin-bottom:.25rem;}
.sub{color:#64748b;font-size:.85rem;margin-bottom:1.5rem;}
.info{background:#f1f5f9;border-radius:8px;padding:1rem;margin-bottom:1.25rem;font-size:.9rem;color:#334155;}
.info strong{display:block;color:#0f172a;font-size:1rem;margin-bottom:.25rem;}
label{display:block;font-size:.8rem;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:.4rem;}
input{width:100%;padding:.75rem;border:1px solid #e2e8f0;border-radius:8px;font-size:1rem;margin-bottom:1rem;}
input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow);}
.canvas-wrap{border:2px dashed #cbd5e1;border-radius:8px;background:#fafafa;margin-bottom:.75rem;position:relative;touch-action:none;}
canvas{display:block;width:100%;border-radius:8px;}
.canvas-hint{text-align:center;font-size:.75rem;color:#94a3b8;padding:.35rem;}
.btn-clear{background:none;border:1px solid #e2e8f0;border-radius:6px;padding:.45rem 1rem;font-size:.82rem;color:#64748b;cursor:pointer;margin-bottom:1rem;}
.btn-sign{width:100%;padding:1rem;background:var(--primary);color:#fff;border:none;border-radius:10px;font-size:1.05rem;font-weight:600;cursor:pointer;box-shadow:0 1px 3px rgba(15,23,42,.12);}
.btn-sign:hover{background:var(--primary-dark);}
.btn-sign:disabled{background:#cbd5e1;box-shadow:none;cursor:not-allowed;}
.error{background:#fef2f2;border:1px solid #fecaca;color:#dc2626;border-radius:8px;padding:1rem;margin-bottom:1rem;font-size:.9rem;}
.success-box{text-align:center;padding:2rem 1rem;}
.success-box .icon{font-size:3.5rem;} .success-box h2{color:#10b981;margin:.5rem 0;}
</style>
</head><body>
<div class="card">
<?php if(!$bon): ?>
    <div class="error">⛔ Ce lien de signature est invalide.</div>
<?php elseif($alreadySigned): ?>
    <div class="success-box"><div class="icon">✅</div><h2>Déjà signé</h2><p style="color:#64748b;">Le bon <strong><?=htmlspecialchars($bon['numero']?:'')?></strong> a déjà été signé<?php if($bon['signer_name']): ?> par <strong><?=htmlspecialchars($bon['signer_name'])?></strong> le <?=date('d/m/Y à H:i', strtotime($bon['signed_at']))?><?php endif; ?>.</p></div>
<?php elseif($isCancelled): ?>
    <div class="error" style="background:#f8fafc;border-color:#e2e8f0;color:#475569;">
        <div style="font-size:1.5rem;margin-bottom:.5rem;">🚫</div>
        <strong>Bon annulé</strong><br><br>
        Ce bon n'est plus valide<?php if($bon['cancel_reason']): ?> : <?=htmlspecialchars($bon['cancel_reason'])?><?php endif; ?>.<br><br>
        <span style="font-size:.85rem;">Demandez à votre DSI de générer un nouveau bon.</span>
    </div>
<?php elseif($isExpired): ?>
    <div class="error" style="background:#fff7ed;border-color:#fed7aa;color:#c2410c;">
        <div style="font-size:1.5rem;margin-bottom:.5rem;">⏰</div>
        <strong>Lien expiré</strong><br><br>
        Ce lien de signature a expiré.<br><br>
        <span style="font-size:.85rem;">Demandez à votre DSI de générer un nouveau bon.</span>
    </div>
<?php elseif($remiseNotSigned): ?>
    <div class="error" style="background:#fff7ed;border-color:#fed7aa;color:#c2410c;">
        <div style="font-size:1.5rem;margin-bottom:.5rem;">🔒</div>
        <strong>Signature impossible</strong><br><br>
        Le <strong>bon de restitution</strong> ne peut pas être signé avant le <strong>bon de remise</strong>.<br><br>
        <span style="font-size:.85rem;">Demandez à votre DSI de générer et vous transmettre d'abord le bon de remise.</span>
    </div>
<?php else: ?>
    <h2>✍️ Signature électronique</h2>
    <div class="sub">Bon de <?=$bon['type']==='remise'?'remise de matériel':'restitution de matériel'?> — <strong><?=htmlspecialchars($bon['numero']?:'')?></strong></div>
    <?php if($archiveAlertMsg): ?>
    <div style="background:#fef2f2;border:2px solid #fca5a5;border-radius:10px;padding:1rem 1.25rem;margin-bottom:1.25rem;color:#dc2626;">
        <div style="font-size:1.4rem;margin-bottom:.35rem;">⚠️</div>
        <strong style="font-size:1rem;">Restitution suite à un incident</strong><br>
        <span style="font-size:.9rem;margin-top:.35rem;display:block;"><?=htmlspecialchars($archiveAlertMsg)?></span>
    </div>
    <?php endif; ?>
    <div class="info">
        <strong><?=htmlspecialchars($agt['first_name'].' '.$agt['last_name'])?></strong>
        <?=htmlspecialchars($agt['service_name']?:'')?>
        <?php if($bonItems && (!empty($bonItems['devices']) || !empty($bonItems['lines']))): ?>
        <div style="margin-top:.75rem;padding-top:.75rem;border-top:1px solid #e2e8f0;font-size:.85rem;">
            <div style="font-weight:600;color:#64748b;text-transform:uppercase;font-size:.72rem;margin-bottom:.4rem;"><?=$bon['type']==='remise'?'Équipements remis':'Équipements à restituer'?></div>
            <?php foreach(($bonItems['devices'] ?? []) as $it): ?>
            <div style="margin-bottom:.25rem;">📱 <?=htmlspecialchars(trim(($it['brand']??'').' '.($it['name']??'')))?> <span style="color:#94a3b8;">— IMEI <?=htmlspecialchars($it['imei']??'')?></span></div>
            <?php endforeach; ?>
            <?php foreach(($bonItems['lines'] ?? []) as $it): ?>
            <div style="margin-bottom:.25rem;">📞 <?=htmlspecialchars(formatPhone($it['phone_number']??''))?><?php if(!empty($it['esim'])): ?> <span style="background:#ede9fe;color:#6d28d9;padding:0 4px;border-radius:3px;font-size:.72rem;">eSIM</span><?php endif; ?><?php if(!empty($it['personal_device'])): ?> <span style="color:#94a3b8;font-size:.78rem;">(appareil personnel)</span><?php endif; ?></div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>
    <form method="post" id="sigForm">
        <label>Votre nom complet</label>
        <input type="text" name="signer_name" required placeholder="Prénom Nom"
               value="<?=htmlspecialchars($agt['first_name'].' '.$agt['last_name'])?>">
        <label>Votre signature <span style="font-weight:400;text-transform:none;">(signez dans le cadre ci-dessous)</span></label>
        <div class="canvas-wrap">
            <canvas id="sigCanvas" height="200"></canvas>
        </div>
        <div class="canvas-hint">Signez avec votre doigt ou la souris</div>
        <button type="button" class="btn-clear" onclick="clearSig()">🗑️ Effacer</button><br>
        <input type="hidden" name="signature_data" id="sig_data">
        <button type="submit" class="btn-sign" id="btnSign" disabled>Valider ma signature</button>
    </form>
    <script>
    const canvas = document.getElementById('sigCanvas');
    const ctx = canvas.getContext('2d');
    let drawing = false, hasSig = false;

    function resizeCanvas() {
        const w = canvas.parentElement.clientWidth;
        canvas.width = w * window.devicePixelRatio;
        canvas.height = 200 * window.devicePixelRatio;
        canvas.style.width = w + 'px';
        canvas.style.height = '200px';
        ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
        ctx.strokeStyle = '#1e293b';
        ctx.lineWidth = 2.5;
        ctx.lineCap = 'round';
        ctx.lineJoin = 'round';
    }
    resizeCanvas();

    function getPos(e) {
        const r = canvas.getBoundingClientRect();
        const src = e.touches ? e.touches[0] : e;
        return { x: (src.clientX - r.left), y: (src.clientY - r.top) };
    }
    function startDraw(e) { e.preventDefault(); drawing = true; const p = getPos(e); ctx.beginPath(); ctx.moveTo(p.x, p.y); }
    function draw(e)      { e.preventDefault(); if(!drawing) return; const p = getPos(e); ctx.lineTo(p.x, p.y); ctx.stroke(); hasSig = true; document.getElementById('btnSign').disabled = false; }
    function stopDraw(e)  { e.preventDefault(); drawing = false; }
    function clearSig()   { ctx.clearRect(0,0,canvas.width,canvas.height); hasSig=false; document.getElementById('btnSign').disabled=true; }

    canvas.addEventListener('mousedown', startDraw);
    canvas.addEventListener('mousemove', draw);
    canvas.addEventListener('mouseup', stopDraw);
    canvas.addEventListener('touchstart', startDraw, {passive:false});
    canvas.addEventListener('touchmove', draw, {passive:false});
    canvas.addEventListener('touchend', stopDraw, {passive:false});

    document.getElementById('sigForm').addEventListener('submit', function(e) {
        if (!hasSig) { e.preventDefault(); alert('Veuillez signer dans le cadre.'); return; }
        document.getElementById('sig_data').value = canvas.toDataURL('image/png');
    });
    </script>
<?php endif; ?>
</div></body></html>
<?php exit; }

// ─── Réglages SMTP : surcharge par variables d'environnement ──
// Mêmes noms que Sentinelle (MAIL_SERVER, MAIL_PORT, MAIL_USERNAME,
// MAIL_PASSWORD, MAIL_DEFAULT_SENDER, MAIL_USE_TLS) : si la variable est
// définie (Docker), elle PRIME sur la base et le champ correspondant est
// verrouillé dans Paramètres — même logique que la configuration LDAP.
// Déclarée AVANT les pages publiques « demandes » (les const ne sont pas
// hoistées comme les fonctions et ces pages envoient des e-mails).
const SMTP_ENV_KEYS = [
    'smtp_host'      => 'MAIL_SERVER',
    'smtp_port'      => 'MAIL_PORT',
    'smtp_secure'    => 'MAIL_SECURE',          // tls | ssl | none
    'smtp_user'      => 'MAIL_USERNAME',
    'smtp_pass'      => 'MAIL_PASSWORD',
    'smtp_from'      => 'MAIL_DEFAULT_SENDER',
    'smtp_from_name' => 'MAIL_FROM_NAME',
];

// ─── 2c. DEMANDES DE TÉLÉPHONE : HELPERS ──────────────────────
// Attribution / renouvellement de téléphone : formulaire public, circuit
// de visas par liens magiques, suivi. Réutilise le socle des bons
// (tokens, SMTP, snapshot de dotation).

// Numéro séquentiel : DT-2026-0042
function requestNumero($pdo) {
    $prefix = 'DT-' . date('Y') . '-';
    $st = $pdo->prepare("SELECT MAX(CAST(SUBSTRING(numero, ?) AS UNSIGNED)) FROM requests WHERE numero LIKE ?");
    $st->execute([strlen($prefix) + 1, $prefix . '%']);
    return $prefix . str_pad((string)((int)$st->fetchColumn() + 1), 4, '0', STR_PAD_LEFT);
}

function requestTypeLabel($t) { return $t === 'renouvellement' ? 'Renouvellement / remplacement' : 'Première attribution'; }

// [libellé, classe badge] d'un statut de demande
function requestStatusInfo($s) {
    $map = [
        'a_qualifier'   => ['📥 À qualifier',   'badge-warning'],
        'en_validation' => ['⏳ En validation', 'badge-info'],
        'validee'       => ['✅ Validée',       'badge-success'],
        'refusee'       => ['⛔ Refusée',       'badge-danger'],
        'livree'        => ['📦 Livrée',        'badge-success'],
        'annulee'       => ['🚫 Annulée',       'badge-muted'],
    ];
    return $map[$s] ?? [$s, 'badge-muted'];
}

// Bouton d'action pour les e-mails : mise en page en table, seule forme
// fiable sous Outlook (les <a> stylés en bloc y perdent leur padding).
// Couleurs du bandeau (et des boutons) des e-mails : personnalisables dans
// Paramètres → Envoi d'e-mails. Retourne [couleur1, couleur2, dégradé?].
function mailBannerColors($pdo = null): array {
    $c1 = '#4f46e5'; $c2 = '#7c3aed'; $grad = true;
    if ($pdo) {
        // La couleur du site (si définie) devient le défaut des e-mails ;
        // les couleurs propres aux e-mails (ci-dessous) priment toujours.
        $site = uiPrimaryColor($pdo);
        if ($site !== '') { $c1 = $site; $c2 = uiColorMix($site, 0.3); }
        $v1 = getSetting($pdo, 'mail_banner_color', '');
        $v2 = getSetting($pdo, 'mail_banner_color2', '');
        if (preg_match('/^#[0-9a-fA-F]{6}$/', $v1)) $c1 = $v1;
        if (preg_match('/^#[0-9a-fA-F]{6}$/', $v2)) $c2 = $v2;
        $g = getSetting($pdo, 'mail_banner_gradient', '');
        if ($g !== '') $grad = $g === '1';
    }
    return [$c1, $c2, $grad];
}

function requestMailButton($url, $label) {
    [$c1, , ] = mailBannerColors($GLOBALS['pdo'] ?? null);
    return '<table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center" style="margin:28px auto;"><tr>'
         . '<td style="background-color:' . $c1 . ';border-radius:8px;" bgcolor="' . $c1 . '">'
         . '<a href="' . h($url) . '" style="display:inline-block;padding:14px 36px;font-family:Arial,Helvetica,sans-serif;font-size:15px;font-weight:bold;color:#ffffff;text-decoration:none;">' . $label . '</a>'
         . '</td></tr></table>';
}

// Gabarit d'e-mail commun (demandes, bons, notifications) : structure en
// tables imbriquées — le rendu HTML moderne (flex, max-width sur div) est
// ignoré par Outlook, qui reste le client des destinataires internes.
// Avec $pdo, le logo uploadé (celui des bons PDF) est affiché dans le
// bandeau — jamais le logo SVG embarqué, qu'Outlook ne sait pas afficher.
function requestMailShell($title, $inner, $pdo = null, $bannerOverride = null) {
    $logoImg = '';
    if ($pdo) {
        $lp = getSetting($pdo, 'pdf_logo_path', '');
        if ($lp && file_exists($lp) && !preg_match('/\.svg$/i', $lp)) {
            $root = preg_replace('~/index\.php$~', '', baseUrl($pdo));
            // Le logo occupe sa propre rangée blanche, au-dessus du bandeau
            // coloré : il reste toujours sur fond blanc.
            $logoImg = '<tr><td bgcolor="#ffffff" align="center" style="background-color:#ffffff;border-radius:12px 12px 0 0;padding:18px 36px;">'
                     . '<img src="' . h($root . '/' . str_replace('\\', '/', $lp)) . '" alt="" style="max-height:44px;display:block;margin:0 auto;">'
                     . '</td></tr>';
        }
    }
    [$c1, $c2, $grad] = $bannerOverride ?: mailBannerColors($pdo);
    $bandCss = $grad
        ? 'background:' . $c1 . ';background:linear-gradient(135deg,' . $c1 . ' 0%,' . $c2 . ' 100%);'
        : 'background-color:' . $c1 . ';';
    // Coins hauts arrondis sur la première rangée visible (logo ou bandeau)
    $bandRadius = $logoImg === '' ? 'border-radius:12px 12px 0 0;' : '';
    return '<!DOCTYPE html><html lang="fr"><body style="margin:0;padding:0;background-color:#eef1f6;">'
         . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#eef1f6"><tr><td align="center" style="padding:32px 12px;">'
         . '<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px;max-width:100%;">'
         // Rangée logo (fond blanc) puis bandeau coloré
         . $logoImg
         . '<tr><td bgcolor="' . $c1 . '" style="' . $bandCss . $bandRadius . 'padding:22px 36px;">'
         . '<div style="font-family:Arial,Helvetica,sans-serif;font-size:21px;font-weight:bold;color:#ffffff;">SimCity</div>'
         . '<div style="font-family:Arial,Helvetica,sans-serif;font-size:11px;color:rgba(255,255,255,.75);letter-spacing:1px;text-transform:uppercase;margin-top:4px;">Gestion de la flotte mobile</div>'
         . '</td></tr>'
         // Corps
         . '<tr><td bgcolor="#ffffff" style="background-color:#ffffff;padding:34px 36px;">'
         . '<h1 style="margin:0 0 18px;font-family:Arial,Helvetica,sans-serif;font-size:19px;line-height:1.35;color:#111827;">' . $title . '</h1>'
         . '<div style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.65;color:#374151;">' . $inner . '</div>'
         . '</td></tr>'
         // Pied
         . '<tr><td bgcolor="#f8fafc" style="background-color:#f8fafc;border-top:1px solid #e5e7eb;border-radius:0 0 12px 12px;padding:18px 36px;">'
         . '<p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#94a3b8;">Message automatique envoyé par SimCity — merci de ne pas répondre.</p>'
         . '</td></tr>'
         . '</table></td></tr></table></body></html>';
}

// ─── Gabarits d'e-mails personnalisables ──────────────────────
// Chaque e-mail de l'application a un gabarit par défaut (sujet, titre,
// corps HTML) surchargé par les réglages mail_tpl_<clé>_* de la table
// settings (Paramètres → Envoi d'e-mails). Les variables {xxx} sont
// remplacées à l'envoi ; celles marquées « peut être vide » arrivent
// déjà formatées (préfixe/suffixe inclus) ou vides.
function mailTemplates(): array {
    return [
        'test' => ['label' => 'E-mail de test SMTP', 'vars' => [],
            'subject' => 'Test SMTP — SimCity', 'title' => 'E-mail de test',
            'body' => '<p>Ceci est un e-mail de test envoyé depuis <strong>SimCity</strong> pour vérifier la configuration SMTP.</p><p>Si vous recevez ce message, l\'envoi d\'e-mails fonctionne correctement.</p>'],
        'accuse' => ['label' => 'Accusé de réception au demandeur',
            'vars' => ['numero' => 'n° de la demande', 'beneficiaire' => 'nom du bénéficiaire', 'bouton' => 'bouton « Suivre ma demande »'],
            'subject' => 'Demande de téléphone {numero} enregistrée', 'title' => 'Demande enregistrée',
            'body' => '<p>Bonjour,</p><p>Votre demande de téléphone <strong>{numero}</strong> pour <strong>{beneficiaire}</strong> a bien été enregistrée.</p><p>Elle va être examinée par la DSI puis suivre le circuit de validation. Vous pouvez suivre son avancement à tout moment :</p>{bouton}'],
        'nouvelle' => ['label' => 'Nouvelle demande (notification DSI)',
            'vars' => ['numero' => 'n° de la demande', 'type' => 'type de demande', 'beneficiaire' => 'nom du bénéficiaire', 'fonction' => 'fonction entre parenthèses (peut être vide)', 'email_beneficiaire' => 'ligne e-mail (peut être vide)', 'service' => 'service', 'demandeur' => 'nom du demandeur', 'email_demandeur' => 'e-mail du demandeur', 'bouton' => 'bouton « Qualifier la demande »'],
            'subject' => 'Nouvelle demande de téléphone {numero} — {beneficiaire}', 'title' => 'Nouvelle demande',
            'body' => '<p>Une nouvelle demande de téléphone vient d\'être déposée :</p><p><strong>{numero}</strong> — {type}<br>Bénéficiaire : <strong>{beneficiaire}</strong>{fonction}{email_beneficiaire}<br>Service : {service}<br>Demandeur : <strong>{demandeur}</strong> ({email_demandeur})</p>{bouton}'],
        'visa' => ['label' => 'Visa requis (valideur du circuit)',
            'vars' => ['validateur' => 'nom du valideur, précédé d\'une espace (peut être vide)', 'rappel' => 'paragraphe de rappel (vide hors relance)', 'numero' => 'n° de la demande', 'type' => 'type de demande', 'beneficiaire' => 'nom du bénéficiaire', 'service' => 'service, précédé de « — service » (peut être vide)', 'etape' => 'libellé du visa', 'bouton' => 'bouton « Examiner et viser »', 'lien' => 'URL du lien de visa'],
            'subject' => 'Visa requis — Demande de téléphone {numero}', 'title' => 'Visa requis',
            'body' => '<p>Bonjour{validateur},</p>{rappel}<p>La demande de téléphone <strong>{numero}</strong> ({type}) pour <strong>{beneficiaire}</strong>{service} attend votre visa <strong>« {etape} »</strong>.</p>{bouton}<p style="font-size:13px;color:#666;">Ou copiez ce lien dans votre navigateur :<br><a href="{lien}" style="color:#4f46e5;">{lien}</a></p><p style="font-size:13px;color:#666;">Aucun compte n\'est nécessaire : ce lien vous est personnel.</p>'],
        'validee' => ['label' => 'Demande validée (notification DSI)',
            'vars' => ['numero' => 'n° de la demande', 'beneficiaire' => 'nom du bénéficiaire', 'lien' => 'URL de la demande dans SimCity'],
            'subject' => 'Demande {numero} validée — à traiter', 'title' => 'Demande validée',
            'body' => '<p>La demande <strong>{numero}</strong> ({beneficiaire}) a terminé son circuit de validation.</p><p>Vous pouvez attribuer le matériel et générer le bon de remise.</p><p style="font-size:13px;color:#666;"><a href="{lien}" style="color:#4f46e5;">Ouvrir la demande dans SimCity</a></p>'],
        'refusee' => ['label' => 'Demande refusée (notification DSI)',
            'vars' => ['numero' => 'n° de la demande', 'beneficiaire' => 'nom du bénéficiaire', 'etape' => 'libellé du visa', 'valideur' => 'nom du valideur, précédé de « par » (peut être vide)', 'avis' => 'avis motivé', 'lien' => 'URL de la demande dans SimCity'],
            'subject' => 'Demande {numero} refusée', 'title' => 'Demande refusée',
            'body' => '<p>La demande <strong>{numero}</strong> ({beneficiaire}) a été refusée au visa « {etape} »{valideur}.</p><p>Avis : {avis}</p><p style="font-size:13px;color:#666;"><a href="{lien}" style="color:#4f46e5;">Ouvrir la demande dans SimCity</a></p>'],
        'suivi' => ['label' => 'Liens de suivi (rappel au demandeur)',
            'vars' => ['liste' => 'liste HTML des demandes en cours'],
            'subject' => 'Vos demandes de téléphone en cours', 'title' => 'Vos liens de suivi',
            'body' => '<p>Voici les demandes de téléphone en cours associées à votre adresse et leur lien de suivi :</p>{liste}<p style="font-size:13px;color:#666;">Ces liens sont personnels — ne les partagez pas.</p>'],
        'bon' => ['label' => 'Signature d\'un bon (remise/restitution)',
            'vars' => ['prenom' => 'prénom du signataire', 'type_bon' => '« remise » ou « restitution »', 'numero' => 'n° du bon', 'bouton' => 'bouton « Signer le bon »', 'lien' => 'URL du lien de signature', 'expiration' => 'paragraphe de validité (peut être vide)'],
            'subject' => 'Signature requise — Bon de {type_bon} {numero}', 'title' => 'Signature requise',
            'body' => '<p>Bonjour {prenom},</p><p>Le bon de <strong>{type_bon} de matériel</strong> n° <strong>{numero}</strong> vous attend pour signature électronique.</p>{bouton}<p style="font-size:13px;color:#666;">Ou copiez ce lien dans votre navigateur :<br><a href="{lien}" style="color:#4f46e5;">{lien}</a></p>{expiration}'],
    ];
}

// Données fictives de démonstration pour chaque gabarit — utilisées par
// l'e-mail de test et l'aperçu des gabarits.
function mailDemoVars($pdo): array {
    $url = h(baseUrl($pdo));
    return [
        'test'     => [],
        'accuse'   => ['numero' => 'DEM-0000', 'beneficiaire' => 'Jean EXEMPLE', 'bouton' => requestMailButton($url, 'Suivre ma demande')],
        'nouvelle' => ['numero' => 'DEM-0000', 'type' => 'Première attribution', 'beneficiaire' => 'Jean EXEMPLE', 'fonction' => ' (Chargé de mission)', 'email_beneficiaire' => '<br>E-mail : jean.exemple@exemple.fr', 'service' => 'DSI', 'demandeur' => 'Marie DÉMO', 'email_demandeur' => 'marie.demo@exemple.fr', 'bouton' => requestMailButton($url, 'Qualifier la demande')],
        'visa'     => ['validateur' => ' Marie DÉMO', 'rappel' => '', 'numero' => 'DEM-0000', 'type' => 'Première attribution', 'beneficiaire' => 'Jean EXEMPLE', 'service' => ' — service DSI', 'etape' => 'Direction du service', 'bouton' => requestMailButton($url, 'Examiner et viser la demande'), 'lien' => $url],
        'validee'  => ['numero' => 'DEM-0000', 'beneficiaire' => 'Jean EXEMPLE', 'lien' => $url],
        'refusee'  => ['numero' => 'DEM-0000', 'beneficiaire' => 'Jean EXEMPLE', 'etape' => 'D.G.A. de secteur', 'valideur' => ' par Paul DÉMO', 'avis' => 'Dotation existante suffisante.', 'lien' => $url],
        'suivi'    => ['liste' => '<p style="margin:.5rem 0;"><strong>DEM-0000</strong> — Jean EXEMPLE <span style="color:#666;">(🟡 En validation)</span><br><a href="' . $url . '" style="color:#4f46e5;">' . $url . '</a></p>'],
        'bon'      => ['prenom' => 'Jean', 'type_bon' => 'remise', 'numero' => 'BR-0000', 'bouton' => requestMailButton($url, 'Signer le bon'), 'lien' => $url, 'expiration' => '<p style="font-size:13px;color:#666;">Ce lien est valable jusqu\'au <strong>' . date('d/m/Y', strtotime('+15 days')) . '</strong>.</p>'],
    ];
}

// Vrai si l'envoi de ce type d'e-mail est activé (activé par défaut ;
// désactivable dans Paramètres → Envoi d'e-mails).
function mailTplEnabled($pdo, $key): bool {
    return getSetting($pdo, "mail_tpl_{$key}_enabled", '1') !== '0';
}

// Rendu d'un gabarit : [sujet, corps HTML complet]. Les valeurs de $vars
// sont déjà échappées/HTML par l'appelant.
function mailRender($pdo, $key, array $vars = []): array {
    $t = mailTemplates()[$key];
    $subject = trim(getSetting($pdo, "mail_tpl_{$key}_subject", '')) ?: $t['subject'];
    $title   = trim(getSetting($pdo, "mail_tpl_{$key}_title", ''))   ?: $t['title'];
    $body    = trim(getSetting($pdo, "mail_tpl_{$key}_body", ''))    ?: $t['body'];
    $repl = [];
    foreach ($vars as $k => $v) $repl['{' . $k . '}'] = (string)$v;
    // Les liens des gabarits par défaut utilisent le violet d'origine :
    // on les aligne sur la couleur du bandeau configurée.
    $body = str_replace('#4f46e5', mailBannerColors($pdo)[0], strtr($body, $repl));
    return [strtr($subject, $repl), requestMailShell(strtr($title, $repl), $body, $pdo)];
}

// Circuit par défaut : les 4 visas du formulaire papier. Les valideurs
// variables (chef de service, DGA de secteur) viennent du référentiel des
// services ; la DSI et le DGS des paramètres généraux.
function requestDefaultSteps($pdo, $serviceId) {
    $svc = $serviceId ? $pdo->query("SELECT * FROM services WHERE id=" . (int)$serviceId)->fetch() : null;
    return [
        ['label' => 'Direction du service', 'name' => trim($svc['chef_name'] ?? ''), 'email' => trim($svc['chef_email'] ?? '')],
        ['label' => 'D.S.I.',               'name' => trim(getSetting($pdo, 'request_dsi_name', '')), 'email' => trim(getSetting($pdo, 'request_dsi_email', ''))],
        ['label' => 'D.G.A. de secteur',    'name' => trim($svc['dga_name'] ?? ''),  'email' => trim($svc['dga_email'] ?? '')],
        ['label' => 'D.G.S.',               'name' => trim(getSetting($pdo, 'request_dgs_name', '')), 'email' => trim(getSetting($pdo, 'request_dgs_email', ''))],
    ];
}

// Envoi (ou relance) de l'e-mail de visa au valideur d'une étape.
// Retourne true, ou un message d'erreur lisible.
function requestSendStepEmail($pdo, $req, $step, $isReminder = false) {
    if (empty($step['validator_email'])) return "Aucune adresse e-mail pour l'étape « {$step['label']} ».";
    if (!mailTplEnabled($pdo, 'visa')) return "L'envoi des e-mails « Visa requis » est désactivé (Paramètres → Envoi d'e-mails).";
    $url = baseUrl($pdo) . '?page=valider&token=' . $step['token'];
    [$subject, $html] = mailRender($pdo, 'visa', [
        'validateur'   => $step['validator_name'] ? ' ' . h($step['validator_name']) : '',
        'rappel'       => $isReminder ? '<p style="color:#c2410c;"><strong>Rappel :</strong> cette demande attend votre avis depuis plusieurs jours.</p>' : '',
        'numero'       => h($req['numero']),
        'type'         => h(requestTypeLabel($req['type'])),
        'beneficiaire' => h($req['agent_name']),
        'service'      => $req['service_name'] ? ' — service ' . h($req['service_name']) : '',
        'etape'        => h($step['label']),
        'bouton'       => requestMailButton($url, 'Examiner et viser la demande'),
        'lien'         => h($url),
    ]);
    $res = smtpSendMail($pdo, $step['validator_email'], ($isReminder ? 'Rappel — ' : '') . $subject, $html);
    if ($res === true) {
        $pdo->prepare("UPDATE request_steps SET " . ($isReminder ? 'reminded_at' : 'notified_at') . "=NOW() WHERE id=?")->execute([(int)$step['id']]);
    }
    return $res;
}

// Fait avancer le circuit d'une demande : notifie l'étape suivante en
// attente, ou clôt la demande en « validée » quand tous les visas sont posés.
function requestAdvance($pdo, $reqId) {
    $rq = $pdo->prepare("SELECT * FROM requests WHERE id=?"); $rq->execute([(int)$reqId]);
    $req = $rq->fetch();
    if (!$req) return;
    $st = $pdo->prepare("SELECT * FROM request_steps WHERE request_id=? AND decision IS NULL ORDER BY ordre ASC LIMIT 1");
    $st->execute([(int)$reqId]);
    if ($next = $st->fetch()) {
        $pdo->prepare("UPDATE requests SET status='en_validation', current_step=? WHERE id=?")->execute([(int)$next['ordre'], (int)$reqId]);
        // Un échec d'envoi ne doit pas passer sous silence : sans trace, un
        // « mail jamais reçu » est indiagnosticable (la colonne Notifié reste
        // à « — », mais personne ne sait pourquoi).
        $res = requestSendStepEmail($pdo, $req, $next);
        if ($res !== true) {
            $pdo->prepare("INSERT INTO history_logs (entity_type, entity_id, action_desc, agent_id, author) VALUES ('request', ?, ?, ?, 'Système')")
                ->execute([(int)$reqId, "⚠️ E-mail de visa « {$next['label']} » non envoyé : $res", $req['agent_id'] ?: null]);
        }
        return;
    }
    // Plus d'étape en attente : la demande est validée
    $pdo->prepare("UPDATE requests SET status='validee', current_step=0, closed_at=NOW() WHERE id=?")->execute([(int)$reqId]);
    $pdo->prepare("INSERT INTO history_logs (entity_type, entity_id, action_desc, agent_id, author) VALUES ('request', ?, ?, ?, 'Système')")
        ->execute([(int)$reqId, "✅ Demande {$req['numero']} validée — circuit de visas complet", $req['agent_id'] ?: null]);
    // Pas d'e-mail de suivi au demandeur à chaque étape : il consulte l'avancement
    // via son lien de suivi. Seule la boîte de base (DSI) est notifiée pour agir.
    $notify = trim(getSetting($pdo, 'request_notify_email', ''));
    if ($notify && mailTplEnabled($pdo, 'validee')) {
        $adm = baseUrl($pdo) . '?page=requests&view=' . (int)$reqId;
        [$subject, $html] = mailRender($pdo, 'validee', ['numero' => h($req['numero']), 'beneficiaire' => h($req['agent_name']), 'lien' => h($adm)]);
        smtpSendMail($pdo, $notify, $subject, $html);
    }
}

// Dotation actuelle d'un agent, en HTML autonome (affichable sur les pages
// publiques sans le CSS de l'application) — la plus-value vs le papier.
// $compact=true : version ANONYMISÉE pour le formulaire public — seul un
// comptage est révélé (nb de lignes, nb de matériels par type), jamais le
// détail (modèles, numéros, IMEI) : les demandeurs n'ont pas à voir qui a quoi.
function requestEquipmentHtml($pdo, $agentId, $compact = false) {
    if (!$agentId) return '';
    $dot = bonSnapshotItems($pdo, (int)$agentId);
    if (empty($dot['devices']) && empty($dot['lines'])) {
        return '<div style="font-size:.85rem;color:#64748b;font-style:italic;">Aucun équipement actuellement attribué à cet agent.</div>';
    }
    $html = '';
    if ($compact) {
        if ($n = count($dot['lines'])) {
            $html .= '<div style="margin-bottom:.3rem;font-size:.88rem;">📞 ' . $n . ' ligne' . ($n > 1 ? 's' : '') . ' mobile' . ($n > 1 ? 's' : '') . '</div>';
        }
        $byCat = [];
        foreach ($dot['devices'] as $it) {
            $cat = trim((string)($it['category'] ?? '')) ?: 'Matériel';
            $byCat[$cat] = ($byCat[$cat] ?? 0) + 1;
        }
        foreach ($byCat as $cat => $n) {
            $html .= '<div style="margin-bottom:.3rem;font-size:.88rem;">📱 ' . $n . ' × ' . h($cat) . '</div>';
        }
        return $html;
    }
    foreach ($dot['devices'] as $it) {
        $id = ' <span style="color:#94a3b8;font-size:.78rem;">IMEI ' . h($it['imei'] ?? '') . '</span>';
        $html .= '<div style="margin-bottom:.3rem;font-size:.88rem;">📱 ' . h(trim(($it['brand'] ?? '') . ' ' . ($it['name'] ?? ''))) . $id . '</div>';
    }
    foreach ($dot['lines'] as $it) {
        $tags = '';
        if (!empty($it['esim'])) $tags .= ' <span style="background:#ede9fe;color:#6d28d9;padding:0 4px;border-radius:3px;font-size:.72rem;">eSIM</span>';
        if (!empty($it['personal_device'])) $tags .= ' <span style="color:#94a3b8;font-size:.78rem;">(appareil personnel)</span>';
        $html .= '<div style="margin-bottom:.3rem;font-size:.88rem;">📞 ' . formatPhone($it['phone_number'] ?? '') . $tags . ' <span style="color:#94a3b8;font-size:.78rem;">' . h($it['plan_name'] ?? '') . '</span></div>';
    }
    return $html;
}

// Rapproche un bénéficiaire (e-mail prioritaire, sinon nom exact unique) d'un
// agent du référentiel. Retourne la ligne agent ou null. Partagé par le
// formulaire public (équipement, auto-lien) et l'AJAX.
function requestMatchAgent($pdo, $email, $fullName) {
    $email = trim((string)$email);
    if ($email !== '') {
        $st = $pdo->prepare("SELECT * FROM agents WHERE archived=0 AND email IS NOT NULL AND LOWER(email)=LOWER(?) LIMIT 1");
        $st->execute([$email]);
        if ($a = $st->fetch()) return $a;
    }
    $fullName = trim((string)$fullName);
    if ($fullName !== '') {
        $st = $pdo->prepare("SELECT * FROM agents WHERE archived=0 AND (LOWER(CONCAT(first_name,' ',last_name))=LOWER(?) OR LOWER(CONCAT(last_name,' ',first_name))=LOWER(?))");
        $st->execute([$fullName, $fullName]);
        $rows = $st->fetchAll();
        if (count($rows) === 1) return $rows[0];
    }
    return null;
}

// ── Relances automatiques « sans cron » (même principe que la sauvegarde) ──
// Déclenchées par le trafic, au plus une fois toutes les 6 h (verrou en
// base). Relance le valideur de l'étape courante muet depuis N jours.
function requestProcessReminders($pdo) {
    try {
        $days = max(1, (int)getSetting($pdo, 'request_reminder_days', 5));
        $claim = $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key='request_last_reminder_check' AND (setting_value='' OR setting_value < ?)");
        $claim->execute([date('Y-m-d H:i:s'), date('Y-m-d H:i:s', time() - 6 * 3600)]);
        if ($claim->rowCount() !== 1) return;
        $st = $pdo->prepare("SELECT s.* FROM request_steps s
            JOIN requests r ON s.request_id = r.id
            WHERE r.status='en_validation' AND s.ordre = r.current_step AND s.decision IS NULL
              AND s.notified_at IS NOT NULL
              AND COALESCE(s.reminded_at, s.notified_at) < DATE_SUB(NOW(), INTERVAL ? DAY)");
        $st->execute([$days]);
        foreach ($st->fetchAll() as $step) {
            $rq = $pdo->prepare("SELECT * FROM requests WHERE id=?"); $rq->execute([(int)$step['request_id']]);
            if ($req = $rq->fetch()) requestSendStepEmail($pdo, $req, $step, true);
        }
    } catch (Throwable $e) {
        error_log('SimCity relances demandes : ' . $e->getMessage());
    }
}
if (PHP_SAPI !== 'cli') requestProcessReminders($pdo);

// ─── Couleur principale du site (Paramètres → Général) ────────
// Vide = palette d'origine (violet). Sinon, toutes les variables CSS
// primaires et le logo SVG embarqué sont teintés avec cette couleur.
function uiPrimaryColor($pdo): string {
    $c = trim(getSetting($pdo, 'ui_primary_color', ''));
    return preg_match('/^#[0-9a-fA-F]{6}$/', $c) ? strtolower($c) : '';
}

// Mélange un hex avec du blanc (ratio > 0) ou du noir (ratio < 0).
function uiColorMix(string $hex, float $ratio): string {
    [$r, $g, $b] = sscanf($hex, '#%02x%02x%02x');
    $t = $ratio >= 0 ? 255 : 0; $a = abs($ratio);
    $f = fn($v) => str_pad(dechex((int)round($v + ($t - $v) * $a)), 2, '0', STR_PAD_LEFT);
    return '#' . $f($r) . $f($g) . $f($b);
}

function uiColorRgb(string $hex): string {
    [$r, $g, $b] = sscanf($hex, '#%02x%02x%02x');
    return "$r,$g,$b";
}

// Bloc <style> de surcharge des variables primaires ('' si couleur par
// défaut). Sélecteurs doublés (:root:root) : plus spécifiques que les
// définitions des feuilles de style, l'ordre d'inclusion est indifférent.
function uiPrimaryCssOverride($pdo): string {
    $c = uiPrimaryColor($pdo);
    if ($c === '') return '';
    $dark = uiColorMix($c, -0.22); $rgb = uiColorRgb($c);
    $l1 = uiColorMix($c, 0.45); $l2 = uiColorMix($c, 0.25); $lrgb = uiColorRgb($l1);
    return '<style>:root:root{--primary:' . $c . ';--primary-dark:' . $dark . ';--primary-dim:rgba(' . $rgb . ',.08);--primary-glow:rgba(' . $rgb . ',.35);--primary-soft:rgba(' . $rgb . ',.5);--ring:0 0 0 3px rgba(' . $rgb . ',.35);}'
         . ':root:root[data-theme="dark"]{--primary:' . $l1 . ';--primary-dark:' . $l2 . ';--primary-dim:rgba(' . $lrgb . ',.14);--primary-glow:rgba(' . $lrgb . ',.35);--primary-soft:rgba(' . $lrgb . ',.5);--ring:0 0 0 3px rgba(' . $lrgb . ',.35);}</style>';
}

// URL web du logo affiché sur les pages publiques de demande.
// Priorité au logo paramétré (celui des bons PDF), sinon le logo de l'app.
function requestLogoUrl($pdo) {
    $logo = getSetting($pdo, 'pdf_logo_path', '');
    if ($logo && file_exists($logo)) {
        // pdf_logo_path est un chemin serveur relatif au webroot (ex. uploads/…)
        return str_replace('\\', '/', $logo);
    }
    return 'index.php?logo=1';
}

// CSS partagé des pages publiques « demandes » (autonome, mobile).
// Aligné sur le design Sentinelle / la page de connexion SimCity :
// IBM Plex Sans, dégradé navy→bleu, indigo + slate, cartes arrondies.
function requestPublicCss() {
    return ':root{--primary:#4f46e5;--primary-dark:#4338ca;--primary-dim:rgba(79,70,229,.1);--primary-soft:rgba(79,70,229,.5);--primary-glow:rgba(79,70,229,.28);--text:#334155;--text-strong:#0f172a;--text-muted:#64748b;--text-light:#94a3b8;--border:#e2e8f0;--border-strong:#cbd5e1;--bg-soft:#f1f5f9;--page:#eef2f7;--radius:10px;--radius-lg:14px;--font:\'IBM Plex Sans\',-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--font);background:var(--page);min-height:100vh;padding:2rem 1rem;color:var(--text);-webkit-font-smoothing:antialiased;letter-spacing:-.005em;}
.wrap{max-width:640px;margin:0 auto;}
.brand{text-align:center;margin-bottom:1.25rem;background:#fff;border:1px solid var(--border);border-radius:var(--radius-lg);padding:1.15rem;box-shadow:0 1px 3px rgba(15,23,42,.06),0 1px 2px rgba(15,23,42,.04);}
.brand img{height:50px;max-width:240px;object-fit:contain;vertical-align:middle;}
.card{background:#fff;border-radius:var(--radius-lg);border:1px solid var(--border);padding:2rem;margin:0 auto 1.25rem;box-shadow:0 1px 3px rgba(15,23,42,.06),0 1px 2px rgba(15,23,42,.04);}
.card-head{display:flex;align-items:center;gap:.75rem;margin-bottom:.35rem;}
.card-head .ico{width:42px;height:42px;flex-shrink:0;border-radius:11px;background:var(--primary-dim);color:var(--primary);display:flex;align-items:center;justify-content:center;font-size:1.35rem;}
h2{font-family:var(--font);font-size:1.3rem;font-weight:700;color:var(--text-strong);line-height:1.25;}
.sub{color:var(--text-muted);font-size:.88rem;line-height:1.5;margin-bottom:1.5rem;}
label{display:block;font-size:.74rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.03em;margin:1.1rem 0 .4rem;}
input[type=text],input[type=email],select,textarea{width:100%;padding:.7rem .85rem;border:1px solid var(--border-strong);border-radius:var(--radius);font-size:.95rem;font-family:inherit;background:#fff;color:var(--text);transition:border-color .18s ease,box-shadow .18s ease;}
input:hover:not(:focus),select:hover:not(:focus),textarea:hover:not(:focus){border-color:var(--primary-soft);}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow);}
    input::placeholder,textarea::placeholder{color:var(--text-light);opacity:.75;font-style:italic;}
textarea{resize:vertical;min-height:96px;line-height:1.5;}
.field-hint{font-size:.78rem;color:var(--text-light);margin-top:.35rem;}
.radio-row{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:.15rem;}
.radio-row label{display:inline-flex;align-items:center;gap:.45rem;text-transform:none;letter-spacing:0;font-weight:500;font-size:.9rem;color:var(--text);margin:0;padding:.5rem .9rem;border:1px solid var(--border-strong);border-radius:999px;cursor:pointer;transition:border-color .15s,background-color .15s;}
.radio-row label:hover{border-color:var(--primary);}
.radio-row input{accent-color:var(--primary);width:16px;height:16px;}
.radio-row input:checked+span,.radio-row label:has(input:checked){border-color:var(--primary);background:var(--primary-dim);color:var(--primary-dark);font-weight:600;}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:.5rem;width:100%;padding:.95rem;background:var(--primary);color:#fff;border:1px solid var(--primary);border-radius:var(--radius);font-size:1rem;font-weight:600;cursor:pointer;text-align:center;text-decoration:none;transition:background-color .18s ease,transform .05s ease;}
.btn:hover{background:var(--primary-dark);border-color:var(--primary-dark);}
.btn:active{transform:translateY(1px);}
.btn-inline{width:auto;padding:.7rem 1.75rem;}
.error{background:#fef2f2;border:1px solid #fecaca;color:#dc2626;border-radius:var(--radius);padding:.9rem 1rem;margin-bottom:1.25rem;font-size:.9rem;display:flex;gap:.5rem;align-items:flex-start;}
.info{background:var(--bg-soft);border:1px solid var(--border);border-radius:var(--radius);padding:1rem 1.1rem;margin-bottom:1rem;font-size:.9rem;line-height:1.5;}
.nota{background:#fffbeb;border:1px solid #fde68a;color:#92400e;border-radius:var(--radius);padding:.9rem 1.1rem;font-size:.82rem;line-height:1.55;margin-top:1.5rem;}
.notice{border-radius:var(--radius);padding:.85rem 1rem;margin:.6rem 0 0;font-size:.86rem;line-height:1.5;}
.notice-warn{background:#fffbeb;border:1px solid #fde68a;color:#92400e;}
.btn-soft{display:inline-block;padding:.5rem 1rem;background:#fff;border:1px solid var(--border-strong);border-radius:var(--radius);font-size:.85rem;font-weight:600;color:var(--primary);cursor:pointer;}
.btn-soft:hover{border-color:var(--primary);}
.btn-soft:disabled{opacity:.6;cursor:default;}
.divider{height:1px;background:var(--border);margin:1.5rem 0;border:none;}
.step{display:flex;gap:.85rem;align-items:flex-start;padding:.7rem 0;border-bottom:1px solid var(--bg-soft);font-size:.9rem;}
.step:last-child{border-bottom:none;}
.step .ic{flex-shrink:0;width:26px;text-align:center;font-size:1.05rem;}
.step .meta{color:var(--text-light);font-size:.78rem;}
.tag{display:inline-block;padding:.18rem .65rem;border-radius:999px;font-size:.72rem;font-weight:600;white-space:nowrap;}
.tag-ok{background:#d1fae5;color:#065f46;} .tag-ko{background:#fee2e2;color:#991b1b;} .tag-wait{background:#dbeafe;color:#1e40af;} .tag-todo{background:#f1f5f9;color:#64748b;} .tag-warn{background:#fef3c7;color:#92400e;}
.success-hero{text-align:center;padding:1rem 0 .5rem;}
.success-hero .check{width:76px;height:76px;margin:0 auto 1rem;border-radius:50%;background:#d1fae5;color:#059669;display:flex;align-items:center;justify-content:center;font-size:2.4rem;}
.success-hero h2{color:#059669;}
.foot{text-align:center;color:var(--text-light);font-size:.78rem;margin-top:.5rem;}
.foot a{color:var(--text-muted);}
.name-grid{display:grid;grid-template-columns:1fr 1fr;gap:.6rem;}
.suggest{position:absolute;left:0;right:0;top:100%;z-index:30;background:#fff;border:1px solid var(--border-strong);border-radius:var(--radius);box-shadow:0 12px 28px rgba(15,23,42,.14);margin-top:.3rem;max-height:280px;overflow-y:auto;display:none;}
.suggest-item{padding:.6rem .8rem;cursor:pointer;border-bottom:1px solid var(--bg-soft);}
.suggest-item:last-child{border-bottom:none;}
.suggest-item:hover{background:var(--bg-soft);}
.s-name{font-size:.92rem;font-weight:600;color:var(--text-strong);}
.s-meta{font-size:.78rem;color:var(--text-light);margin-top:.1rem;}
.s-badge{display:inline-block;font-size:.64rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em;background:#d1fae5;color:#065f46;border-radius:999px;padding:.05rem .45rem;vertical-align:middle;margin-left:.35rem;}
.s-badge.s-ad{background:#dbeafe;color:#1e40af;}
.equip-panel{background:#eff6ff;border:1px solid #bfdbfe;border-radius:var(--radius);padding:.85rem 1rem;margin-top:.85rem;}
.equip-title{font-size:.76rem;font-weight:700;color:#1e40af;text-transform:uppercase;letter-spacing:.02em;margin-bottom:.5rem;}
@media(max-width:520px){.card{padding:1.5rem 1.25rem;}.name-grid{grid-template-columns:1fr;}}';
}

// Bandeau logo + nom d'app, commun aux pages publiques (design Sentinelle)
function requestPublicBrand($pdo) {
    $logo = h(requestLogoUrl($pdo));
    return '<div class="brand"><img src="' . $logo . '" alt="Logo"></div>';
}

// ─── AJAX PUBLIC : recherche de bénéficiaire (AD prioritaire + référentiel) ──
// Alimente l'autocomplétion du formulaire public. Sans authentification (le
// formulaire est public) : longueur minimale et nombre de résultats limités.
if (isset($_GET['ajax_request_lookup'])) {
    header('Content-Type: application/json; charset=utf-8');
    $q = trim($_GET['q'] ?? '');
    if (mb_strlen($q) < 2) { echo json_encode([]); exit; }
    $out = []; $seenEmail = [];

    // 1) Active Directory en priorité (via le compte de service)
    foreach (ldap_search_people($q, 8) as $p) {
        $name  = trim($p['display_name']) ?: trim($p['first_name'] . ' ' . $p['last_name']);
        $email = strtolower(trim($p['email']));
        $agent = requestMatchAgent($pdo, $email, $name);
        $out[] = ['first_name' => $p['first_name'], 'last_name' => $p['last_name'], 'name' => $name,
                  'email' => $email, 'fonction' => $p['title'], 'source' => 'ad', 'in_tool' => (bool)$agent];
        if ($email) $seenEmail[$email] = true;
    }

    // 2) Référentiel local (agents déjà connus, complète/remplace l'AD si absent)
    $like = '%' . $q . '%';
    $st = $pdo->prepare("SELECT a.first_name, a.last_name, a.fonction, a.email FROM agents a
        WHERE a.archived=0 AND (a.first_name LIKE ? OR a.last_name LIKE ?
              OR CONCAT(a.first_name,' ',a.last_name) LIKE ? OR CONCAT(a.last_name,' ',a.first_name) LIKE ?
              OR a.email LIKE ?) ORDER BY a.last_name, a.first_name LIMIT 8");
    $st->execute([$like, $like, $like, $like, $like]);
    foreach ($st->fetchAll() as $a) {
        $email = strtolower(trim((string)$a['email']));
        if ($email && isset($seenEmail[$email])) continue;   // déjà couvert par l'AD
        $out[] = ['first_name' => $a['first_name'], 'last_name' => $a['last_name'],
                  'name' => trim($a['first_name'] . ' ' . $a['last_name']),
                  'email' => $email, 'fonction' => (string)($a['fonction'] ?? ''), 'source' => 'local', 'in_tool' => true];
    }
    echo json_encode(array_slice($out, 0, 12));
    exit;
}

// ─── AJAX PUBLIC : équipement actuel d'un bénéficiaire déjà connu ────────────
// Révélé uniquement sur correspondance EXACTE (e-mail, ou nom complet unique) :
// le demandeur doit connaître l'identité précise — pas d'énumération à l'aveugle.
// Version compacte (sans IMEI/ICCID).
if (isset($_GET['ajax_request_equipment'])) {
    header('Content-Type: application/json; charset=utf-8');
    $agent = requestMatchAgent($pdo, $_GET['email'] ?? '', $_GET['name'] ?? '');
    if (!$agent) { echo json_encode(['found' => false]); exit; }
    echo json_encode(['found' => true,
        'name' => trim($agent['first_name'] . ' ' . $agent['last_name']),
        'html' => requestEquipmentHtml($pdo, (int)$agent['id'], true)]);
    exit;
}

// Demandes « en cours » (non closes) liées à une adresse (demandeur ou bénéficiaire).
function requestOpenByEmail($pdo, $email) {
    $email = fmtEmail($email);
    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) return [];
    $st = $pdo->prepare("SELECT numero, track_token, status, agent_name, created_at
        FROM requests
        WHERE status IN ('a_qualifier','en_validation','validee')
          AND (LOWER(requester_email)=? OR LOWER(agent_email)=?)
        ORDER BY created_at DESC");
    $st->execute([$email, $email]);
    return $st->fetchAll();
}

// ─── AJAX PUBLIC : « ai-je déjà des demandes ? » (prévention de doublon) ─────
// Ne renvoie qu'un COMPTE, aucun détail (garde-fou : le détail part par e-mail).
if (isset($_GET['ajax_request_has'])) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['count' => count(requestOpenByEmail($pdo, $_GET['email'] ?? ''))]);
    exit;
}

// ─── AJAX PUBLIC : envoi des liens de suivi par e-mail (lien magique) ────────
// Les détails (numéros, liens de suivi) ne sont JAMAIS affichés à l'écran : ils
// partent dans la boîte de l'adresse saisie, ce qui prouve qu'on la possède.
// Anti-« bombing » : au plus un envoi toutes les 5 min par adresse.
if (isset($_GET['ajax_request_send_links'])) {
    header('Content-Type: application/json; charset=utf-8');
    $email = fmtEmail(NV($_POST, 'email'));
    if ($email && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $recent = $pdo->prepare("SELECT COUNT(*) FROM history_logs WHERE entity_type='req_links' AND action_desc=? AND action_date > DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
        $recent->execute([$email]);
        $rows = ((int)$recent->fetchColumn() === 0) ? requestOpenByEmail($pdo, $email) : [];
        if ($rows) {
            $items = '';
            foreach ($rows as $r) {
                [$lbl, ] = requestStatusInfo($r['status']);
                $url = baseUrl($pdo) . '?page=demande_suivi&token=' . $r['track_token'];
                $items .= '<p style="margin:.5rem 0;"><strong>' . h($r['numero']) . '</strong> — ' . h($r['agent_name']) . ' <span style="color:#666;">(' . h($lbl) . ')</span><br><a href="' . h($url) . '">' . h($url) . '</a></p>';
            }
            if (mailTplEnabled($pdo, 'suivi')) {
                [$subject, $html] = mailRender($pdo, 'suivi', ['liste' => $items]);
                smtpSendMail($pdo, $email, $subject, $html);
            }
            $pdo->prepare("INSERT INTO history_logs (entity_type, entity_id, action_desc, author) VALUES ('req_links', 0, ?, 'Formulaire public')")->execute([$email]);
        }
    }
    // Réponse volontairement neutre (n'en dit pas plus que l'écran)
    echo json_encode(['ok' => true]);
    exit;
}

// ─── 2d. PAGE PUBLIQUE : FORMULAIRE DE DEMANDE ────────────────
if (isset($_GET['page']) && $_GET['page'] === 'demande') {
    $services = $pdo->query("SELECT id, name FROM services ORDER BY name")->fetchAll();
    $formError = null;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Pot de miel anti-robots : ce champ caché doit rester vide
        if (trim($_POST['website'] ?? '') !== '') { header('Location: ?page=demande'); exit; }
        // Bénéficiaire : prénom + nom séparés (pré-remplis depuis l'AD), fonction,
        // e-mail. Le nom complet stocké reste « Prénom Nom » (compat affichage).
        $firstName     = trim(strip_tags($_POST['agent_first_name'] ?? ''));
        $lastName      = trim(strip_tags($_POST['agent_last_name'] ?? ''));
        $agentName     = trim($firstName . ' ' . $lastName);
        $agentEmail    = fmtEmail(NV($_POST, 'agent_email'));
        $fonction      = trim(strip_tags($_POST['agent_fonction'] ?? ''));
        // Identité + e-mail du demandeur : l'e-mail sert UNIQUEMENT à lui envoyer
        // l'accusé de réception + le lien de suivi. N'intervient pas dans le circuit.
        $requesterName  = trim(strip_tags($_POST['requester_name'] ?? ''));
        $requesterEmail = fmtEmail(NV($_POST, 'requester_email'));
        $serviceId     = (int)($_POST['service_id'] ?? 0);
        $replAgent     = !empty($_POST['replace_agent']) ? 1 : 0;
        $replAgentName = $replAgent ? trim(strip_tags($_POST['replaced_agent_name'] ?? '')) : '';
        $replAgentEmail = $replAgent ? fmtEmail(NV($_POST, 'replaced_agent_email')) : null;
        if ($replAgentEmail !== null && !filter_var($replAgentEmail, FILTER_VALIDATE_EMAIL)) $replAgentEmail = null;
        $replDevice    = !empty($_POST['replace_device']) ? 1 : 0;
        // Motifs paramétrables (un par ligne dans les réglages)
        $motifsOk      = array_values(array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', getSetting($pdo, 'request_form_motifs', "Panne\nCasse\nPerte\nVol\nObsolescence")))));
        $motif         = ($replDevice && in_array($_POST['replace_motif'] ?? '', $motifsOk, true)) ? $_POST['replace_motif'] : null;
        $motivation    = trim(strip_tags($_POST['motivation'] ?? ''));
        $svcRow        = $serviceId ? $pdo->query("SELECT id, name FROM services WHERE id=" . (int)$serviceId)->fetch() : null;

        if ($lastName === '' || !$svcRow || $motivation === '') {
            $formError = "Veuillez remplir tous les champs obligatoires (nom du bénéficiaire, service et motivation).";
        } elseif ($requesterName === '') {
            $formError = "Indiquez vos prénom et nom (demandeur).";
        } elseif (!filter_var((string)$requesterEmail, FILTER_VALIDATE_EMAIL)) {
            $formError = "Indiquez votre adresse e-mail (demandeur) pour recevoir l'accusé de réception.";
        } elseif ($agentEmail !== null && !filter_var($agentEmail, FILTER_VALIDATE_EMAIL)) {
            $formError = "L'adresse e-mail du bénéficiaire n'est pas valide.";
        } elseif ($replDevice && !$motif) {
            $formError = "Précisez le motif du remplacement du téléphone existant.";
        } else {
            // Rapprochement avec le référentiel : e-mail prioritaire, sinon nom
            // exact unique (dans les deux ordres). Sinon la DSI liera à la main.
            $agentRow = requestMatchAgent($pdo, $agentEmail ?? '', $agentName);
            $agentId  = $agentRow ? (int)$agentRow['id'] : null;

            $type  = $replDevice ? 'renouvellement' : 'attribution';
            $track = bin2hex(random_bytes(32));
            $ins = $pdo->prepare("INSERT INTO requests (numero, type, agent_id, agent_name, agent_fonction, agent_email, service_id, service_name, replace_agent, replaced_agent_name, replaced_agent_email, replace_device, replace_motif, motivation, requester_name, requester_email, track_token)
                                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
            // Numéro MAX+1 sans verrou : on réessaie sur collision (comme les bons)
            for ($attempt = 0; ; $attempt++) {
                try {
                    $ins->execute([requestNumero($pdo), $type, $agentId, $agentName, $fonction ?: null, $agentEmail, (int)$svcRow['id'], $svcRow['name'],
                                   $replAgent, $replAgentName ?: null, $replAgentEmail, $replDevice, $motif, $motivation, $requesterName, $requesterEmail, $track]);
                    break;
                } catch (PDOException $e) {
                    if ($e->getCode() === '23000' && $attempt < 5) continue;
                    throw $e;
                }
            }
            $reqId  = (int)$pdo->lastInsertId();
            $numero = $pdo->query("SELECT numero FROM requests WHERE id=$reqId")->fetchColumn();
            $pdo->prepare("INSERT INTO history_logs (entity_type, entity_id, action_desc, agent_id, author) VALUES ('request', ?, ?, ?, 'Formulaire public')")
                ->execute([$reqId, "📥 Demande $numero déposée pour $agentName", $agentId]);

            // Deux e-mails à l'enregistrement (échec silencieux, la demande vit
            // dans l'application même sans SMTP) :
            $suivi = baseUrl($pdo) . '?page=demande_suivi&token=' . $track;
            // 1) Notification à l'adresse de base (« E-mail notifié à chaque
            //    nouvelle demande ») : c'est elle qui pilote la qualification.
            $notify = trim(getSetting($pdo, 'request_notify_email', ''));
            if ($notify && mailTplEnabled($pdo, 'nouvelle')) {
                $adm = baseUrl($pdo) . '?page=requests&view=' . $reqId;
                [$subject, $html] = mailRender($pdo, 'nouvelle', [
                    'numero' => h($numero), 'type' => h(requestTypeLabel($type)),
                    'beneficiaire' => h($agentName),
                    'fonction' => $fonction ? ' (' . h($fonction) . ')' : '',
                    'email_beneficiaire' => $agentEmail ? '<br>E-mail : ' . h($agentEmail) : '',
                    'service' => h($svcRow['name']),
                    'demandeur' => h($requesterName), 'email_demandeur' => h($requesterEmail),
                    'bouton' => requestMailButton($adm, 'Qualifier la demande'),
                ]);
                smtpSendMail($pdo, $notify, $subject, $html);
            }
            // 2) Accusé de réception au demandeur (l'e-mail qu'il a saisi) : simple
            //    confirmation + lien de suivi. N'intervient pas dans le circuit.
            if (mailTplEnabled($pdo, 'accuse')) {
                [$subject, $html] = mailRender($pdo, 'accuse', [
                    'numero' => h($numero), 'beneficiaire' => h($agentName),
                    'bouton' => requestMailButton($suivi, 'Suivre ma demande'),
                ]);
                smtpSendMail($pdo, $requesterEmail, $subject, $html);
            }

            header('Location: ?page=demande&ok=' . urlencode($numero) . '&t=' . $track); exit;
        }
    }
    $okNumero = trim($_GET['ok'] ?? '');
    $okTrack  = preg_replace('/[^a-zA-Z0-9]/', '', $_GET['t'] ?? '');
    // Textes paramétrables (repli sur les valeurs par défaut)
    $fTitle   = getSetting($pdo, 'request_form_title', 'Demande de téléphone portable');
    $fIntro   = getSetting($pdo, 'request_form_intro', "Attribution ou renouvellement — la demande suivra le circuit de validation habituel (Direction du service, D.S.I., D.G.A., D.G.S.).");
    $fMotivLbl = getSetting($pdo, 'request_form_motivation_label', "Motivation du besoin (astreinte, types de déplacement, fréquence d'utilisation…)");
    $fNota    = getSetting($pdo, 'request_form_nota', "Nous vous rappelons que l'attribution d'un téléphone portable relève des avantages en nature susceptibles de demande de justificatif par la Chambre Régionale des Comptes. Il vous appartient de bien évaluer le besoin et d'en contrôler l'usage.");
    $fSuccess = getSetting($pdo, 'request_form_success', "Votre demande a bien été transmise à la DSI. Un accusé de réception vous a été envoyé par e-mail ; vous pourrez suivre son avancement via le lien ci-dessous.");
    $fMotifs  = array_values(array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', getSetting($pdo, 'request_form_motifs', "Panne\nCasse\nPerte\nVol\nObsolescence")))));
    ?>
<!DOCTYPE html><html lang="fr"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?=h($fTitle)?> – SimCity</title>
<link rel="icon" type="image/svg+xml" href="index.php?logo=1"><?php echo uiPrimaryCssOverride($pdo); ?>
<link href="vendor/plex.css" rel="stylesheet">
<style><?=requestPublicCss()?></style>
</head><body>
<div class="wrap">
<?=requestPublicBrand($pdo)?>
<div class="card">
<?php if ($okNumero): ?>
    <div class="success-hero">
        <div class="check">✓</div>
        <h2>Demande enregistrée</h2>
        <p style="color:var(--text-muted);margin-top:.75rem;line-height:1.6;">Votre demande <strong style="color:var(--text-strong);"><?=h($okNumero)?></strong> a bien été enregistrée.<br><?=nl2br(h($fSuccess))?></p>
        <?php if ($okTrack): ?>
        <p style="margin-top:1.75rem;"><a class="btn btn-inline" href="?page=demande_suivi&token=<?=h($okTrack)?>">📍 Suivre ma demande</a></p>
        <?php endif; ?>
        <p style="margin-top:1.25rem;font-size:.85rem;"><a href="?page=demande" style="color:var(--primary);">Déposer une autre demande</a></p>
    </div>
<?php else: ?>
    <div class="card-head"><span class="ico">📱</span><h2><?=h($fTitle)?></h2></div>
    <div class="sub"><?=nl2br(h($fIntro))?></div>
    <?php if ($formError): ?><div class="error"><span>⚠️</span><span><?=h($formError)?></span></div><?php endif; ?>
    <form method="post" autocomplete="off">
        <input type="text" name="website" value="" style="display:none" tabindex="-1" aria-hidden="true">
        <label>Vos prénom et nom (demandeur) *</label>
        <div style="position:relative;">
            <input type="text" name="requester_name" id="req-name" required placeholder="Prénom Nom" autocomplete="off" value="<?=h($_POST['requester_name'] ?? '')?>">
            <div id="req-suggest" class="suggest"></div>
        </div>
        <label>Votre e-mail (demandeur) *</label>
        <input type="email" name="requester_email" id="req-email" required placeholder="prenom.nom@collectivite.fr" value="<?=h($_POST['requester_email'] ?? '')?>">
        <div class="field-hint">Pour recevoir l'accusé de réception et le lien de suivi. N'intervient pas dans le circuit de validation.</div>
        <div id="req-existing" style="display:none;"></div>

        <hr class="divider">
        <label>Service *</label>
        <select name="service_id" required>
            <option value="">— Sélectionner le service —</option>
            <?php foreach ($services as $s): ?>
            <option value="<?=$s['id']?>" <?=((int)($_POST['service_id'] ?? 0) === (int)$s['id']) ? 'selected' : ''?>><?=h($s['name'])?></option>
            <?php endforeach; ?>
        </select>
        <label>Bénéficiaire *</label>
        <?php if (ldap_auth_enabled()): ?>
        <div class="field-hint" style="margin:-.2rem 0 .5rem;">🔎 Commencez à taper le nom : l'annuaire propose l'agent et pré-remplit ses coordonnées si l'agent est dans la base (modifiables).</div>
        <?php endif; ?>
        <div style="position:relative;">
            <div class="name-grid">
                <input type="text" name="agent_first_name" id="bene-first" placeholder="Prénom" autocomplete="off" value="<?=h($_POST['agent_first_name'] ?? '')?>">
                <input type="text" name="agent_last_name" id="bene-last" required placeholder="Nom *" autocomplete="off" value="<?=h($_POST['agent_last_name'] ?? '')?>">
            </div>
            <div id="bene-suggest" class="suggest"></div>
        </div>
        <label>Fonction</label>
        <input type="text" name="agent_fonction" id="bene-fonction" placeholder="ex : Responsable voirie" value="<?=h($_POST['agent_fonction'] ?? '')?>">
        <label>E-mail du bénéficiaire</label>
        <input type="email" name="agent_email" id="bene-email" placeholder="prenom.nom@collectivite.fr" value="<?=h($_POST['agent_email'] ?? '')?>">
        <div id="bene-equip" class="equip-panel" style="display:none;"></div>

        <label>Remplacement d'un(e) agent sur ce poste ?</label>
        <div class="radio-row">
            <label><input type="radio" name="replace_agent" value="1" <?=!empty($_POST['replace_agent']) ? 'checked' : ''?> onchange="document.getElementById('repl-agent-name').style.display='block'"> Oui</label>
            <label><input type="radio" name="replace_agent" value="" <?=empty($_POST['replace_agent']) ? 'checked' : ''?> onchange="document.getElementById('repl-agent-name').style.display='none'"> Non</label>
        </div>
        <div id="repl-agent-name" style="display:<?=!empty($_POST['replace_agent']) ? 'block' : 'none'?>;">
            <label>Nom de l'agent remplacé</label>
            <?php if (ldap_auth_enabled()): ?>
            <div class="field-hint" style="margin:-.2rem 0 .5rem;">🔎 Commencez à taper le nom : l'annuaire propose l'agent remplacé.</div>
            <?php endif; ?>
            <div style="position:relative;">
                <input type="text" name="replaced_agent_name" id="repl-name" placeholder="Prénom Nom" autocomplete="off" value="<?=h($_POST['replaced_agent_name'] ?? '')?>">
                <div id="repl-suggest" class="suggest"></div>
            </div>
            <input type="hidden" name="replaced_agent_email" id="repl-email" value="<?=h($_POST['replaced_agent_email'] ?? '')?>">
            <div id="repl-equip" class="equip-panel" style="display:none;"></div>
        </div>

        <label>Remplacement d'un téléphone existant ?</label>
        <div class="radio-row">
            <label><input type="radio" name="replace_device" value="1" <?=!empty($_POST['replace_device']) ? 'checked' : ''?> onchange="document.getElementById('repl-motif').style.display='block'"> Oui</label>
            <label><input type="radio" name="replace_device" value="" <?=empty($_POST['replace_device']) ? 'checked' : ''?> onchange="document.getElementById('repl-motif').style.display='none'"> Non</label>
        </div>
        <div id="repl-motif" style="display:<?=!empty($_POST['replace_device']) ? 'block' : 'none'?>;">
            <label>Si oui, motif</label>
            <div class="radio-row">
                <?php foreach ($fMotifs as $mo): ?>
                <label><input type="radio" name="replace_motif" value="<?=h($mo)?>" <?=(($_POST['replace_motif'] ?? '') === $mo) ? 'checked' : ''?>> <?=h($mo)?></label>
                <?php endforeach; ?>
            </div>
        </div>

        <label><?=h($fMotivLbl)?> *</label>
        <textarea name="motivation" rows="4" required placeholder="Décrivez précisément le besoin"><?=h($_POST['motivation'] ?? '')?></textarea>

        <?php if (trim($fNota) !== ''): ?>
        <div class="nota"><strong>Nota :</strong> <?=nl2br(h($fNota))?></div>
        <?php endif; ?>

        <button type="submit" class="btn" style="margin-top:1.5rem;">📨 Envoyer la demande</button>
    </form>
    <script>
    (function(){
      const first = document.getElementById('bene-first'),
            last  = document.getElementById('bene-last'),
            fonction = document.getElementById('bene-fonction'),
            email = document.getElementById('bene-email'),
            sug   = document.getElementById('bene-suggest'),
            equip = document.getElementById('bene-equip');
      if (!last) return;
      const esc = s => { const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; };
      const hideSug = () => { sug.style.display='none'; sug.innerHTML=''; };
      let timer=null, equipTimer=null;

      function renderSug(items){
        if (!Array.isArray(items) || !items.length){ hideSug(); return; }
        sug.innerHTML = items.map((p,i) =>
          '<div class="suggest-item" data-i="'+i+'">'
          + '<div class="s-name">'+esc(p.name || ((p.first_name||'')+' '+(p.last_name||'')))
          + (p.in_tool ? ' <span class="s-badge">déjà dans l\'outil</span>' : '')
          + (p.source==='ad' ? ' <span class="s-badge s-ad">AD</span>' : '')+'</div>'
          + '<div class="s-meta">'+esc([p.fonction, p.email].filter(Boolean).join(' · '))+'</div>'
          + '</div>').join('');
        sug.style.display='block';
        [...sug.querySelectorAll('.suggest-item')].forEach(el=>{
          el.addEventListener('mousedown', e=>{ e.preventDefault(); pick(items[+el.dataset.i]); });
        });
      }
      function pick(p){
        first.value = p.first_name || '';
        last.value  = p.last_name || '';
        if (p.fonction) fonction.value = p.fonction;
        email.value = p.email || '';
        hideSug(); loadEquip();
      }
      function search(inp){
        const q = inp.value.trim();
        clearTimeout(timer);
        if (q.length < 2){ hideSug(); return; }
        timer = setTimeout(async ()=>{
          try { const r = await fetch('index.php?ajax_request_lookup=1&q='+encodeURIComponent(q)); renderSug(await r.json()); }
          catch(e){ hideSug(); }
        }, 250);
      }
      function loadEquip(){
        clearTimeout(equipTimer);
        equipTimer = setTimeout(async ()=>{
          const em = email.value.trim(), nm = (first.value.trim()+' '+last.value.trim()).trim();
          if (!em && last.value.trim()===''){ equip.style.display='none'; return; }
          try {
            const r = await fetch('index.php?ajax_request_equipment=1&email='+encodeURIComponent(em)+'&name='+encodeURIComponent(nm));
            const j = await r.json();
            if (j && j.found){ equip.innerHTML = '<div class="equip-title">📦 Équipement déjà attribué à '+esc(j.name)+'</div>'+(j.html||''); equip.style.display='block'; }
            else { equip.style.display='none'; equip.innerHTML=''; }
          } catch(e){ equip.style.display='none'; }
        }, 300);
      }
      first.addEventListener('input', ()=>search(first));
      last.addEventListener('input', ()=>search(last));
      first.addEventListener('blur', ()=>setTimeout(hideSug,150));
      last.addEventListener('blur', ()=>{ setTimeout(hideSug,150); loadEquip(); });
      email.addEventListener('blur', loadEquip);
      if (last.value.trim() || email.value.trim()) loadEquip();
    })();

    // ── Demandeur : même annuaire (AD + référentiel) ; la sélection ──
    //    remplit le nom complet et l'e-mail du demandeur.
    (function(){
      const name  = document.getElementById('req-name'),
            email = document.getElementById('req-email'),
            sug   = document.getElementById('req-suggest');
      if (!name || !sug) return;
      const esc = s => { const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; };
      const hideSug = () => { sug.style.display='none'; sug.innerHTML=''; };
      let timer=null;
      name.addEventListener('input', ()=>{
        const q = name.value.trim();
        clearTimeout(timer);
        if (q.length < 2){ hideSug(); return; }
        timer = setTimeout(async ()=>{
          try {
            const r = await fetch('index.php?ajax_request_lookup=1&q='+encodeURIComponent(q));
            const items = await r.json();
            if (!Array.isArray(items) || !items.length){ hideSug(); return; }
            sug.innerHTML = items.map((p,i) =>
              '<div class="suggest-item" data-i="'+i+'">'
              + '<div class="s-name">'+esc(p.name || ((p.first_name||'')+' '+(p.last_name||'')))
              + (p.source==='ad' ? ' <span class="s-badge s-ad">AD</span>' : '')+'</div>'
              + '<div class="s-meta">'+esc([p.fonction, p.email].filter(Boolean).join(' · '))+'</div>'
              + '</div>').join('');
            sug.style.display='block';
            [...sug.querySelectorAll('.suggest-item')].forEach(el=>{
              el.addEventListener('mousedown', e=>{
                e.preventDefault(); const p = items[+el.dataset.i];
                name.value = p.name || ((p.first_name||'')+' '+(p.last_name||'')).trim();
                if (p.email){ email.value = p.email; email.dispatchEvent(new Event('blur')); }
                hideSug();
              });
            });
          } catch(e){ hideSug(); }
        }, 250);
      });
      name.addEventListener('blur', ()=>setTimeout(hideSug,150));
    })();

    // ── Agent remplacé : recherche AD/référentiel + dotation actuelle ──
    //    Même annuaire que le bénéficiaire ; la dotation affichée est un
    //    simple comptage (nb lignes / matériels), jamais le détail.
    (function(){
      const name  = document.getElementById('repl-name'),
            email = document.getElementById('repl-email'),
            sug   = document.getElementById('repl-suggest'),
            equip = document.getElementById('repl-equip');
      if (!name) return;
      const esc = s => { const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; };
      const hideSug = () => { sug.style.display='none'; sug.innerHTML=''; };
      let timer=null, equipTimer=null;

      function loadEquip(){
        clearTimeout(equipTimer);
        equipTimer = setTimeout(async ()=>{
          const em = email.value.trim(), nm = name.value.trim();
          if (!em && !nm){ equip.style.display='none'; equip.innerHTML=''; return; }
          try {
            const r = await fetch('index.php?ajax_request_equipment=1&email='+encodeURIComponent(em)+'&name='+encodeURIComponent(nm));
            const j = await r.json();
            if (j && j.found){ equip.innerHTML = '<div class="equip-title">📦 Équipement déjà attribué à '+esc(j.name)+'</div>'+(j.html||''); equip.style.display='block'; }
            else { equip.style.display='none'; equip.innerHTML=''; }
          } catch(e){ equip.style.display='none'; }
        }, 300);
      }
      function pick(p){
        name.value  = p.name || ((p.first_name||'')+' '+(p.last_name||'')).trim();
        email.value = p.email || '';
        hideSug(); loadEquip();
      }
      name.addEventListener('input', ()=>{
        email.value = '';   // saisie manuelle : l'e-mail mémorisé ne vaut plus
        const q = name.value.trim();
        clearTimeout(timer);
        if (q.length < 2){ hideSug(); return; }
        timer = setTimeout(async ()=>{
          try {
            const r = await fetch('index.php?ajax_request_lookup=1&q='+encodeURIComponent(q));
            const items = await r.json();
            if (!Array.isArray(items) || !items.length){ hideSug(); return; }
            sug.innerHTML = items.map((p,i) =>
              '<div class="suggest-item" data-i="'+i+'">'
              + '<div class="s-name">'+esc(p.name || ((p.first_name||'')+' '+(p.last_name||'')))
              + (p.in_tool ? ' <span class="s-badge">déjà dans l\'outil</span>' : '')
              + (p.source==='ad' ? ' <span class="s-badge s-ad">AD</span>' : '')+'</div>'
              + '<div class="s-meta">'+esc([p.fonction, p.email].filter(Boolean).join(' · '))+'</div>'
              + '</div>').join('');
            sug.style.display='block';
            [...sug.querySelectorAll('.suggest-item')].forEach(el=>{
              el.addEventListener('mousedown', e=>{ e.preventDefault(); pick(items[+el.dataset.i]); });
            });
          } catch(e){ hideSug(); }
        }, 250);
      });
      name.addEventListener('blur', ()=>{ setTimeout(hideSug,150); loadEquip(); });
      if (name.value.trim() || email.value.trim()) loadEquip();
    })();

    // ── Garde-fou anti-doublon : à la saisie de l'e-mail demandeur, on signale
    //    l'existence de demandes SANS révéler le détail (envoi des liens par e-mail).
    (function(){
      const em = document.getElementById('req-email');
      const box = document.getElementById('req-existing');
      if (!em || !box) return;
      const valid = v => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v);
      async function check(){
        const v = em.value.trim();
        box.style.display='none'; box.innerHTML='';
        if (!valid(v)) return;
        try {
          const r = await fetch('index.php?ajax_request_has=1&email='+encodeURIComponent(v));
          const j = await r.json();
          if (j && j.count > 0) {
            box.innerHTML =
              '<div class="notice notice-warn">⚠️ Une ou plusieurs demandes sont déjà enregistrées avec cette adresse. '
              + 'Pour éviter un doublon, vérifiez leur avancement avant d\'en déposer une nouvelle.'
              + '<div style="margin-top:.6rem;"><button type="button" class="btn-soft" id="req-send">📧 Recevoir mes liens de suivi par e-mail</button>'
              + '<span id="req-sent" style="display:none;color:#065f46;font-weight:600;">✅ E-mail envoyé — consultez votre boîte.</span></div></div>';
            box.style.display='block';
            document.getElementById('req-send').addEventListener('click', async function(){
              this.disabled = true;
              const fd = new FormData(); fd.append('email', v);
              try { await fetch('index.php?ajax_request_send_links=1', {method:'POST', body:fd}); } catch(e){}
              this.style.display='none';
              document.getElementById('req-sent').style.display='inline';
            });
          }
        } catch(e){}
      }
      em.addEventListener('blur', check);
      if (em.value.trim()) check();
    })();
    </script>
<?php endif; ?>
</div>
</div>
</body></html>
<?php exit; }

// ─── 2e. PAGE PUBLIQUE : SUIVI D'UNE DEMANDE (demandeur) ──────
if (isset($_GET['page']) && $_GET['page'] === 'demande_suivi') {
    $token = preg_replace('/[^a-zA-Z0-9]/', '', $_GET['token'] ?? '');
    $req = null; $steps = [];
    if ($token) {
        $st = $pdo->prepare("SELECT * FROM requests WHERE track_token=?"); $st->execute([$token]);
        $req = $st->fetch();
        if ($req) {
            $ss = $pdo->prepare("SELECT * FROM request_steps WHERE request_id=? ORDER BY ordre");
            $ss->execute([(int)$req['id']]);
            $steps = $ss->fetchAll();
        }
    }
    ?>
<!DOCTYPE html><html lang="fr"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Suivi de demande – SimCity</title>
<link rel="icon" type="image/svg+xml" href="index.php?logo=1"><?php echo uiPrimaryCssOverride($pdo); ?>
<link href="vendor/plex.css" rel="stylesheet">
<style><?=requestPublicCss()?></style>
</head><body>
<div class="wrap">
<?=requestPublicBrand($pdo)?>
<div class="card">
<?php if (!$req): ?>
    <div class="error"><span>⛔</span><span>Ce lien de suivi est invalide.</span></div>
<?php else: [$stLbl, ] = requestStatusInfo($req['status']); ?>
    <div class="card-head"><span class="ico">📍</span><h2>Suivi — <?=h($req['numero'])?></h2></div>
    <div class="sub"><?=h(requestTypeLabel($req['type']))?> pour <strong><?=h($req['agent_name'])?></strong><?=$req['service_name'] ? ' — ' . h($req['service_name']) : ''?></div>
    <div class="info">
        Statut actuel : <strong><?=h($stLbl)?></strong><br>
        <span style="color:var(--text-light);font-size:.8rem;">Déposée le <?=date('d/m/Y à H:i', strtotime($req['created_at']))?></span>
        <?php if ($req['status'] === 'refusee' && $req['refusal_reason']): ?>
        <div style="margin-top:.5rem;color:#dc2626;font-size:.85rem;"><?=h($req['refusal_reason'])?></div>
        <?php endif; ?>
        <?php if ($req['status'] === 'livree'): ?>
        <div style="margin-top:.5rem;color:#059669;font-size:.85rem;">Le matériel a été remis<?=$req['delivered_at'] ? ' le ' . date('d/m/Y', strtotime($req['delivered_at'])) : ''?>.</div>
        <?php endif; ?>
    </div>
    <?php if ($req['status'] === 'a_qualifier'): ?>
    <div class="step"><span class="ic">🕐</span><div>La demande est en cours d'examen par la DSI avant le lancement du circuit de validation.</div></div>
    <?php endif; ?>
    <?php foreach ($steps as $s):
        if ($s['decision'] === 'approuve')      { $ic = '✅'; $txt = 'Visa favorable le ' . date('d/m/Y', strtotime($s['decided_at'])); }
        elseif ($s['decision'] === 'refuse')    { $ic = '⛔'; $txt = 'Visa défavorable le ' . date('d/m/Y', strtotime($s['decided_at'])); }
        elseif ($req['status'] === 'en_validation' && (int)$req['current_step'] === (int)$s['ordre']) { $ic = '⏳'; $txt = 'En attente de visa'; }
        elseif (in_array($req['status'], ['refusee', 'annulee'], true)) { $ic = '➖'; $txt = 'Sans objet'; }
        else { $ic = '•'; $txt = 'À venir'; }
    ?>
    <div class="step"><span class="ic"><?=$ic?></span>
        <div><strong><?=h($s['label'])?></strong><?=$s['validator_name'] ? ' — ' . h($s['validator_name']) : ''?><br><span class="meta"><?=h($txt)?></span></div>
    </div>
    <?php endforeach; ?>
<?php endif; ?>
</div>
</div>
</body></html>
<?php exit; }

// ─── 2f. PAGE PUBLIQUE : VISA D'UN VALIDEUR (lien magique) ────
if (isset($_GET['page']) && $_GET['page'] === 'valider') {
    $token = preg_replace('/[^a-zA-Z0-9]/', '', $_GET['token'] ?? '');
    $step = null; $req = null; $formError = null;
    if ($token) {
        $st = $pdo->prepare("SELECT * FROM request_steps WHERE token=?"); $st->execute([$token]);
        $step = $st->fetch();
        if ($step) {
            $rq = $pdo->prepare("SELECT * FROM requests WHERE id=?"); $rq->execute([(int)$step['request_id']]);
            $req = $rq->fetch();
        }
    }
    $stepActive = function($step, $req) {
        return $step && $req && $req['status'] === 'en_validation'
            && (int)$req['current_step'] === (int)$step['ordre'] && $step['decision'] === null
            && (!$step['expires_at'] || strtotime($step['expires_at']) >= time());
    };
    $isActive = $stepActive($step, $req);

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && $isActive) {
        $decision = ($_POST['decision'] ?? '') === 'refuse' ? 'refuse' : 'approuve';
        $name     = trim(strip_tags($_POST['validator_name'] ?? '')) ?: ($step['validator_name'] ?? '');
        $avis     = trim(strip_tags($_POST['avis'] ?? ''));
        if ($decision === 'refuse' && $avis === '') {
            $formError = "Un avis motivé est obligatoire pour refuser la demande.";
        } else {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '';
            $pdo->beginTransaction();
            try {
                // Verrou + re-vérification : une étape ne se vise qu'une seule fois
                $lock = $pdo->prepare("SELECT id FROM request_steps WHERE id=? AND decision IS NULL FOR UPDATE");
                $lock->execute([(int)$step['id']]);
                if ($lock->fetchColumn()) {
                    $pdo->prepare("UPDATE request_steps SET decision=?, avis=?, validator_name=?, decided_at=NOW(), ip=? WHERE id=?")
                        ->execute([$decision, $avis ?: null, $name ?: null, $ip, (int)$step['id']]);
                    $pdo->prepare("INSERT INTO history_logs (entity_type, entity_id, action_desc, agent_id, author) VALUES ('request', ?, ?, ?, ?)")
                        ->execute([(int)$req['id'],
                                   ($decision === 'approuve' ? '✅' : '⛔') . " Visa « {$step['label']} » " . ($decision === 'approuve' ? 'favorable' : 'défavorable') . " — demande {$req['numero']}",
                                   $req['agent_id'] ?: null, $name ?: 'Valideur']);
                    if ($decision === 'approuve') {
                        requestAdvance($pdo, (int)$req['id']);
                    } else {
                        $pdo->prepare("UPDATE requests SET status='refusee', refusal_reason=?, closed_at=NOW(), current_step=0 WHERE id=?")
                            ->execute([mb_substr("Refus au visa « {$step['label']} »" . ($name ? " ($name)" : ''), 0, 255), (int)$req['id']]);
                        // Le demandeur n'est pas notifié à chaque étape : il suit via son lien.
                        $notify = trim(getSetting($pdo, 'request_notify_email', ''));
                        if ($notify && mailTplEnabled($pdo, 'refusee')) {
                            $adm = baseUrl($pdo) . '?page=requests&view=' . (int)$req['id'];
                            [$subject, $html] = mailRender($pdo, 'refusee', [
                                'numero' => h($req['numero']), 'beneficiaire' => h($req['agent_name']),
                                'etape' => h($step['label']), 'valideur' => $name ? ' par ' . h($name) : '',
                                'avis' => h($avis), 'lien' => h($adm),
                            ]);
                            smtpSendMail($pdo, $notify, $subject, $html);
                        }
                    }
                }
                $pdo->commit();
            } catch (Exception $e) {
                if ($pdo->inTransaction()) $pdo->rollBack();
            }
            // Recharger l'état réel (double soumission, avancement du circuit…)
            $st = $pdo->prepare("SELECT * FROM request_steps WHERE token=?"); $st->execute([$token]); $step = $st->fetch();
            $rq = $pdo->prepare("SELECT * FROM requests WHERE id=?"); $rq->execute([(int)$step['request_id']]); $req = $rq->fetch();
            $isActive = false;
        }
    }

    $allSteps = $req ? $pdo->prepare("SELECT * FROM request_steps WHERE request_id=? ORDER BY ordre") : null;
    $steps = [];
    if ($allSteps) { $allSteps->execute([(int)$req['id']]); $steps = $allSteps->fetchAll(); }

    // « Mes validations » : toutes les demandes liées à cet e-mail de valideur
    $myList = [];
    if ($step && $step['validator_email']) {
        $ml = $pdo->prepare("SELECT s.token as stoken, s.label, s.decision, s.decided_at, s.ordre,
                r.numero, r.agent_name, r.service_name, r.type, r.status, r.current_step, r.created_at as req_created
            FROM request_steps s JOIN requests r ON s.request_id = r.id
            WHERE s.validator_email = ? AND s.id != ?
            ORDER BY (s.decision IS NULL AND r.status='en_validation' AND r.current_step = s.ordre) DESC, r.created_at DESC
            LIMIT 30");
        $ml->execute([$step['validator_email'], (int)$step['id']]);
        $myList = $ml->fetchAll();
    }
    ?>
<!DOCTYPE html><html lang="fr"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Visa d'une demande – SimCity</title>
<link rel="icon" type="image/svg+xml" href="index.php?logo=1"><?php echo uiPrimaryCssOverride($pdo); ?>
<link href="vendor/plex.css" rel="stylesheet">
<style><?=requestPublicCss()?>
.btn-approve{background:#059669;border-color:#059669;} .btn-approve:hover{background:#047857;border-color:#047857;}
.btn-refuse{background:#fff;color:#dc2626;border:1px solid #fecaca;} .btn-refuse:hover{background:#fef2f2;}
.btn-row{display:flex;gap:.75rem;margin-top:1.25rem;} .btn-row .btn{width:auto;flex:1;}
.dl{display:grid;grid-template-columns:190px 1fr;gap:.4rem .75rem;font-size:.9rem;}
.dl dt{color:var(--text-muted);font-size:.8rem;} .dl dd{margin:0;}
@media(max-width:520px){.dl{grid-template-columns:1fr;} .dl dt{margin-top:.4rem;}}
</style>
</head><body>
<div class="wrap">
<?=requestPublicBrand($pdo)?>
<div class="card">
<?php if (!$step || !$req): ?>
    <div class="error"><span>⛔</span><span>Ce lien de validation est invalide.</span></div>
<?php else: [$stLbl, ] = requestStatusInfo($req['status']); ?>
    <div class="card-head"><span class="ico">🖊️</span><h2>Visa « <?=h($step['label'])?> »</h2></div>
    <div class="sub">Demande de téléphone <strong><?=h($req['numero'])?></strong> — <?=h($stLbl)?></div>

    <?php if ($step['decision'] !== null): ?>
    <div class="info" style="background:<?=$step['decision'] === 'approuve' ? '#f0fdf4' : '#fef2f2'?>;">
        <?=$step['decision'] === 'approuve' ? '✅ <strong>Visa favorable enregistré</strong>' : '⛔ <strong>Visa défavorable enregistré</strong>'?>
        <?=$step['validator_name'] ? ' par ' . h($step['validator_name']) : ''?> le <?=date('d/m/Y à H:i', strtotime($step['decided_at']))?>.
        <?php if ($step['avis']): ?><div style="margin-top:.4rem;font-size:.85rem;color:#475569;">Avis : « <?=h($step['avis'])?> »</div><?php endif; ?>
    </div>
    <?php elseif (in_array($req['status'], ['refusee', 'annulee'], true)): ?>
    <div class="error" style="background:#f8fafc;border-color:#e2e8f0;color:#475569;">Cette demande est close (<?=$req['status'] === 'refusee' ? 'refusée à une étape précédente' : 'annulée par la DSI'?>) — aucun visa n'est attendu de votre part.</div>
    <?php elseif (!$isActive && $req['status'] === 'en_validation' && (int)$req['current_step'] < (int)$step['ordre']): ?>
    <div class="info" style="background:#fffbeb;">⏳ Ce n'est pas encore votre tour : la demande est au visa « <?=h($steps[(int)$req['current_step'] - 1]['label'] ?? '')?> ». Vous serez notifié(e) par e-mail quand elle arrivera à votre étape.</div>
    <?php elseif (!$isActive && $req['status'] === 'a_qualifier'): ?>
    <div class="info" style="background:#fffbeb;">🕐 La demande est encore en cours de qualification par la DSI.</div>
    <?php endif; ?>

    <!-- Détail de la demande -->
    <div class="info">
        <dl class="dl">
            <dt>Type</dt><dd><?=h(requestTypeLabel($req['type']))?></dd>
            <dt>Agent</dt><dd><strong><?=h($req['agent_name'])?></strong><?=$req['agent_fonction'] ? ' — ' . h($req['agent_fonction']) : ''?></dd>
            <dt>Service</dt><dd><?=h($req['service_name'] ?: '—')?></dd>
            <dt>Remplacement d'agent</dt><dd><?=$req['replace_agent'] ? 'Oui' . ($req['replaced_agent_name'] ? ' — ' . h($req['replaced_agent_name']) : '') : 'Non'?></dd>
            <dt>Remplacement de téléphone</dt><dd><?=$req['replace_device'] ? 'Oui — motif : ' . h($req['replace_motif'] ?: 'non précisé') : 'Non'?></dd>
            <dt>Déposée le</dt><dd><?=date('d/m/Y à H:i', strtotime($req['created_at']))?></dd>
        </dl>
        <div style="margin-top:.75rem;padding-top:.75rem;border-top:1px solid #e2e8f0;">
            <div style="font-size:.75rem;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:.3rem;">Motivation du besoin</div>
            <div style="font-size:.9rem;white-space:pre-line;"><?=h($req['motivation'])?></div>
        </div>
    </div>

    <?php if ($req['agent_id']): ?>
    <div class="info">
        <div style="font-size:.75rem;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:.5rem;">📦 Équipement actuel de l'agent (parc DSI)</div>
        <?=requestEquipmentHtml($pdo, (int)$req['agent_id'])?>
    </div>
    <?php endif; ?>

    <?php if ($req['replace_agent'] && ($replacedForVisa = requestMatchAgent($pdo, $req['replaced_agent_email'] ?? '', $req['replaced_agent_name'] ?? ''))): ?>
    <div class="info">
        <div style="font-size:.75rem;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:.5rem;">♻️ Équipement de l'agent remplacé (<?=h(trim($replacedForVisa['first_name'] . ' ' . $replacedForVisa['last_name']))?>)</div>
        <?=requestEquipmentHtml($pdo, (int)$replacedForVisa['id'])?>
    </div>
    <?php endif; ?>

    <!-- Circuit et avis déjà posés -->
    <div class="info" style="background:#fff;border:1px solid #e2e8f0;">
        <div style="font-size:.75rem;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:.4rem;">Circuit de validation</div>
        <?php foreach ($steps as $s):
            $isMe = ((int)$s['id'] === (int)$step['id']);
            if ($s['decision'] === 'approuve')   { $ic = '✅'; $tag = '<span class="tag tag-ok">Favorable</span>'; }
            elseif ($s['decision'] === 'refuse') { $ic = '⛔'; $tag = '<span class="tag tag-ko">Défavorable</span>'; }
            elseif ($req['status'] === 'en_validation' && (int)$req['current_step'] === (int)$s['ordre']) { $ic = '⏳'; $tag = '<span class="tag tag-wait">En cours</span>'; }
            else { $ic = '•'; $tag = '<span class="tag tag-todo">À venir</span>'; }
        ?>
        <div class="step" <?=$isMe ? 'style="background:#eef2ff;border-radius:8px;padding:.6rem .5rem;"' : ''?>>
            <span class="ic"><?=$ic?></span>
            <div style="flex:1;">
                <strong><?=h($s['label'])?></strong><?=$s['validator_name'] ? ' — ' . h($s['validator_name']) : ''?> <?=$isMe ? '<span style="color:var(--primary);font-size:.78rem;">(vous)</span>' : ''?><br>
                <span class="meta"><?=$s['decided_at'] ? date('d/m/Y H:i', strtotime($s['decided_at'])) : ''?></span>
                <?php if ($s['avis'] && $s['decision'] !== null): ?><div style="font-size:.82rem;color:#475569;margin-top:.2rem;">« <?=h($s['avis'])?> »</div><?php endif; ?>
            </div>
            <?=$tag?>
        </div>
        <?php endforeach; ?>
    </div>

    <?php if ($isActive): ?>
    <?php if ($formError): ?><div class="error">⚠️ <?=h($formError)?></div><?php endif; ?>
    <form method="post">
        <label>Votre nom</label>
        <input type="text" name="validator_name" required placeholder="Prénom Nom" value="<?=h($step['validator_name'] ?: '')?>">
        <label>Avis motivé sur la demande <span style="font-weight:400;text-transform:none;">(obligatoire en cas de refus)</span></label>
        <textarea name="avis" rows="3" placeholder="Votre avis…"><?=h($_POST['avis'] ?? '')?></textarea>
        <div class="btn-row">
            <button type="submit" name="decision" value="approuve" class="btn btn-approve">✅ Approuver</button>
            <button type="submit" name="decision" value="refuse" class="btn btn-refuse" onclick="return confirm('Confirmer le refus de cette demande ? Elle sera close et le demandeur informé.')">⛔ Refuser</button>
        </div>
        <p style="font-size:.75rem;color:var(--text-light);margin-top:.75rem;">Votre décision est horodatée et tracée. Ce lien vous est strictement personnel.</p>
    </form>
    <?php endif; ?>
<?php endif; ?>
</div>

<?php if ($myList): ?>
<div class="card">
    <div class="card-head"><span class="ico">🗂️</span><h2 style="font-size:1.1rem;">Mes autres demandes à viser</h2></div>
    <div class="sub">Toutes les demandes associées à votre adresse (<?=h($step['validator_email'])?>)</div>
    <?php foreach ($myList as $m):
        $pendingMine = ($m['decision'] === null && $m['status'] === 'en_validation' && (int)$m['current_step'] === (int)$m['ordre']);
        if ($pendingMine)                       { $tag = '<span class="tag tag-warn">⏳ À viser</span>'; }
        elseif ($m['decision'] === 'approuve')  { $tag = '<span class="tag tag-ok">Visé favorable</span>'; }
        elseif ($m['decision'] === 'refuse')    { $tag = '<span class="tag tag-ko">Visé défavorable</span>'; }
        elseif (in_array($m['status'], ['refusee', 'annulee'], true)) { $tag = '<span class="tag tag-todo">Close</span>'; }
        else                                    { $tag = '<span class="tag tag-todo">En amont</span>'; }
    ?>
    <div class="step">
        <span class="ic"><?=$pendingMine ? '🔔' : '📄'?></span>
        <div style="flex:1;">
            <a href="?page=valider&token=<?=h($m['stoken'])?>" style="color:var(--primary);font-weight:600;text-decoration:none;"><?=h($m['numero'])?></a>
            — <?=h($m['agent_name'])?> <span class="meta">(<?=h($m['service_name'] ?: '—')?>)</span><br>
            <span class="meta">Visa « <?=h($m['label'])?> » · déposée le <?=date('d/m/Y', strtotime($m['req_created']))?></span>
        </div>
        <?=$tag?>
    </div>
    <?php endforeach; ?>
</div>
<?php endif; ?>
</div>
</body></html>
<?php exit; }

// ─── 2g. RÉCAPITULATIF IMPRIMABLE D'UNE DEMANDE (admin) ───────
// Pièce justificative (CRC) : reprend le formulaire papier avec les visas
// électroniques posés. Lecture seule, réservé aux comptes connectés.
if (isset($_GET['page']) && $_GET['page'] === 'pdf_demande') {
    if (!isset($_SESSION['user_id'])) die("Accès refusé.");
    $rq = $pdo->prepare("SELECT * FROM requests WHERE id=?"); $rq->execute([(int)($_GET['id'] ?? 0)]);
    $req = $rq->fetch();
    if (!$req) die("Demande introuvable.");
    $ss = $pdo->prepare("SELECT * FROM request_steps WHERE request_id=? ORDER BY ordre");
    $ss->execute([(int)$req['id']]);
    $steps = $ss->fetchAll();
    $pdfLogo = getSetting($pdo, 'pdf_logo_path', '');
    [$stLbl, ] = requestStatusInfo($req['status']);
    ?>
<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Demande <?=h($req['numero'])?> — <?=h($req['agent_name'])?></title>
<style>
*{box-sizing:border-box;} body{font-family:sans-serif;padding:1.5rem;font-size:13px;color:#111;}
.header{display:grid;grid-template-columns:200px 1fr 200px;align-items:center;border-bottom:2px solid #000;padding-bottom:.75rem;margin-bottom:1.25rem;}
.header-logo{max-height:60px;max-width:170px;object-fit:contain;}
h1{margin:0;font-size:1.15rem;text-align:center;}
.section{margin-bottom:1.1rem;} .section h3{font-size:.92rem;margin-bottom:.4rem;border-bottom:1px solid #ddd;padding-bottom:.25rem;}
table{width:100%;border-collapse:collapse;margin-top:.4rem;}
th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;font-size:.82rem;vertical-align:top;}
th{background:#f5f5f5;}
.nota{font-size:.75rem;color:#444;border:1px solid #ddd;background:#fafafa;padding:.5rem .75rem;margin-top:1rem;line-height:1.5;}
.toolbar{display:flex;justify-content:flex-end;gap:.5rem;margin-bottom:1rem;}
.toolbar button{padding:.5rem 1rem;border-radius:8px;border:1px solid #cbd5e1;background:<?=uiPrimaryColor($pdo) ?: '#4f46e5'?>;color:#fff;font-size:.85rem;cursor:pointer;font-weight:600;}
@media print { @page{margin:1cm;} .no-print{display:none!important;} }
</style></head><body>
<div class="toolbar no-print"><button onclick="window.print()">🖨️ Imprimer</button></div>
<div class="header">
    <div><?=($pdfLogo && file_exists($pdfLogo)) ? '<img src="' . h($pdfLogo) . '" class="header-logo" alt="Logo">' : ''?></div>
    <div><h1>DEMANDE DE TÉLÉPHONE PORTABLE</h1>
        <p style="margin:.25rem 0 0;font-size:.85rem;font-weight:700;text-align:center;">N° <?=h($req['numero'])?> — <?=h($stLbl)?></p>
        <p style="margin:.15rem 0 0;font-size:.75rem;color:#555;text-align:center;">Déposée le <?=date('d/m/Y à H:i', strtotime($req['created_at']))?></p></div>
    <div></div>
</div>
<div class="section"><h3>👤 Demande</h3>
<table>
    <tr><th style="width:220px;">Type de demande</th><td><?=h(requestTypeLabel($req['type']))?></td></tr>
    <tr><th>Service</th><td><?=h($req['service_name'] ?: '—')?></td></tr>
    <tr><th>Nom de l'agent</th><td><strong><?=h($req['agent_name'])?></strong></td></tr>
    <tr><th>Fonction</th><td><?=h($req['agent_fonction'] ?: '—')?></td></tr>
    <tr><th>Remplacement d'un(e) agent sur ce poste</th><td><?=$req['replace_agent'] ? '☑ Oui' . ($req['replaced_agent_name'] ? ' — ' . h($req['replaced_agent_name']) : '') : '☐ Non'?></td></tr>
    <tr><th>Remplacement d'un téléphone existant</th><td><?=$req['replace_device'] ? '☑ Oui — motif : ' . h($req['replace_motif'] ?: 'non précisé') : '☐ Non'?></td></tr>
    <tr><th>Motivation du besoin</th><td style="white-space:pre-line;"><?=h($req['motivation'])?></td></tr>
    <tr><th>E-mail du bénéficiaire</th><td><?=h($req['agent_email'] ?: '—')?></td></tr>
    <tr><th>Demandeur</th><td><?=h($req['requester_name'] ?: '—')?><?=$req['requester_email'] ? ' — ' . h($req['requester_email']) : ''?></td></tr>
</table>
</div>
<div class="section"><h3>🖊️ Circuit de validation</h3>
<table>
    <thead><tr><th style="width:170px;">Visa</th><th style="width:170px;">Valideur</th><th style="width:110px;">Date</th><th style="width:90px;">Décision</th><th>Avis motivé</th></tr></thead>
    <tbody>
    <?php if (!$steps): ?><tr><td colspan="5" style="text-align:center;font-style:italic;color:#999;">Circuit non lancé</td></tr><?php endif; ?>
    <?php foreach ($steps as $s): ?>
    <tr>
        <td><?=h($s['label'])?></td>
        <td><?=h($s['validator_name'] ?: '—')?></td>
        <td><?=$s['decided_at'] ? date('d/m/Y H:i', strtotime($s['decided_at'])) : '—'?></td>
        <td><?=$s['decision'] === 'approuve' ? '✅ Favorable' : ($s['decision'] === 'refuse' ? '⛔ Défavorable' : '—')?></td>
        <td><?=h($s['avis'] ?: '')?></td>
    </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php if ($req['status'] === 'refusee' && $req['refusal_reason']): ?>
<p style="color:#dc2626;font-size:.82rem;margin-top:.5rem;"><strong><?=h($req['refusal_reason'])?></strong></p>
<?php endif; ?>
<?php if ($req['status'] === 'livree'): ?>
<p style="color:#059669;font-size:.82rem;margin-top:.5rem;"><strong>📦 Matériel remis<?=$req['delivered_at'] ? ' le ' . date('d/m/Y', strtotime($req['delivered_at'])) : ''?><?=$req['bon_id'] ? ' — voir bon de remise associé' : ''?>.</strong></p>
<?php endif; ?>
</div>
<div class="nota"><strong>Nota :</strong> Nous vous rappelons que l'attribution d'un téléphone portable relève des avantages en nature susceptibles de demande de justificatif par la Chambre Régionale des Comptes. Il vous appartient de bien évaluer le besoin et d'en contrôler l'usage. Les visas ci-dessus ont été recueillis électroniquement (liens personnels horodatés, adresse IP conservée).</div>
</body></html>
<?php exit; }

// ─── 3. GENERATION PDF (BON DE REMISE) ────────────────────────
function formatPhone($phone) { $val = preg_replace('/[^0-9]/', '', (string)$phone); return $val ? implode(' ', str_split($val, 2)) : ''; }
function baseUrl($pdo = null) {
    if ($pdo) {
        $custom = getSetting($pdo, 'site_url', '');
        if ($custom) return rtrim($custom, '/') . '/index.php';
    }
    $proto = isHttps() ? 'https' : 'http';
    $host  = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $script = str_replace('\\', '/', $_SERVER['SCRIPT_NAME'] ?? '/index.php');
    $dir   = rtrim(dirname($script), '/');
    if ($dir === '/' || $dir === '\\' || $dir === '.') $dir = '';
    return $proto . '://' . $host . $dir . '/index.php';
}

// ─── Helpers bons de remise / restitution ─────────────────────
// Numéro séquentiel : BR-2026-0042 (remise) / BT-2026-0042 (restitution)
function bonNumero($pdo, $type) {
    $prefix = ($type === 'remise' ? 'BR' : 'BT') . '-' . date('Y') . '-';
    $st = $pdo->prepare("SELECT MAX(CAST(SUBSTRING(numero, ?) AS UNSIGNED)) FROM bons WHERE numero LIKE ?");
    $st->execute([strlen($prefix) + 1, $prefix . '%']);
    return $prefix . str_pad((string)((int)$st->fetchColumn() + 1), 4, '0', STR_PAD_LEFT);
}

// Photographie la dotation actuelle d'un agent — contenu figé du bon
function bonSnapshotItems($pdo, $agentId) {
    $agentId = (int)$agentId;
    $agt = $pdo->query("SELECT a.first_name, a.last_name, a.email, s.name as service_name FROM agents a LEFT JOIN services s ON a.service_id=s.id WHERE a.id=$agentId")->fetch() ?: [];
    $lines = $pdo->query("SELECT l.id as line_id, l.phone_number, l.iccid, l.eid, l.activation_code, p.name as plan_name, COALESCE(l.personal_device,0) as personal_device, COALESCE(l.esim,0) as esim FROM mobile_lines l LEFT JOIN plan_types p ON l.plan_id=p.id WHERE l.agent_id=$agentId AND l.archived=0 ORDER BY l.id")->fetchAll();
    $devices = $pdo->query("SELECT DISTINCT d.id as device_id, d.imei, d.serial_number, d.inventory_label, m.brand, m.name, m.category FROM devices d LEFT JOIN models m ON d.model_id=m.id WHERE (d.agent_id=$agentId OR d.id IN (SELECT device_id FROM mobile_lines WHERE agent_id=$agentId AND device_id IS NOT NULL)) AND d.archived=0 ORDER BY d.id")->fetchAll();
    return [
        'agent'   => ['name' => trim(($agt['first_name'] ?? '') . ' ' . ($agt['last_name'] ?? '')), 'service' => $agt['service_name'] ?? '', 'email' => $agt['email'] ?? ''],
        'devices' => $devices,
        'lines'   => $lines,
    ];
}

// Identifiants d'équipements d'un bon ('d3', 'l5'…) depuis son snapshot figé.
// null = bon migré de l'ancien système, sans contenu enregistré.
function bonItemIds($b) {
    if (empty($b['items'])) return null;
    $it = json_decode($b['items'], true);
    $ids = [];
    foreach (($it['devices'] ?? []) as $d) if (!empty($d['device_id'])) $ids[] = 'd' . $d['device_id'];
    foreach (($it['lines'] ?? []) as $l) if (!empty($l['line_id'])) $ids[] = 'l' . $l['line_id'];
    return $ids;
}

// Un bon de remise signé est-il entièrement restitué ? Les restitutions
// signées se cumulent (plusieurs restitutions partielles peuvent clôturer).
function bonCycleClosed($pdo, $remise) {
    $st = $pdo->prepare("SELECT * FROM bons WHERE parent_id=? AND type='restitution' AND status='signed'");
    $st->execute([(int)$remise['id']]);
    $restits = $st->fetchAll();
    if (!$restits) return false;
    $rIds = bonItemIds($remise);
    if ($rIds === null) return true;   // bon migré sans snapshot : une restitution signée clôture
    $returned = [];
    foreach ($restits as $t) {
        $ids = bonItemIds($t);
        if ($ids === null) return true;
        $returned = array_merge($returned, $ids);
    }
    return !array_diff($rIds, $returned);
}

// Crée un bon en attente de signature (token valable 30 jours).
// Le visa DSI (signature de l'admin connecté) est copié dans le bon : le
// document reste immuable même si l'admin change sa signature plus tard.
function createBon($pdo, $type, $agentId, $items, $parentId = null) {
    $token   = bin2hex(random_bytes(32));
    $expires = date('Y-m-d H:i:s', strtotime('+30 days'));
    $dsiName = $_SESSION['admin_fullname'] ?? $_SESSION['username'] ?? 'DSI';
    $dsiSig  = null;
    if (!empty($_SESSION['user_id'])) {
        $st = $pdo->prepare("SELECT signature_data FROM users WHERE id=?");
        $st->execute([(int)$_SESSION['user_id']]);
        $dsiSig = $st->fetchColumn() ?: null;
    }
    // Le numéro est calculé par MAX+1 sans verrou : deux générations simultanées
    // peuvent viser le même numéro. On réessaie sur collision (contrainte UNIQUE).
    $ins = $pdo->prepare("INSERT INTO bons (numero, type, agent_id, parent_id, items, status, token, expires_at, created_by, dsi_name, dsi_signature_data) VALUES (?,?,?,?,?,'pending',?,?,?,?,?)");
    $itemsJson = json_encode($items, JSON_UNESCAPED_UNICODE);
    $createdBy = $_SESSION['username'] ?? 'admin';
    for ($attempt = 0; ; $attempt++) {
        try {
            $ins->execute([bonNumero($pdo, $type), $type, (int)$agentId, $parentId, $itemsJson, $token, $expires, $createdBy, $dsiName, $dsiSig]);
            break;
        } catch (PDOException $e) {
            // 23000 = violation de contrainte d'intégrité (numéro déjà pris)
            if ($e->getCode() === '23000' && $attempt < 5) continue;
            throw $e;
        }
    }
    return (int)$pdo->lastInsertId();
}

// ─── Réglages SMTP : surcharge par variables d'environnement ──
// (La constante SMTP_ENV_KEYS est déclarée plus haut, avant les pages
// publiques « demandes » qui envoient des e-mails.)

function smtp_env_locked(string $key): bool {
    $env = SMTP_ENV_KEYS[$key] ?? '';
    if ($env !== '' && getenv($env) !== false && getenv($env) !== '') return true;
    // Compat Sentinelle : MAIL_USE_TLS pilote smtp_secure si MAIL_SECURE absent
    return $key === 'smtp_secure' && getenv('MAIL_USE_TLS') !== false && getenv('MAIL_USE_TLS') !== '';
}

function smtpSetting($pdo, string $key, $default = '') {
    $env = SMTP_ENV_KEYS[$key] ?? '';
    if ($env !== '') {
        $v = getenv($env);
        if ($v !== false && $v !== '') return $v;
    }
    if ($key === 'smtp_secure') {
        $tls = getenv('MAIL_USE_TLS');
        if ($tls !== false && $tls !== '') return filter_var($tls, FILTER_VALIDATE_BOOLEAN) ? 'tls' : 'none';
    }
    return getSetting($pdo, $key, $default);
}

// ─── Envoi d'e-mail via SMTP (aucune dépendance externe) ──────
// Retourne true en cas de succès, sinon un message d'erreur lisible.
function smtpSendMail($pdo, $to, $subject, $htmlBody) {
    $host     = trim(smtpSetting($pdo, 'smtp_host', ''));
    $port     = (int)smtpSetting($pdo, 'smtp_port', 587);
    $secure   = strtolower(trim(smtpSetting($pdo, 'smtp_secure', 'tls')));   // tls | ssl | none
    $user     = smtpSetting($pdo, 'smtp_user', '');
    $pass     = smtpSetting($pdo, 'smtp_pass', '');
    $from     = trim(smtpSetting($pdo, 'smtp_from', '')) ?: $user;
    $fromName = smtpSetting($pdo, 'smtp_from_name', 'SimCity');
    if (!$host || !$from) return "SMTP non configuré — renseignez Paramètres → Envoi d'e-mails.";
    if (!filter_var($to, FILTER_VALIDATE_EMAIL)) return "Adresse destinataire invalide : $to";

    $errno = 0; $errstr = '';
    $fp = @stream_socket_client(($secure === 'ssl' ? "ssl://$host" : $host) . ":$port", $errno, $errstr, 10);
    if (!$fp) return "Connexion SMTP impossible ($host:$port) : $errstr";
    stream_set_timeout($fp, 10);

    $read = function() use ($fp) {
        $data = '';
        while ($line = fgets($fp, 1024)) { $data .= $line; if (isset($line[3]) && $line[3] === ' ') break; }
        return $data;
    };
    $cmd    = function($c) use ($fp, $read) { fwrite($fp, $c . "\r\n"); return $read(); };
    $expect = function($resp, $codes) { return in_array((int)substr($resp, 0, 3), (array)$codes, true); };

    try {
        if (!$expect($read(), 220)) return "Réponse SMTP inattendue à la connexion.";
        $ehloHost = $_SERVER['SERVER_NAME'] ?? 'localhost';
        if (!$expect($cmd("EHLO $ehloHost"), 250)) return "EHLO refusé par le serveur.";
        if ($secure === 'tls') {
            if (!$expect($cmd("STARTTLS"), 220)) return "STARTTLS refusé par le serveur.";
            if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) return "Échec de la négociation TLS.";
            if (!$expect($cmd("EHLO $ehloHost"), 250)) return "EHLO (après TLS) refusé.";
        }
        if ($user !== '') {
            if (!$expect($cmd("AUTH LOGIN"), 334)) return "AUTH LOGIN refusé.";
            if (!$expect($cmd(base64_encode($user)), 334)) return "Identifiant SMTP refusé.";
            if (!$expect($cmd(base64_encode($pass)), 235)) return "Authentification SMTP échouée (mot de passe ?).";
        }
        if (!$expect($cmd("MAIL FROM:<$from>"), 250)) return "Expéditeur refusé : $from";
        if (!$expect($cmd("RCPT TO:<$to>"), [250, 251])) return "Destinataire refusé : $to";
        if (!$expect($cmd("DATA"), 354)) return "Commande DATA refusée.";
        // Message-ID obligatoire : sans lui, nombre de filtres (Exchange
        // notamment) classent le message en spam ou le rejettent en silence.
        $midDomain = substr(strrchr($from, '@') ?: '', 1) ?: 'localhost';
        $headers = "From: =?UTF-8?B?" . base64_encode($fromName) . "?= <$from>\r\n"
                 . "To: <$to>\r\n"
                 . "Subject: =?UTF-8?B?" . base64_encode($subject) . "?=\r\n"
                 . "Message-ID: <" . bin2hex(random_bytes(16)) . "@" . $midDomain . ">\r\n"
                 . "MIME-Version: 1.0\r\n"
                 . "Content-Type: text/html; charset=UTF-8\r\n"
                 . "Content-Transfer-Encoding: base64\r\n"
                 . "Date: " . date('r') . "\r\n";
        if (!$expect($cmd($headers . "\r\n" . chunk_split(base64_encode($htmlBody)) . "."), 250)) return "Message refusé par le serveur.";
        $cmd("QUIT");
        return true;
    } finally {
        fclose($fp);
    }
}

// Annule les bons non signés d'un agent (la dotation a changé, ils ne
// correspondent plus à la réalité). Les bons signés ne sont jamais touchés.
function cancelPendingBons($pdo, $agentId, $reason = 'Dotation modifiée') {
    if (!$agentId) return;
    $st = $pdo->prepare("UPDATE bons SET status='cancelled', cancel_reason=? WHERE agent_id=? AND status='pending'");
    $st->execute([$reason, $agentId]);
    if ($st->rowCount() > 0) {
        $author = $_SESSION['username'] ?? 'Système';
        $pdo->prepare("INSERT INTO history_logs (entity_type, entity_id, action_desc, author) VALUES ('agent', ?, ?, ?)")
            ->execute([$agentId, "🚫 Bon(s) en attente annulé(s) — $reason. Générez un nouveau bon si nécessaire.", $author]);
    }
}

if (isset($_GET['page']) && $_GET['page'] === 'pdf_bon') {
    if (!isset($_SESSION['user_id'])) die("Accès refusé.");
    if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    $pdfLogo = getSetting($pdo, 'pdf_logo_path', '');

    // ── Résolution des bons à afficher — lecture seule, AUCUN effet de bord ──
    $bonRemise = null; $bonRestitution = null; $agentId = 0;
    if (!empty($_GET['bon_id'])) {
        $st = $pdo->prepare("SELECT * FROM bons WHERE id=?");
        $st->execute([(int)$_GET['bon_id']]);
        if ($b = $st->fetch()) {
            $agentId = (int)$b['agent_id'];
            if ($b['type'] === 'remise') {
                $bonRemise = $b;
                $st = $pdo->prepare("SELECT * FROM bons WHERE parent_id=? AND type='restitution' AND status!='cancelled' ORDER BY created_at DESC, id DESC LIMIT 1");
                $st->execute([$b['id']]);
                $bonRestitution = $st->fetch() ?: null;
            } else {
                $bonRestitution = $b;
                if ($b['parent_id']) {
                    $st = $pdo->prepare("SELECT * FROM bons WHERE id=?");
                    $st->execute([$b['parent_id']]);
                    $bonRemise = $st->fetch() ?: null;
                }
            }
        }
    } elseif (!empty($_GET['agent_id'])) {
        // Lien par agent : dernier cycle (dernier bon de remise non annulé)
        $agentId = (int)$_GET['agent_id'];
        $st = $pdo->prepare("SELECT * FROM bons WHERE agent_id=? AND type='remise' AND status!='cancelled' ORDER BY created_at DESC, id DESC LIMIT 1");
        $st->execute([$agentId]);
        $bonRemise = $st->fetch() ?: null;
        if ($bonRemise) {
            $st = $pdo->prepare("SELECT * FROM bons WHERE parent_id=? AND type='restitution' AND status!='cancelled' ORDER BY created_at DESC, id DESC LIMIT 1");
            $st->execute([$bonRemise['id']]);
            $bonRestitution = $st->fetch() ?: null;
        }
    }

    $agt = $agentId ? $pdo->query("SELECT a.*, s.name as service_name FROM agents a LEFT JOIN services s ON a.service_id=s.id WHERE a.id=$agentId")->fetch() : null;
    $agtName = $agt ? trim($agt['first_name'].' '.$agt['last_name']) : 'Agent inconnu';

    // ── Aucun bon à afficher : écran d'information + génération ──
    if (!$bonRemise && !$bonRestitution) {
        $dotation = $agt ? bonSnapshotItems($pdo, $agentId) : null;
        $hasDotation = $dotation && (!empty($dotation['devices']) || !empty($dotation['lines']));
        ?>
        <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Bon de remise — <?=h($agtName)?></title>
        <style>
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f8fafc;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem;margin:0;}
        .card{background:#fff;border-radius:14px;padding:2rem;max-width:480px;width:100%;box-shadow:0 4px 20px rgba(0,0,0,.08);text-align:center;}
        h2{font-size:1.2rem;color:#1e293b;margin:0 0 1rem;}
        p{color:#475569;font-size:.92rem;line-height:1.6;}
        .btn{display:inline-block;margin-top:1rem;padding:.75rem 1.75rem;background:<?=uiPrimaryColor($pdo) ?: '#4f46e5'?>;color:#fff;border:none;border-radius:9px;font-size:.95rem;font-weight:600;cursor:pointer;}
        </style></head><body>
        <div class="card">
            <h2>📄 Bon de remise — <?=h($agtName)?></h2>
            <?php if (!$agt): ?>
                <p>⛔ Agent introuvable.</p>
            <?php elseif (!$hasDotation): ?>
                <p>ℹ️ Aucun bon n'existe pour cet agent et aucun équipement ne lui est attribué.<br>Attribuez d'abord une ligne ou un matériel, puis générez le bon de remise.</p>
            <?php else: ?>
                <p>Aucun bon n'a encore été généré pour cet agent.<br>Sa dotation actuelle : <strong><?=count($dotation['devices'])?> matériel(s)</strong> et <strong><?=count($dotation['lines'])?> ligne(s)</strong>.</p>
                <form method="post" action="index.php">
                    <?=csrf_field()?>
                    <input type="hidden" name="_entity" value="bon">
                    <input type="hidden" name="_action" value="generate_remise">
                    <input type="hidden" name="agent_id" value="<?=$agentId?>">
                    <button type="submit" class="btn">📄 Générer le bon de remise</button>
                </form>
            <?php endif; ?>
        </div>
        </body></html>
        <?php exit;
    }

    // Libellé de statut affiché à la place du QR code quand la signature n'est plus possible
    function bonStatusLabel($bon) {
        if ($bon['status'] === 'signed')    return '✅ Signé le '.date('d/m/Y H:i', strtotime($bon['signed_at']));
        if ($bon['status'] === 'cancelled') return '🚫 Annulé';
        if ($bon['expires_at'] && strtotime($bon['expires_at']) < time()) return '⏰ Lien de signature expiré';
        return '⏳ En attente de signature';
    }

    // Tableau des équipements depuis le snapshot figé du bon
    function equipTable($items) {
        $devices = $items['devices'] ?? []; $lines = $items['lines'] ?? [];
        $html = '<table><thead><tr><th>Type</th><th>Détails</th><th>Identifiant</th></tr></thead><tbody>';
        foreach($devices as $d) {
            $devId = htmlspecialchars(!empty($d['inventory_label']) ? 'Inv: '.$d['inventory_label'].' | S/N: '.($d['serial_number']?:$d['imei']) : 'IMEI: '.$d['imei'].(!empty($d['serial_number'])?' | S/N: '.$d['serial_number']:''));
            $html .= '<tr><td>Matériel</td><td>'.htmlspecialchars(($d['brand']??'').' '.($d['name']??'')).'</td><td>'.$devId.'</td></tr>';
        }
        foreach($lines as $l) {
            if(!empty($l['personal_device'])) {
                $html .= '<tr><td>Tél. perso<br><small>(BYOD)</small></td><td>'.htmlspecialchars($l['plan_name']?:'Forfait inconnu').'</td><td>📲 Appareil personnel<br><small>N° : '.formatPhone($l['phone_number']).'</small></td></tr>';
            } elseif(!empty($l['esim'])) {
                $detail = 'N° : '.formatPhone($l['phone_number']);
                if(!empty($l['iccid'])) $detail .= '<br><small>ICCID : '.htmlspecialchars($l['iccid']).'</small>';
                if(!empty($l['eid']))   $detail .= '<br><small>EID : '.htmlspecialchars($l['eid']).'</small>';
                $html .= '<tr><td>Abonnement<br><small style="background:#ede9fe;color:#6d28d9;padding:1px 4px;border-radius:3px;">eSIM</small></td><td>'.htmlspecialchars($l['plan_name']?:'Forfait inconnu').'</td><td>'.$detail.'</td></tr>';
            } else {
                $detail = 'N° : '.formatPhone($l['phone_number']);
                if(!empty($l['iccid'])) $detail .= '<br><small>ICCID : '.htmlspecialchars($l['iccid']).'</small>';
                $html .= '<tr><td>Abonnement<br><small style="background:#e0f2fe;color:#0369a1;padding:1px 4px;border-radius:3px;">SIM</small></td><td>'.htmlspecialchars($l['plan_name']?:'Forfait inconnu').'</td><td>'.$detail.'</td></tr>';
            }
        }
        if ($items === null) $html .= '<tr><td colspan="3" style="text-align:center;font-style:italic;color:#999;">Contenu non enregistré (bon issu de l\'ancien système)</td></tr>';
        elseif (!$devices && !$lines) $html .= '<tr><td colspan="3" style="text-align:center;font-style:italic;color:#999;">Aucun équipement</td></tr>';
        return $html . '</tbody></table>';
    }

    // Rendu complet d'un bon (en-tête, bénéficiaire, équipements, signatures)
    function renderBonSection($pdo, $bon, $agt) {
        global $pdfLogo;
        $type  = $bon['type'];
        $items = $bon['items'] ? json_decode($bon['items'], true) : null;
        $isPending = $bon['status'] === 'pending' && (!$bon['expires_at'] || strtotime($bon['expires_at']) >= time());
        $title = $type === 'remise' ? 'BON DE REMISE DE MATÉRIEL' : 'BON DE RESTITUTION DE MATÉRIEL';
        $benefName    = ($items['agent']['name'] ?? '')    ?: ($agt ? trim($agt['first_name'].' '.$agt['last_name']) : 'Agent inconnu');
        $benefService = ($items['agent']['service'] ?? '') ?: ($agt['service_name'] ?? '');
        $benefEmail   = ($items['agent']['email'] ?? '')   ?: ($agt['email'] ?? '');

        echo '<div class="header">
            <div>'.($pdfLogo && file_exists($pdfLogo) ? '<img src="'.htmlspecialchars($pdfLogo).'" class="header-logo" alt="Logo">' : '').'</div>
            <div class="header-text"><h1>'.$title.'</h1>
                <p style="margin:.25rem 0 0;font-size:.85rem;font-weight:700;">N° '.htmlspecialchars($bon['numero']?:'—').'</p>
                <p style="margin:.15rem 0 0;font-size:.75rem;color:#555;">Généré le '.date('d/m/Y', strtotime($bon['created_at'])).'</p></div>
            <div class="qr-wrap">';
        if ($isPending) {
            $url = baseUrl($pdo).'?page=sign&token='.$bon['token'];
            echo '<div id="qr-'.(int)$bon['id'].'"></div>
                  <a href="'.htmlspecialchars($url).'" style="display:block;margin-top:3px;font-size:.75rem;color:'.(uiPrimaryColor($pdo) ?: '#4f46e5').';text-decoration:none;">Signer en ligne</a>';
        } else {
            echo '<div style="font-size:.8rem;font-weight:600;">'.bonStatusLabel($bon).'</div>';
        }
        echo '</div></div>';

        if ($bon['status'] === 'cancelled') {
            echo '<div style="border:2px solid #dc2626;color:#dc2626;padding:.5rem .75rem;margin-bottom:1rem;font-weight:700;">🚫 BON ANNULÉ'.($bon['cancel_reason'] ? ' — '.htmlspecialchars($bon['cancel_reason']) : '').'</div>';
        }

        echo '<div class="section"><h3>👤 Bénéficiaire</h3><p><strong>'.htmlspecialchars($benefName).'</strong><br>Service : '.htmlspecialchars($benefService?:'Non assigné').' | Email : '.htmlspecialchars($benefEmail?:'Non renseigné').'</p></div>';
        echo '<div class="section"><h3>📱 '.($type==='remise' ? 'Équipements confiés' : ($bon['status']==='signed' ? 'Équipements restitués' : 'Équipements à restituer')).'</h3>'.equipTable($items).'</div>';
        echo '<p class="mention">'.($type==='remise'
            ? 'Je soussigné(e) reconnais avoir reçu le matériel et/ou les abonnements désignés ci-dessus et m\'engage à en faire un usage professionnel et à les restituer sur demande.'
            : 'Je soussigné(e) certifie avoir restitué le matériel et/ou les abonnements désignés ci-dessus en bon état de fonctionnement.').'</p>';
        echo '<div class="sig-row">';
        echo '<div class="sig-box">Signature de l\'Agent :'
            . ($bon['status']==='signed' && $bon['signature_data'] ? '<img class="sig-image" src="'.htmlspecialchars($bon['signature_data']).'" alt="signature"><div class="sig-name">'.htmlspecialchars($bon['signer_name']).' — '.date('d/m/Y H:i', strtotime($bon['signed_at'])).'</div>' : '<br><br><br>')
            . '</div>';
        echo '<div class="sig-box">Visa de la DSI :'
            . (!empty($bon['dsi_signature_data']) ? '<img class="sig-image" src="'.htmlspecialchars($bon['dsi_signature_data']).'" alt="visa DSI">' : '')
            . '<div class="sig-name">'.htmlspecialchars($bon['dsi_name'] ?: ($bon['created_by'] ?: '')).'</div></div>';
        echo '</div>';
    }

    // QR codes à générer côté client (uniquement pour les bons signables)
    $qrTargets = [];
    foreach ([$bonRemise, $bonRestitution] as $b) {
        if ($b && $b['status'] === 'pending' && (!$b['expires_at'] || strtotime($b['expires_at']) >= time())) {
            $qrTargets['qr-'.(int)$b['id']] = baseUrl($pdo).'?page=sign&token='.$b['token'];
        }
    }
    ?>
    <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Bons <?=h(($bonRemise['numero'] ?? $bonRestitution['numero'] ?? ''))?> - <?=h($agtName)?></title>
    <style>
        *{box-sizing:border-box;}
        body{font-family:sans-serif;padding:1.5rem;font-size:13px;}
        .header{display:grid;grid-template-columns:200px 1fr 200px;align-items:center;border-bottom:2px solid #000;padding-bottom:.75rem;margin-bottom:1.25rem;}
        .header-logo{max-height:60px;max-width:170px;object-fit:contain;}
        .header-text{text-align:center;} h1{margin:0;font-size:1.2rem;}
        .section{margin-bottom:1.25rem;}
        .section h3{font-size:.95rem;margin-bottom:.5rem;border-bottom:1px solid #ddd;padding-bottom:.25rem;}
        table{width:100%;border-collapse:collapse;margin-top:.5rem;}
        th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;font-size:.82rem;}
        th{background:#f5f5f5;}
        .sig-row{display:flex;justify-content:space-between;gap:1rem;margin-top:1rem;}
        .sig-box{border:1px dashed #999;flex:1;min-height:100px;padding:8px;font-size:.8rem;}
        .sig-box .sig-name{font-size:.75rem;color:#555;margin-top:.3rem;}
        .sig-image{max-height:80px;max-width:180px;display:block;margin-top:4px;}
        .qr-wrap{text-align:right;font-size:.7rem;color:#777;}
        .qr-wrap img{display:block;margin-left:auto;}
        .divider{border:none;border-top:2px dashed #aaa;margin:1.5rem 0;page-break-after:always;}
        .bon-title{text-align:center;font-size:1rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;margin-bottom:1rem;padding:.4rem;background:#f5f5f5;border:1px solid #ddd;}
        .mention{font-size:.78rem;margin:.75rem 0;color:#444;line-height:1.5;}
        .qr-wrap{text-align:right;font-size:.65rem;color:#777;line-height:1.4;}
        .qr-wrap canvas, .qr-wrap img{display:block;margin-left:auto;margin-bottom:2px;}
        .qr-url{font-size:.6rem;word-break:break-all;color:#555;max-width:130px;display:block;margin-top:3px;}
        .toolbar{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:10px;padding:.75rem 1rem;margin-bottom:1.25rem;}
        .toolbar .tb-status{font-size:.8rem;color:#475569;}
        .toolbar form{display:inline;margin:0;}
        .toolbar button{padding:.5rem 1rem;border-radius:8px;border:1px solid #cbd5e1;background:#fff;font-size:.85rem;cursor:pointer;font-weight:600;}
        .toolbar button.tb-primary{background:<?=uiPrimaryColor($pdo) ?: '#4f46e5'?>;border-color:<?=uiPrimaryColor($pdo) ?: '#4f46e5'?>;color:#fff;}
        @media print {
            @page { margin: 1cm; }
            body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            a[href]::after { content: none !important; }
            .no-print { display: none !important; }
        }
    </style>
    <?php
    // Chercher qrcode.min.js localement
    $qrJsPath = null;
    foreach(['qrcode.min.js','js/qrcode.min.js','assets/qrcode.min.js'] as $p) {
        if(file_exists(__DIR__.'/'.$p)) { $qrJsPath = $p; break; }
    }
    ?>
    <?php if($qrJsPath && $qrTargets): ?>
    <script src="<?=htmlspecialchars($qrJsPath)?>"></script>
    <script>
    window.addEventListener('load', function() {
        <?php foreach($qrTargets as $elId=>$url): ?>
        try {
            new QRCode(document.getElementById(<?=json_encode($elId)?>), {
                text: <?=json_encode($url)?>,
                width: 90, height: 90,
                colorDark:'#000', colorLight:'#fff',
                correctLevel: QRCode.CorrectLevel.M
            });
        } catch(e) {}
        <?php endforeach; ?>
    });
    </script>
    <?php endif; ?>
    <script>
    function copySignLink(btn, url) {
        function fallback() { window.prompt('Copiez le lien de signature :', url); }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(url).then(function() {
                var t = btn.textContent; btn.textContent = '✅ Lien copié';
                setTimeout(function(){ btn.textContent = t; }, 1800);
            }, fallback);
        } else { fallback(); }
    }
    </script>
    </head><body>

    <!-- Messages (masqués à l'impression) -->
    <?php foreach(getFlashes() as $f): ?>
    <div class="no-print" style="padding:.75rem 1rem;border-radius:8px;margin-bottom:1rem;font-size:.9rem;<?=($f['type']??'')==='error' ? 'background:#fef2f2;color:#dc2626;border:1px solid #fecaca;' : 'background:#f0fdf4;color:#059669;border:1px solid #bbf7d0;'?>">
        <?=(($f['type']??'')==='error'?'⚠️ ':'✅ ')?><?=h($f['msg'])?>
    </div>
    <?php endforeach; ?>

    <!-- Barre d'outils écran (masquée à l'impression) -->
    <div class="toolbar no-print">
        <div class="tb-status">
            <strong>👤 <?=h($agtName)?></strong>
            <?php if($bonRemise): ?> &nbsp;·&nbsp; 📥 <?=h($bonRemise['numero'])?> : <?=bonStatusLabel($bonRemise)?><?php endif; ?>
            <?php if($bonRestitution): ?> &nbsp;·&nbsp; 📤 <?=h($bonRestitution['numero'])?> : <?=bonStatusLabel($bonRestitution)?><?php endif; ?>
        </div>
        <div style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;">
            <?php // Pour chaque bon encore signable : copier le lien (toujours), e-mail (si SMTP configuré)
            $smtpConfigured = trim(smtpSetting($pdo, 'smtp_host', '')) !== '';
            foreach ([$bonRemise, $bonRestitution] as $tb):
                if (!$tb || $tb['status'] !== 'pending' || ($tb['expires_at'] && strtotime($tb['expires_at']) < time())) continue;
                $signUrl = baseUrl($pdo) . '?page=sign&token=' . $tb['token']; ?>
            <button type="button" title="Copier le lien de signature du bon <?=h($tb['numero'])?>" onclick="copySignLink(this, '<?=h($signUrl)?>')">🔗 Copier le lien <?=h($tb['numero'])?></button>
            <?php if ($smtpConfigured && $agt && !empty($agt['email'])): ?>
            <form method="post" action="index.php">
                <?=csrf_field()?>
                <input type="hidden" name="_entity" value="bon">
                <input type="hidden" name="_action" value="send_mail">
                <input type="hidden" name="bon_id" value="<?=(int)$tb['id']?>">
                <button type="submit" title="Envoyer le lien de signature à <?=h($agt['email'])?>">📧 Envoyer <?=h($tb['numero'])?></button>
            </form>
            <?php endif; ?>
            <?php endforeach; ?>
            <?php if($agt && empty($agt['archived'])): ?>
            <form method="post" action="index.php" onsubmit="return confirm('Générer un nouveau bon de remise à partir de la dotation actuelle ?\nLe bon en attente (s\'il existe et diffère) sera annulé.')">
                <?=csrf_field()?>
                <input type="hidden" name="_entity" value="bon">
                <input type="hidden" name="_action" value="generate_remise">
                <input type="hidden" name="agent_id" value="<?=$agentId?>">
                <button type="submit">📄 Générer un nouveau bon</button>
            </form>
            <?php endif; ?>
            <?php
            // Raccourci restitution : remise signée, pas de restitution en cours, dotation encore en place
            $restitutionPossible = $bonRemise && $bonRemise['status'] === 'signed' && !$bonRestitution && $agt && empty($agt['archived']);
            $canOfferRestitution = $restitutionPossible;
            if ($canOfferRestitution) {
                $dotationNow = bonSnapshotItems($pdo, $agentId);
                $canOfferRestitution = !empty($dotationNow['devices']) || !empty($dotationNow['lines']);
            }
            ?>
            <?php if($restitutionPossible && !$canOfferRestitution): ?>
            <span style="font-size:.78rem;color:#94a3b8;" title="Les équipements de cet agent ne lui sont plus attribués (retour en stock ou réattribution manuelle) — un bon de restitution serait vide.">ℹ️ Rien à restituer — plus d'équipement en dotation</span>
            <?php endif; ?>
            <?php if($canOfferRestitution): ?>
            <form method="post" action="index.php" onsubmit="return confirm('Générer le bon de restitution pour TOUTE la dotation actuelle ?\n(Pour une restitution partielle, passez par la fiche agent.)')">
                <?=csrf_field()?>
                <input type="hidden" name="_entity" value="bon">
                <input type="hidden" name="_action" value="generate_restitution">
                <input type="hidden" name="ret_all" value="1">
                <input type="hidden" name="agent_id" value="<?=$agentId?>">
                <button type="submit">📤 Générer le bon de restitution</button>
            </form>
            <?php endif; ?>
            <button type="button" class="tb-primary" onclick="window.print()">🖨️ Imprimer</button>
        </div>
    </div>

    <?php
    if ($bonRemise) renderBonSection($pdo, $bonRemise, $agt);
    if ($bonRemise && $bonRestitution) echo '<hr class="divider">';
    if ($bonRestitution) renderBonSection($pdo, $bonRestitution, $agt);
    ?>
    </body></html>
    <?php exit;
}

// ─── 3b. EXPORT SQL DE LA BASE (sauvegarde téléchargeable) ────
// Génère un fichier .sql complet (structure + données) à copier sur
// une clé USB ou un partage réseau. Réservé aux super-admins.
if (isset($_GET['page']) && $_GET['page'] === 'backup_sql') {
    if (!isset($_SESSION['user_id']) || empty($_SESSION['is_admin'])) die("Accès refusé — réservé aux super-administrateurs.");
    while (ob_get_level()) ob_end_clean();
    header('Content-Type: application/sql; charset=utf-8');
    header('Content-Disposition: attachment; filename="simcity_sauvegarde_' . date('Y-m-d_His') . '.sql"');
    $out = fopen('php://output', 'w');
    simcity_write_dump($pdo, $out);
    fclose($out);
    exit;
}

// ─── 3c. MODÈLE CSV POUR L'IMPORTATION ────────────────────────
// Gabarit au format attendu par simcity_import_csv() : séparateur « ; »,
// encodage Windows-1252 (celui des exports Excel, que l'importeur décode),
// en-tête dont la première colonne contient « LIGNE » (marqueur de départ).
if (isset($_GET['page']) && $_GET['page'] === 'import_template') {
    if (!isset($_SESSION['user_id']) || empty($_SESSION['is_admin'])) die("Accès refusé — réservé aux super-administrateurs.");
    while (ob_get_level()) ob_end_clean();
    header('Content-Type: text/csv; charset=windows-1252');
    header('Content-Disposition: attachment; filename="simcity_modele_import.csv"');
    $rows = [
        // La colonne 15 alimente mobile_lines.puk (PUK 1) : elle s'intitulait
        // « PUK2 » alors que l'écran d'import documente « [15] PUK ». Depuis que
        // pin2 / puk2 existent vraiment, ce libellé faisait écrire le PUK 2 dans
        // le PUK 1. Les codes secondaires viennent de l'export de parc SFR.
        ['LIGNE','(non importé)','NOM','PRENOM','NOTES','COMPTE FACTURATION','SERVICE','OPTIONS','(non importé)','DATE ACTIVATION','IMEI','MODELE','FORFAIT','ICCID','PIN','PUK','OPERATEUR'],
        ['0612345678','','DUPONT','Marie','Remplacement écran 2025','CF123456','DSI','Multi-SIM','','01/09/2024','356789104563218','APPLE IPHONE 13','Forfait 20 Go','89330126112233445566','0000','12345678','Orange'],
        ['','','','','','','DSI','','','','356789104563219','SAMSUNG GALAXY A54','','','','',''],
    ];
    $out = fopen('php://output', 'w');
    foreach ($rows as $r) {
        fputcsv($out, array_map(fn($v) => mb_convert_encoding($v, 'Windows-1252', 'UTF-8'), $r), ';', '"', '\\');
    }
    fclose($out);
    exit;
}

// ─── 3d. TÉLÉCHARGEMENT D'UNE SAUVEGARDE STOCKÉE ──────────────
// Les fichiers de BACKUP_DIR ne sont pas servis directement par le web
// (ils contiennent signatures + mot de passe SMTP). On les diffuse ici,
// après contrôle d'accès. Réservé aux super-admins.
if (isset($_GET['page']) && $_GET['page'] === 'backup_download') {
    if (!isset($_SESSION['user_id']) || empty($_SESSION['is_admin'])) die("Accès refusé — réservé aux super-administrateurs.");
    // Nom de fichier durci : uniquement le motif attendu, pas de traversée de dossier
    $f = basename($_GET['f'] ?? '');
    if (!preg_match('/^simcity_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}\.sql$/', $f)) die("Fichier invalide.");
    $path = simcity_backup_dir() . $f;
    if (!is_file($path)) die("Sauvegarde introuvable.");
    while (ob_get_level()) ob_end_clean();
    header('Content-Type: application/sql; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $f . '"');
    header('Content-Length: ' . filesize($path));
    readfile($path);
    exit;
}

// ─── 3d bis. TÉLÉCHARGEMENT D'UN PDF DE FACTURE ARCHIVÉ ───────
// Les PDF de uploads/invoices/ ne sont pas servis directement par le web : une
// facture mensuelle, c'est la liste nominative complète du parc. Le .htaccess
// bloque le dossier, la diffusion passe par ici, après contrôle d'accès.
if (isset($_GET['page']) && $_GET['page'] === 'invoice_pdf') {
    if (!isset($_SESSION['user_id'])) die("Accès refusé — connexion requise.");
    $st = $pdo->prepare("SELECT invoice_number, pdf_path FROM invoices WHERE id=?");
    $st->execute([(int)($_GET['id'] ?? 0)]);
    $inv = $st->fetch();
    if (!$inv || empty($inv['pdf_path'])) die("Facture introuvable.");
    // Le chemin vient de la base, mais on le durcit quand même : uniquement le
    // motif attendu, aucune traversée de dossier possible.
    if (!preg_match('#^uploads/invoices/[A-Za-z0-9_-]+\.pdf$#', $inv['pdf_path'])) die("Chemin de fichier invalide.");
    $path = __DIR__ . '/' . $inv['pdf_path'];
    if (!is_file($path)) die("PDF archivé introuvable sur le serveur.");
    while (ob_get_level()) ob_end_clean();
    header('Content-Type: application/pdf');
    header('Content-Disposition: inline; filename="facture_' . preg_replace('/[^A-Za-z0-9_-]/', '', $inv['invoice_number']) . '.pdf"');
    header('Content-Length: ' . filesize($path));
    header('X-Content-Type-Options: nosniff');
    readfile($path);
    exit;
}

// ─── 3d ter. TÉLÉCHARGEMENT D'UNE PIÈCE JOINTE ────────────────
// Même principe que les PDF de factures : les fichiers joints aux fiches
// agents (justificatifs, courriers) ne sont plus servis directement par
// Apache, mais ici, après contrôle de session.
if (isset($_GET['page']) && $_GET['page'] === 'attachment') {
    if (!isset($_SESSION['user_id'])) die("Accès refusé — connexion requise.");
    $st = $pdo->prepare("SELECT file_name, file_path FROM attachments WHERE id=?");
    $st->execute([(int)($_GET['id'] ?? 0)]);
    $att = $st->fetch();
    if (!$att || empty($att['file_path'])) die("Pièce jointe introuvable.");
    // Le chemin vient de la base ; on le durcit malgré tout : sous uploads/,
    // sans traversée de dossier.
    $rel = ltrim(str_replace('\\', '/', (string)$att['file_path']), '/');
    if (!preg_match('#^uploads/[A-Za-z0-9._-]+$#', $rel)) die("Chemin de fichier invalide.");
    $path = __DIR__ . '/' . $rel;
    if (!is_file($path)) die("Fichier absent du serveur.");
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime  = $finfo->file($path) ?: 'application/octet-stream';
    $name  = preg_replace('/[^\w .()-]/u', '_', (string)($att['file_name'] ?: basename($rel)));
    while (ob_get_level()) ob_end_clean();
    header('Content-Type: ' . $mime);
    header('Content-Disposition: inline; filename="' . $name . '"');
    header('Content-Length: ' . filesize($path));
    header('X-Content-Type-Options: nosniff');
    readfile($path);
    exit;
}

// ─── 3e. LOGO SVG TEINTÉ ──────────────────────────────────────
// Sert le logo embarqué, recoloré avec la couleur du site si définie.
// Public (affiché sur la page de connexion et les pages de demande).
if (isset($_GET['logo'])) {
    header('Content-Type: image/svg+xml');
    header('Cache-Control: no-cache');
    $svg = (string)@file_get_contents(__DIR__ . '/assets/logo.svg');
    $c = uiPrimaryColor($pdo);
    if ($c !== '') $svg = str_replace(['#6366f1', '#3b82f6'], [$c, uiColorMix($c, 0.3)], $svg);
    echo $svg; exit;
}

// ─── 4. SECURITE & AUTHENTIFICATION ───────────────────────────

// ── Déconnexion ───────────────────────────────────────────────
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
    header('Location: index.php'); exit;
}

// Jeton CSRF disponible dès la page de connexion (anonyme)
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// ── Connexion avec protection anti-brute-force (en base) ──────
// Le compteur est stocké en base (par compte ET par IP) : impossible de le
// contourner en jetant son cookie de session.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $loginUser = trim($_POST['username'] ?? '');
    $loginIp   = $_SERVER['REMOTE_ADDR'] ?? '';

    // Protection CSRF du formulaire de connexion
    if (!csrf_verify()) {
        $login_error = "Session expirée. Rechargez la page et réessayez.";
        goto login_render;
    }

    // Purge des tentatives anciennes (> 24 h)
    $pdo->exec("DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 1 DAY)");

    // Verrouillage : 5 échecs sur le même compte ou la même IP en 15 minutes
    $st = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE (username=? OR ip=?) AND attempted_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
    $st->execute([$loginUser, $loginIp]);
    if ($st->fetchColumn() >= 5) {
        $login_error = "Trop de tentatives échouées. Réessayez dans quelques minutes.";
    } else {
        $loginPass = $_POST['password'] ?? '';
        $st = $pdo->prepare("SELECT id, username, password, active, IFNULL(first_name,'') as first_name, IFNULL(last_name,'') as last_name, IFNULL(is_admin,0) as is_admin, IFNULL(auth_source,'local') as auth_source FROM users WHERE username=?");
        $st->execute([$loginUser]);
        $u = $st->fetch();

        // 1) Mot de passe local d'abord…
        $authed   = ($u && $loginPass !== '' && password_verify($loginPass, $u['password']));
        $ldapUsed = false;

        // 2) …puis bind LDAP / Active Directory (si activé). Un utilisateur AD
        //    valide et inconnu en base est provisionné automatiquement
        //    (jamais super-admin), comme sur Sentinelle.
        if (!$authed && ldap_auth_enabled() && $loginUser !== '' && $loginPass !== '') {
            $ldapInfo = ldap_authenticate_user($loginUser, $loginPass);
            if ($ldapInfo !== null) {
                $authed = $ldapUsed = true;
                if (!$u) {
                    // Provisionnement : mot de passe local aléatoire inutilisable
                    // (l'utilisateur s'authentifiera toujours via LDAP).
                    $pdo->prepare("INSERT INTO users (username, password, first_name, last_name, email, is_admin, auth_source) VALUES (?,?,?,?,?,0,'ldap')")
                        ->execute([
                            $loginUser,
                            password_hash(bin2hex(random_bytes(24)), PASSWORD_DEFAULT),
                            fmtFirstName($ldapInfo['first_name'] ?: null),
                            fmtLastName($ldapInfo['last_name']  ?: ($ldapInfo['display_name'] ?: null)),
                            fmtEmail($ldapInfo['email']      ?: null),
                        ]);
                    $newId = (int)$pdo->lastInsertId();
                    logHistory($pdo, 'admin', $newId, "Compte provisionné automatiquement depuis l'Active Directory : {$loginUser}");
                    $st->execute([$loginUser]);
                    $u = $st->fetch();
                }
            }
        }

        if ($authed && $u) {
            // Compte désactivé
            if (!(int)$u['active']) {
                $login_error = "Ce compte est désactivé. Contactez un administrateur.";
            } else {
                // Connexion réussie : régénérer l'ID de session (anti-fixation)
                session_regenerate_id(true);
                $pdo->prepare("DELETE FROM login_attempts WHERE username=? OR ip=?")->execute([$loginUser, $loginIp]);
                $_SESSION['user_id'] = $u['id'];
                $_SESSION['username'] = $u['username'];
                $_SESSION['is_admin'] = !empty($u['is_admin']);
                $_SESSION['auth_ldap'] = $ldapUsed;
                $fullName = trim(($u['first_name'] ?? '') . ' ' . ($u['last_name'] ?? ''));
                if ($fullName) $_SESSION['admin_fullname'] = $fullName;
                header('Location: index.php'); exit;
            }
        } else {
            // Échec : enregistrer la tentative
            $pdo->prepare("INSERT INTO login_attempts (username, ip) VALUES (?,?)")->execute([$loginUser, $loginIp]);
            $login_error = "Identifiants incorrects.";
        }
    }
} // fin if POST login

login_render:
// ── Page de login ─────────────────────────────────────────────
if (!isset($_SESSION['user_id'])) {
    ?>
    <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connexion – SimCity</title>
    <link rel="icon" type="image/svg+xml" href="index.php?logo=1"><?php echo uiPrimaryCssOverride($pdo); ?>
    <link href="vendor/plex.css" rel="stylesheet">
    <style>
        :root{--primary:#4f46e5;--primary-dark:#4338ca;--primary-glow:rgba(79,70,229,.35);--card:#ffffff;--text:#334155;--text-strong:#0f172a;--text-light:#94a3b8;--border:#e2e8f0;--border-strong:#cbd5e1;--danger:#dc2626;--radius:7px;}
        .login-logo{height:56px;width:56px;object-fit:contain;display:block;margin:0 auto 8px;}
        <?php
            // Fond du login : dégradé sombre dérivé de la couleur du site si
            // définie, sinon le bleu nuit d'origine.
            $lc = uiPrimaryColor($pdo);
            $loginBg = $lc !== ''
                ? 'linear-gradient(135deg,' . uiColorMix($lc, -0.85) . ' 0%,' . uiColorMix($lc, -0.7) . ' 55%,' . uiColorMix($lc, -0.45) . ' 100%)'
                : 'linear-gradient(135deg,#0f172a 0%,#1e293b 55%,#1e3a6b 100%)';
        ?>
        body{background:<?=$loginBg?>;color:var(--text);font-family:'IBM Plex Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:24px;box-sizing:border-box;}
        .login-box{background:var(--card);padding:36px 32px;border-radius:14px;border:1px solid var(--border);width:100%;max-width:400px;box-shadow:0 12px 28px rgba(15,23,42,.35),0 4px 10px rgba(15,23,42,.2);}
        h2{text-align:center;margin-top:0;font-size:1.6rem;font-weight:700;color:var(--text-strong);}
        label{font-size:.82rem;font-weight:600;color:var(--text);}
        input{width:100%;padding:9px 12px;margin-top:5px;background:#fff;border:1px solid var(--border-strong);border-radius:var(--radius);color:var(--text);font-family:inherit;font-size:.9rem;box-sizing:border-box;transition:border-color .18s ease,box-shadow .18s ease;}
        input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow);}
        input::placeholder{color:var(--text-light);opacity:.75;font-style:italic;}
        button{width:100%;padding:11px;background:var(--primary);color:#fff;border:1px solid var(--primary);border-radius:var(--radius);font-weight:600;font-size:.95rem;margin-top:1.5rem;cursor:pointer;transition:background-color .18s ease;}
        button:hover{background:var(--primary-dark);}
    </style></head>
    <body>
        <div class="login-box"><img src="index.php?logo=1" alt="SimCity" class="login-logo"><h2>SimCity</h2><p style="text-align:center;opacity:.7;margin-bottom:2rem;font-size:.9rem;">Gestion du Parc Mobile — DSI</p>
            <?php if(isset($login_error)) echo "<div style='color:var(--danger);text-align:center;margin-bottom:1rem;'>".h($login_error)."</div>"; ?>
            <form method="post" autocomplete="off">
                <?=csrf_field()?>
                <div style="margin-bottom:1rem;"><label>Nom d'utilisateur</label><input type="text" name="username" required autofocus autocomplete="username"></div>
                <div><label>Mot de passe</label><input type="password" name="password" required autocomplete="current-password"></div>
                <button type="submit" name="login">Se connecter</button>
            </form>
        </div>
    </body></html>
    <?php exit;
}

// ─── 5. HELPERS ───────────────────────────────────────────────
function h($str) { return htmlspecialchars((string)$str, ENT_QUOTES); }
function S(array $d, string $k, string $def=''): string { return trim(strip_tags((string)($d[$k] ?? $def))); }
function IV(array $d, string $k) { return !empty($d[$k]) ? (int)$d[$k] : null; }
function NV(array $d, string $k) { $v=trim($d[$k]??''); return $v?:null; }

// Normalisation des noms / e-mails (fmtLastName / fmtFirstName / fmtEmail)
require_once __DIR__ . '/lib_format.php';

function flash($type, $msg) { $_SESSION['flashes'][] = ['type'=>$type, 'msg'=>$msg]; }
function getFlashes() { $f = $_SESSION['flashes'] ?? []; $_SESSION['flashes'] = []; return $f; }

// ── CSRF ─────────────────────────────────────────────────────
// Génère (ou réutilise) le token de session pour tous les formulaires POST
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$CSRF_TOKEN = $_SESSION['csrf_token'];

function csrf_verify(): bool {
    $submitted = $_POST[CSRF_TOKEN_NAME] ?? '';
    $expected  = $_SESSION['csrf_token'] ?? '';
    return $submitted !== '' && $expected !== '' && hash_equals($expected, $submitted);
}

// Champ HTML à insérer dans chaque formulaire POST
function csrf_field(): string {
    return '<input type="hidden" name="' . CSRF_TOKEN_NAME . '" value="' . htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES) . '">';
}

function getAgentName($pdo, $id) {
    if (!$id) return '';
    $st = $pdo->prepare("SELECT first_name, last_name FROM agents WHERE id=?");
    $st->execute([$id]); $a = $st->fetch();
    return $a ? trim($a['first_name'] . ' ' . $a['last_name']) : '';
}

function logHistory($pdo, $type, $id, $desc, $agent_id = null) { 
    $author = $_SESSION['username'] ?? 'Inconnu';
    $pdo->prepare("INSERT INTO history_logs (entity_type, entity_id, action_desc, agent_id, author) VALUES (?, ?, ?, ?, ?)")->execute([$type, $id, $desc, $agent_id, $author]); 
}

function fetchEntityHistory($pdo, $type, $id) {
    $st = $pdo->prepare("SELECT DATE_FORMAT(h.action_date, '%d/%m/%Y %H:%i') as dt, h.action_desc, h.author, a.first_name, a.last_name FROM history_logs h LEFT JOIN agents a ON h.agent_id = a.id WHERE h.entity_type=? AND h.entity_id=? ORDER BY h.action_date DESC");
    $st->execute([$type, $id]); $res = [];
    foreach($st->fetchAll() as $row) {
        $desc = trim($row['action_desc']); $agtName = trim($row['first_name'].' '.$row['last_name']);
        if (preg_match('/(attribué[e]? à|affecté[e]? à)\s*$/', $desc)) { $desc .= ' ' . ($agtName ?: 'Utilisateur inconnu'); }
        $res[] = ['dt' => $row['dt'], 'action_desc' => $desc, 'agent_name' => $agtName, 'author' => $row['author']];
    } return $res;
}

function statusBadge($s) {
    $map = ['Stock'=>['En Stock / Dispo','badge-success'], 'Deployed'=>['Déployé / Actif','badge-info'], 'Repair'=>['Réparation','badge-warning'], 'HS'=>['Casse / Rebus','badge-danger'], 'Lost'=>['Perdu / Volé','badge-danger'], 'Active'=>['Active','badge-success'], 'Suspended'=>['Suspendue','badge-warning'], 'Resiliated'=>['Résiliée','badge-danger']];
    [$label, $cls] = $map[$s] ?? [$s, 'badge-muted']; return "<span class='badge $cls'>$label</span>";
}
function getSetting($pdo, $key, $default=0) {
    $st = $pdo->prepare("SELECT setting_value FROM settings WHERE setting_key=?");
    $st->execute([$key]);
    $v = $st->fetchColumn();
    return $v !== false ? $v : $default;
}

// ─── AJAX : AJOUT RAPIDE (+) D'UNE ENTITÉ LIÉE ───────────────
// Crée une entité de référentiel (service, modèle, agent, forfait, compte de
// facturation, opérateur) sans quitter le formulaire courant. Renvoie
// {ok, id, label} en JSON ; le JS injecte l'option dans le <select> cible.
if (isset($_GET['ajax_quickadd'])) {
    header('Content-Type: application/json');
    if (!isset($_SESSION['user_id'])) { http_response_code(403); echo json_encode(['ok'=>false,'error'=>'Non authentifié']); exit; }
    if (!csrf_verify()) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Session expirée, rechargez la page.']); exit; }
    $ent = $_POST['_entity'] ?? '';
    $g = fn($k) => trim($_POST[$k] ?? '');
    try {
        switch ($ent) {
            case 'service':
                if ($g('name') === '') throw new Exception('Le nom du service est obligatoire.');
                $pdo->prepare("INSERT INTO services(name,direction,notes,chef_name,chef_email,dga_name,dga_email) VALUES(?,?,?,?,?,?,?)")
                    ->execute([$g('name'), $g('direction'), $g('notes'), $g('chef_name'), fmtEmail($g('chef_email')), $g('dga_name'), fmtEmail($g('dga_email'))]);
                $id = (int)$pdo->lastInsertId(); $label = $g('name'); break;
            case 'model':
                if ($g('brand') === '' || $g('name') === '') throw new Exception('Marque et modèle sont obligatoires.');
                $cat = $g('category') ?: 'Smartphone';
                $pdo->prepare("INSERT INTO models(brand,name,category) VALUES(?,?,?)")->execute([$g('brand'), $g('name'), $cat]);
                $id = (int)$pdo->lastInsertId(); $label = $g('brand').' '.$g('name'); break;
            case 'agent':
                if ($g('last_name') === '') throw new Exception('Le nom est obligatoire.');
                $fn = fmtFirstName($g('first_name')); $ln = fmtLastName($g('last_name'));
                $pdo->prepare("INSERT INTO agents(first_name,last_name,fonction,email,service_id) VALUES(?,?,?,?,?)")
                    ->execute([$fn, $ln, $g('fonction'), fmtEmail($g('email')), ($g('service_id') !== '' ? (int)$g('service_id') : null)]);
                $id = (int)$pdo->lastInsertId(); $label = trim($ln.' '.$fn); break;
            case 'plan':
                if ($g('name') === '') throw new Exception('Le nom du forfait est obligatoire.');
                $pdo->prepare("INSERT INTO plan_types(name,data_limit,notes,operator_id) VALUES(?,?,?,?)")
                    ->execute([$g('name'), $g('data_limit'), $g('notes'), ($g('operator_id') !== '' ? (int)$g('operator_id') : null)]);
                $id = (int)$pdo->lastInsertId(); $label = $g('name'); break;
            case 'billing':
                if ($g('account_number') === '') throw new Exception('Le numéro de compte est obligatoire.');
                $pdo->prepare("INSERT INTO billing_accounts(account_number,name,notes) VALUES(?,?,?)")->execute([$g('account_number'), $g('name'), $g('notes')]);
                $id = (int)$pdo->lastInsertId(); $label = trim($g('account_number').' '.($g('name') !== '' ? '— '.$g('name') : '')); break;
            case 'operator':
                if ($g('name') === '') throw new Exception('Le nom de l\'opérateur est obligatoire.');
                $pdo->prepare("INSERT INTO operators(name,website,notes) VALUES(?,?,?)")->execute([$g('name'), $g('website'), $g('notes')]);
                $id = (int)$pdo->lastInsertId(); $label = $g('name'); break;
            default:
                throw new Exception('Type non pris en charge.');
        }
        logHistory($pdo, $ent, $id, "Ajout rapide depuis un formulaire : ".$label);
        echo json_encode(['ok'=>true, 'id'=>$id, 'label'=>$label]);
    } catch (Exception $e) {
        http_response_code(422);
        echo json_encode(['ok'=>false, 'error'=>$e->getMessage()]);
    }
    exit;
}

// ─── AJAX : APERÇU D'UN GABARIT D'E-MAIL (Paramètres → Envoi d'e-mails) ──
// Rend le gabarit avec les valeurs du formulaire (non enregistrées) et les
// données de démonstration. Retourne {subject, html} ; le HTML part dans une
// iframe sandboxée côté client.
if (isset($_GET['ajax_mail_preview'])) {
    header('Content-Type: application/json; charset=utf-8');
    if (!isset($_SESSION['user_id'])) { http_response_code(403); echo json_encode(['error' => 'Non authentifié']); exit; }
    $key = $_POST['tpl'] ?? '';
    $all = mailTemplates();
    if (!isset($all[$key])) { http_response_code(422); echo json_encode(['error' => 'Gabarit inconnu']); exit; }
    $t = $all[$key];
    $subject = trim($_POST['subject'] ?? '') ?: $t['subject'];
    $title   = trim($_POST['title'] ?? '')   ?: $t['title'];
    $body    = trim($_POST['body'] ?? '')    ?: $t['body'];
    $repl = [];
    foreach (mailDemoVars($pdo)[$key] as $k => $v) $repl['{' . $k . '}'] = (string)$v;
    // Couleurs du bandeau : celles du formulaire (non enregistrées) si valides
    $banner = mailBannerColors($pdo);
    if (preg_match('/^#[0-9a-fA-F]{6}$/', $_POST['banner_color'] ?? ''))  $banner[0] = $_POST['banner_color'];
    if (preg_match('/^#[0-9a-fA-F]{6}$/', $_POST['banner_color2'] ?? '')) $banner[1] = $_POST['banner_color2'];
    if (isset($_POST['banner_gradient'])) $banner[2] = $_POST['banner_gradient'] === '1';
    echo json_encode([
        'subject' => strtr($subject, $repl),
        'html'    => requestMailShell(strtr($title, $repl), strtr($body, $repl), $pdo, $banner),
    ]);
    exit;
}

// ─── AJAX : RECHERCHE LOCALE D'UN UTILISATEUR (sélecteurs lignes / matériels) ──
// Remplace les <select> exhaustifs (inutilisables avec beaucoup d'agents) :
// recherche dans le référentiel local uniquement (pas l'AD). Authentifié.
if (isset($_GET['ajax_agent_search'])) {
    header('Content-Type: application/json; charset=utf-8');
    if (!isset($_SESSION['user_id'])) { echo json_encode([]); exit; }
    $q = trim($_GET['q'] ?? '');
    if (mb_strlen($q) < 2) { echo json_encode([]); exit; }
    $like = '%' . $q . '%';
    $st = $pdo->prepare("SELECT a.id, a.first_name, a.last_name, a.email, a.service_id, s.name AS service_name
        FROM agents a LEFT JOIN services s ON a.service_id = s.id
        WHERE a.archived=0 AND (a.first_name LIKE ? OR a.last_name LIKE ?
              OR CONCAT(a.first_name,' ',a.last_name) LIKE ? OR CONCAT(a.last_name,' ',a.first_name) LIKE ?
              OR a.email LIKE ?)
        ORDER BY a.last_name, a.first_name LIMIT 10");
    $st->execute([$like, $like, $like, $like, $like]);
    $out = [];
    foreach ($st->fetchAll() as $a) {
        $out[] = ['id' => (int)$a['id'], 'name' => trim($a['last_name'] . ' ' . $a['first_name']),
                  'email' => (string)($a['email'] ?? ''),
                  'service_id' => (int)($a['service_id'] ?? 0), 'service_name' => (string)($a['service_name'] ?? '')];
    }
    echo json_encode($out); exit;
}

// ─── AJAX : HISTORIQUE SIM D'UNE LIGNE ───────────────────────
if (isset($_GET['ajax_sim_history'])) {
    header('Content-Type: application/json');
    if (!isset($_SESSION['user_id'])) { echo json_encode([]); exit; }
    $lid = (int)$_GET['ajax_sim_history'];
    $rows = $pdo->prepare("SELECT *, DATE_FORMAT(swapped_at,'%d/%m/%Y %H:%i') as dt FROM sim_history WHERE line_id=? ORDER BY swapped_at DESC");
    $rows->execute([$lid]);
    echo json_encode($rows->fetchAll()); exit;
}

// ─── REQUETES AJAX (RECHERCHE & FICHE AGENT) ──────────────────
if (isset($_GET['ajax_global_search'])) {
    header('Content-Type: application/json');
    $q = trim($_GET['q'] ?? ''); if (strlen($q) < 2) { echo json_encode([]); exit; }

    // Préparer plusieurs variantes de recherche
    $like       = '%' . $q . '%';
    $likeClean  = '%' . str_replace(' ', '', $q) . '%';
    $parts      = preg_split('/\s+/', $q, 2);
    $likeP1     = '%' . ($parts[0] ?? '') . '%';
    $likeP2     = '%' . ($parts[1] ?? '') . '%';
    $hasSpace   = count($parts) === 2;

    $results = []; $seenLines = []; $seenDevices = [];

    // ── 1. LIGNES actives — par numéro, ICCID, agent courant ────
    // Onglet cible d'une ligne dans la vue Lignes (le découpage par statut
    // doit suivre les onglets : Actives / Stock / Suspendues / Archives).
    $lineTab = fn($r) => $r['archived'] ? 'archive' : ($r['status'] === 'Stock' ? 'stock' : ($r['status'] === 'Suspended' ? 'suspended' : 'active'));

    $stL = $pdo->prepare("SELECT l.id, l.phone_number, l.iccid, l.archived, l.status,
        CONCAT(IFNULL(a.first_name,''), ' ', IFNULL(a.last_name,'')) as agent_name,
        IFNULL(a.first_name,'') as fn, IFNULL(a.last_name,'') as ln
        FROM mobile_lines l LEFT JOIN agents a ON l.agent_id=a.id
        WHERE l.phone_number LIKE ? OR l.iccid LIKE ?
           OR a.first_name LIKE ? OR a.last_name LIKE ?
           OR CONCAT(a.first_name,' ',a.last_name) LIKE ?
           OR CONCAT(a.last_name,' ',a.first_name) LIKE ?
        LIMIT 5");
    $stL->execute([$likeClean, $likeClean, $like, $like, $like, $like]);
    foreach ($stL->fetchAll() as $r) {
        $seenLines[$r['id']] = true;
        $num = $r['phone_number'] ? formatPhone($r['phone_number']) : 'SIM Vierge';
        $results[] = ['type'=>'Ligne','title'=>$num.($r['archived']?' 🗄️':''),
            'subtitle'=>'Agent : '.trim($r['agent_name']).' | ICCID : '.($r['iccid']?:'-'),
            'link'=>'?page=lines&tab='.$lineTab($r).'&q='.urlencode($r['phone_number']?:$r['iccid'])];
    }

    // ── 2. LIGNES — via historique (ex-agent, ligne archivée) ─────
    if ($hasSpace) {
        // "Prénom Nom" ou "Nom Prénom" — inclut les lignes archivées d'un agent
        $histLineQ = $pdo->prepare("SELECT DISTINCT h.entity_id FROM history_logs h
            WHERE h.entity_type='line'
              AND (h.action_desc LIKE ? OR h.action_desc LIKE ?
                   OR (h.action_desc LIKE ? AND h.action_desc LIKE ?)
                   OR h.agent_id IN (SELECT id FROM agents WHERE first_name LIKE ? OR last_name LIKE ?
                       OR CONCAT(first_name,' ',last_name) LIKE ? OR CONCAT(last_name,' ',first_name) LIKE ?))
            LIMIT 15");
        $histLineQ->execute([$like, '%'.implode('%',$parts).'%', $likeP1, $likeP2, $like, $like, $like, $like]);
    } else {
        $histLineQ = $pdo->prepare("SELECT DISTINCT h.entity_id FROM history_logs h
            WHERE h.entity_type='line'
              AND (h.action_desc LIKE ?
                   OR h.agent_id IN (SELECT id FROM agents WHERE first_name LIKE ? OR last_name LIKE ?))
            LIMIT 15");
        $histLineQ->execute([$like, $like, $like]);
    }
    foreach ($histLineQ->fetchAll(PDO::FETCH_COLUMN) as $lineId) {
        if (isset($seenLines[$lineId])) continue;
        $seenLines[$lineId] = true;
        $lr = $pdo->query("SELECT l.id, l.phone_number, l.iccid, l.archived, l.status,
            IFNULL(a.first_name,'') as fn, IFNULL(a.last_name,'') as ln
            FROM mobile_lines l LEFT JOIN agents a ON l.agent_id=a.id WHERE l.id=$lineId")->fetch();
        if (!$lr) continue;
        $num = $lr['phone_number'] ? formatPhone($lr['phone_number']) : 'SIM Vierge';
        $results[] = ['type'=>'Ligne','title'=>$num.($lr['archived']?' 🗄️':''),
            'subtitle'=>'📋 Trouvé via historique — Agent actuel : '.trim($lr['fn'].' '.$lr['ln']?:'Aucun'),
            'link'=>'?page=lines&tab='.$lineTab($lr).'&q='.urlencode($lr['phone_number']?:$lr['iccid'])];
    }

    // ── 3. MATÉRIELS — par IMEI, S/N, modèle, agent courant ────
    $stD = $pdo->prepare("SELECT d.id, d.imei, d.archived,
        CONCAT(m.brand,' ',m.name) as model_name, d.serial_number,
        IFNULL(a.first_name,'') as fn, IFNULL(a.last_name,'') as ln
        FROM devices d LEFT JOIN models m ON d.model_id=m.id
        LEFT JOIN agents a ON d.agent_id=a.id
        WHERE d.imei LIKE ? OR d.serial_number LIKE ? OR m.name LIKE ? OR m.brand LIKE ?
           OR a.first_name LIKE ? OR a.last_name LIKE ?
           OR CONCAT(a.first_name,' ',a.last_name) LIKE ?
           OR CONCAT(a.last_name,' ',a.first_name) LIKE ?
        LIMIT 5");
    $stD->execute([$likeClean, $likeClean, $like, $like, $like, $like, $like, $like]);
    foreach ($stD->fetchAll() as $r) {
        $seenDevices[$r['id']] = true;
        $results[] = ['type'=>'Matériel','title'=>$r['model_name'].($r['archived']?' 🗄️':''),
            'subtitle'=>'IMEI : '.($r['imei']?:'-').' | Agent : '.trim($r['fn'].' '.$r['ln']?:'Aucun'),
            'link'=>'?page=devices&tab='.($r['archived']?'archive':'active').'&q='.urlencode($r['imei'])];
    }

    // ── 4. MATÉRIELS — via historique ───────────────────────────
    if ($hasSpace) {
        $histDevQ = $pdo->prepare("SELECT DISTINCT h.entity_id FROM history_logs h
            WHERE h.entity_type='device'
              AND (h.action_desc LIKE ? OR h.action_desc LIKE ?
                   OR (h.action_desc LIKE ? AND h.action_desc LIKE ?)
                   OR h.agent_id IN (SELECT id FROM agents WHERE first_name LIKE ? OR last_name LIKE ?
                       OR CONCAT(first_name,' ',last_name) LIKE ? OR CONCAT(last_name,' ',first_name) LIKE ?))
            LIMIT 15");
        $histDevQ->execute([$like, '%'.implode('%',$parts).'%', $likeP1, $likeP2, $like, $like, $like, $like]);
    } else {
        $histDevQ = $pdo->prepare("SELECT DISTINCT h.entity_id FROM history_logs h
            WHERE h.entity_type='device'
              AND (h.action_desc LIKE ?
                   OR h.agent_id IN (SELECT id FROM agents WHERE first_name LIKE ? OR last_name LIKE ?))
            LIMIT 15");
        $histDevQ->execute([$like, $like, $like]);
    }
    foreach ($histDevQ->fetchAll(PDO::FETCH_COLUMN) as $devId) {
        if (isset($seenDevices[$devId])) continue;
        $seenDevices[$devId] = true;
        $dr = $pdo->query("SELECT d.id, d.imei, d.archived, m.brand, m.name as mname,
            IFNULL(a.first_name,'') as fn, IFNULL(a.last_name,'') as ln
            FROM devices d LEFT JOIN models m ON d.model_id=m.id
            LEFT JOIN agents a ON d.agent_id=a.id WHERE d.id=$devId")->fetch();
        if (!$dr) continue;
        $results[] = ['type'=>'Matériel','title'=>$dr['brand'].' '.$dr['mname'].($dr['archived']?' 🗄️':''),
            'subtitle'=>'📋 Trouvé via historique — IMEI : '.($dr['imei']?:'-').' | Agent actuel : '.trim($dr['fn'].' '.$dr['ln']?:'Aucun'),
            'link'=>'?page=devices&tab='.($dr['archived']?'archive':'active').'&q='.urlencode($dr['imei'])];
    }

    // ── 5. AGENTS — par prénom/nom dans les deux ordres ─────────
    if ($hasSpace) {
        $stA = $pdo->prepare("SELECT a.id, a.first_name, a.last_name, a.archived,
            IFNULL(s.name,'Aucun service') as svc
            FROM agents a LEFT JOIN services s ON a.service_id=s.id
            WHERE CONCAT(a.first_name,' ',a.last_name) LIKE ?
               OR CONCAT(a.last_name,' ',a.first_name) LIKE ?
               OR (a.first_name LIKE ? AND a.last_name LIKE ?)
               OR (a.first_name LIKE ? AND a.last_name LIKE ?)
            LIMIT 5");
        $stA->execute([$like, $like, $likeP1, $likeP2, $likeP2, $likeP1]);
    } else {
        $stA = $pdo->prepare("SELECT a.id, a.first_name, a.last_name, a.archived,
            IFNULL(s.name,'Aucun service') as svc
            FROM agents a LEFT JOIN services s ON a.service_id=s.id
            WHERE a.first_name LIKE ? OR a.last_name LIKE ? LIMIT 5");
        $stA->execute([$like, $like]);
    }
    foreach ($stA->fetchAll() as $r) {
        $archivedLabel = $r['archived'] ? ' 🗄️ Parti' : '';
        $fullName = trim($r['first_name'].' '.$r['last_name']);
        $results[] = ['type'=>'Agent','title'=>$fullName.$archivedLabel,
            'subtitle'=>$r['svc'],
            'link'=>'?page=refs&tab=agents&q='.urlencode($fullName)];
    }

    echo json_encode(array_values($results)); exit;
}

if (isset($_GET['ajax_agent_details'])) {
    $id = (int)$_GET['ajax_agent_details'];
    $agt = $pdo->query("SELECT a.*, s.name as service_name FROM agents a LEFT JOIN services s ON a.service_id=s.id WHERE a.id=$id")->fetch();
    $lines = $pdo->query("SELECT l.phone_number, l.iccid, l.pin, l.puk, p.name as plan_name, l.status, COALESCE(l.personal_device,0) as personal_device, COALESCE(l.esim,0) as esim, l.eid, l.activation_code FROM mobile_lines l LEFT JOIN plan_types p ON l.plan_id=p.id WHERE l.agent_id=$id AND l.archived=0")->fetchAll();
    $devices = $pdo->query("SELECT DISTINCT d.imei, m.brand, m.name, m.category, d.status FROM devices d LEFT JOIN models m ON d.model_id=m.id WHERE (d.agent_id=$id OR d.id IN (SELECT device_id FROM mobile_lines WHERE agent_id=$id AND device_id IS NOT NULL)) AND d.archived=0")->fetchAll();
    // Lignes BYOD (téléphone perso, pas de device dans le parc)
    $byodLines = array_filter($lines, fn($l) => !empty($l['personal_device']));

    // Stock disponible pour l'attribution rapide depuis la fiche
    $stockLines = $pdo->query("SELECT l.id, l.phone_number, l.iccid, p.name as plan_name, COALESCE(l.esim,0) as esim FROM mobile_lines l LEFT JOIN plan_types p ON l.plan_id=p.id WHERE l.archived=0 AND l.agent_id IS NULL AND l.sim_vierge=0 ORDER BY l.phone_number")->fetchAll();
    $stockDevices = $pdo->query("SELECT d.id, d.imei, d.serial_number, m.brand, m.name FROM devices d LEFT JOIN models m ON d.model_id=m.id WHERE d.archived=0 AND d.agent_id IS NULL AND d.status='Stock' AND d.id NOT IN (SELECT device_id FROM mobile_lines WHERE device_id IS NOT NULL AND archived=0) ORDER BY m.brand, m.name, d.id")->fetchAll();
    
    // NOUVEAU : Récupération des pièces jointes
    $att = $pdo->query("SELECT * FROM attachments WHERE entity_type='agent' AND entity_id=$id ORDER BY uploaded_at DESC")->fetchAll();
    
    $nameStr = trim($agt['first_name'].' '.$agt['last_name']);
    $histSt = $pdo->prepare("SELECT DATE_FORMAT(h.action_date, '%d/%m/%Y %H:%i') as dt, h.entity_type, h.action_desc, h.author, a.first_name, a.last_name FROM history_logs h LEFT JOIN agents a ON h.agent_id = a.id WHERE h.agent_id = ? OR (? != '' AND h.action_desc LIKE ?) OR (h.entity_type = 'line' AND h.entity_id IN (SELECT id FROM mobile_lines WHERE agent_id = ?)) OR (h.entity_type = 'device' AND h.entity_id IN (SELECT id FROM devices WHERE agent_id = ? OR id IN (SELECT device_id FROM mobile_lines WHERE agent_id = ?))) ORDER BY h.action_date DESC");
    $histSt->execute([$id, $nameStr, "%$nameStr%", $id, $id, $id]);
    $history = $histSt->fetchAll();
    
    // ── BONS : statut du dernier cycle + actions ──────────────────
    $smtpConfigured = trim(smtpSetting($pdo, 'smtp_host', '')) !== '';
    $lastRemise = $pdo->prepare("SELECT * FROM bons WHERE agent_id=? AND type='remise' AND status!='cancelled' ORDER BY created_at DESC, id DESC LIMIT 1");
    $lastRemise->execute([$id]); $lastRemise = $lastRemise->fetch();
    $lastRestit = null;
    if ($lastRemise) {
        $st = $pdo->prepare("SELECT * FROM bons WHERE parent_id=? AND type='restitution' AND status!='cancelled' ORDER BY created_at DESC, id DESC LIMIT 1");
        $st->execute([$lastRemise['id']]); $lastRestit = $st->fetch();
    }
    $hasPendingBons = (int)$pdo->query("SELECT COUNT(*) FROM bons WHERE agent_id=$id AND status='pending'")->fetchColumn();

    // Cycle clôturé : les restitutions signées couvrent tous les équipements
    // de la remise → plus de « bon actuel », la paire vit dans l'historique.
    $cycleClosed = $lastRemise ? bonCycleClosed($pdo, $lastRemise) : false;

    echo "<div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:1.5rem; flex-wrap:wrap; gap:.75rem;'>";
    echo "<div style='display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;'>";
    echo "<form method='post' action='index.php' target='_blank' style='display:inline;padding:0;margin:0;'>
        <input type='hidden' name='_entity' value='bon'>
        <input type='hidden' name='_action' value='generate_remise'>
        <input type='hidden' name='agent_id' value='$id'>
        <input type='hidden' name='" . CSRF_TOKEN_NAME . "' value='" . h($CSRF_TOKEN) . "'>
        <button type='submit' class='btn-primary' style='display:inline-flex; align-items:center; gap:5px; box-shadow: 0 4px 10px rgba(67, 97, 238, 0.3);'><i class='bi bi-file-earmark-arrow-down'></i> Générer le bon de remise</button>
    </form>";
    if ($lastRemise && !$cycleClosed) {
        echo "<a href='?page=pdf_bon&bon_id={$lastRemise['id']}' target='_blank' class='btn-secondary' style='text-decoration:none;display:inline-flex;align-items:center;gap:5px;'>🖨️ Voir le bon actuel</a>";
    }
    echo "</div>";
    // Statut des bons du dernier cycle
    echo "<div style='display:flex;flex-direction:column;gap:4px;font-size:.8rem;'>";
    if ($cycleClosed) {
        $dt = ($lastRestit && $lastRestit['signed_at']) ? ' le ' . date('d/m/Y H:i', strtotime($lastRestit['signed_at'])) : '';
        echo "<span style='color:var(--text3);'>📦 Matériel restitué — cycle " . h($lastRemise['numero']) . " clôturé$dt</span>";
        echo "<span style='color:var(--text3);font-size:.75rem;'>Les bons signés restent consultables dans l'historique ci-dessous.</span>";
    } else {
        foreach ([['📥 Remise', $lastRemise], ['📤 Restitution', $lastRestit]] as [$lbl, $b]) {
            if ($b && $b['status'] === 'signed') {
                $dt = date('d/m/Y H:i', strtotime($b['signed_at']));
                echo "<span style='color:var(--success);'>✅ $lbl " . h($b['numero']) . " signé — " . h($b['signer_name']) . " le $dt</span>";
            } elseif ($b && $b['status'] === 'pending' && (!$b['expires_at'] || strtotime($b['expires_at']) >= time())) {
                echo "<span style='color:var(--warning);'>⏳ $lbl " . h($b['numero']) . " — en attente de signature</span>";
            } elseif ($b) {
                echo "<span style='color:var(--text3);'>⏰ $lbl " . h($b['numero']) . " — lien de signature expiré</span>";
            } else {
                echo "<span style='color:var(--text3);'>— $lbl : aucun bon</span>";
            }
        }
    }
    echo "</div>";
    // Annulation manuelle des bons en attente
    if ($hasPendingBons) {
        echo "<form method='post' action='index.php?page=refs&tab=agents' onsubmit=\"return confirm('Annuler les bons en attente ? Un nouveau bon devra être généré et signé.')\" style='display:inline;'>
            <input type='hidden' name='_entity' value='bon'>
            <input type='hidden' name='_action' value='cancel_pending'>
            <input type='hidden' name='agent_id' value='$id'>
            <input type='hidden' name='" . CSRF_TOKEN_NAME . "' value='" . h($CSRF_TOKEN) . "'>
            <button type='submit' class='btn-secondary' style='font-size:.82rem;padding:.45rem .9rem;color:var(--warning);border-color:rgba(245,158,11,.3);' title='Annuler les bons non signés (les bons signés sont conservés)'>🚫 Annuler les bons en attente</button>
        </form>";
    }
    echo "</div>";

    // ── Remise partielle : sélection des équipements du bon (optionnel) ──────
    $dotation = bonSnapshotItems($pdo, $id);
    $hasDotation = !empty($dotation['devices']) || !empty($dotation['lines']);
    $nbItems = count($dotation['devices']) + count($dotation['lines']);
    if (empty($agt['archived']) && $nbItems > 1) {
        echo "<details style='margin-bottom:1.25rem;background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:.6rem .9rem;'>
            <summary style='cursor:pointer;font-size:.85rem;color:var(--text2);font-weight:600;'>📄 Remise partielle — choisir les équipements du bon</summary>
            <div class='muted' style='font-size:.78rem;margin:.6rem 0;'>Par défaut, le bouton « Générer le bon de remise » couvre toute la dotation. Ici, vous pouvez générer un bon ne listant que certains équipements (ex. : nouvel appareil remis séparément).</div>
            <form method='post' action='index.php' target='_blank' style='padding:0;margin:0;'>
                <input type='hidden' name='_entity' value='bon'>
                <input type='hidden' name='_action' value='generate_remise'>
                <input type='hidden' name='items_selection' value='1'>
                <input type='hidden' name='agent_id' value='$id'>
                <input type='hidden' name='" . CSRF_TOKEN_NAME . "' value='" . h($CSRF_TOKEN) . "'>";
        foreach ($dotation['devices'] as $it) {
            echo "<label style='display:flex;align-items:center;gap:.5rem;margin-bottom:.35rem;font-size:.85rem;cursor:pointer;text-transform:none;font-weight:400;color:var(--text);'>
                <input type='checkbox' name='ret_devices[]' value='" . (int)$it['device_id'] . "' checked style='width:15px;height:15px;accent-color:var(--primary);cursor:pointer;flex-shrink:0;'>
                📱 " . h(trim(($it['brand'] ?? '') . ' ' . ($it['name'] ?? ''))) . " <span class='muted' style='font-size:.72rem;'>IMEI " . h($it['imei']) . "</span></label>";
        }
        foreach ($dotation['lines'] as $it) {
            $tag = !empty($it['esim']) ? ' (eSIM)' : (!empty($it['personal_device']) ? ' (BYOD)' : '');
            echo "<label style='display:flex;align-items:center;gap:.5rem;margin-bottom:.35rem;font-size:.85rem;cursor:pointer;text-transform:none;font-weight:400;color:var(--text);'>
                <input type='checkbox' name='ret_lines[]' value='" . (int)$it['line_id'] . "' checked style='width:15px;height:15px;accent-color:var(--primary);cursor:pointer;flex-shrink:0;'>
                📞 " . formatPhone($it['phone_number']) . "$tag <span class='muted' style='font-size:.72rem;'>" . h($it['plan_name'] ?: '') . "</span></label>";
        }
        echo "<button type='submit' class='btn-secondary' style='margin-top:.4rem;font-size:.82rem;'>📄 Générer le bon avec la sélection</button>
            </form></details>";
    }

    // ── Restitution : génération avec sélection des équipements ──────────────
    // Proposée uniquement si la remise du cycle EN COURS est signée et pas
    // encore entièrement restituée : un cycle clôturé exige d'abord un nouveau
    // bon de remise signé pour la dotation actuelle.
    if ($lastRemise && $lastRemise['status'] === 'signed' && !$cycleClosed && $hasDotation && empty($agt['archived'])) {
        echo "<details style='margin-bottom:1.25rem;background:rgba(245,158,11,.05);border:1px solid rgba(245,158,11,.25);border-radius:8px;padding:.6rem .9rem;'>
            <summary style='cursor:pointer;font-size:.85rem;color:var(--warning);font-weight:600;'>📤 Générer un bon de restitution — choisir les équipements restitués</summary>
            <div class='muted' style='font-size:.78rem;margin:.6rem 0;'>Cochez les équipements restitués (restitution partielle possible). Le bon sera lié au bon de remise " . h($lastRemise['numero']) . ". À la signature, les équipements cochés retournent automatiquement en stock.</div>
            <form method='post' action='index.php' target='_blank' style='padding:0;margin:0;'>
            <input type='hidden' name='_entity' value='bon'>
            <input type='hidden' name='_action' value='generate_restitution'>
            <input type='hidden' name='agent_id' value='$id'>
            <input type='hidden' name='" . CSRF_TOKEN_NAME . "' value='" . h($CSRF_TOKEN) . "'>";
        foreach ($dotation['devices'] as $it) {
            echo "<label style='display:flex;align-items:center;gap:.5rem;margin-bottom:.4rem;font-size:.88rem;cursor:pointer;text-transform:none;font-weight:400;color:var(--text);'>
                <input type='checkbox' name='ret_devices[]' value='" . (int)$it['device_id'] . "' checked style='width:15px;height:15px;accent-color:var(--warning);cursor:pointer;flex-shrink:0;'>
                📱 " . h(trim(($it['brand'] ?? '') . ' ' . ($it['name'] ?? ''))) . " <span class='muted' style='font-size:.75rem;'>IMEI " . h($it['imei']) . "</span></label>";
        }
        foreach ($dotation['lines'] as $it) {
            $tag = !empty($it['esim']) ? ' (eSIM)' : (!empty($it['personal_device']) ? ' (BYOD)' : '');
            echo "<label style='display:flex;align-items:center;gap:.5rem;margin-bottom:.4rem;font-size:.88rem;cursor:pointer;text-transform:none;font-weight:400;color:var(--text);'>
                <input type='checkbox' name='ret_lines[]' value='" . (int)$it['line_id'] . "' checked style='width:15px;height:15px;accent-color:var(--warning);cursor:pointer;flex-shrink:0;'>
                📞 " . formatPhone($it['phone_number']) . "$tag <span class='muted' style='font-size:.75rem;'>" . h($it['plan_name'] ?: '') . "</span></label>";
        }
        echo "<button type='submit' class='btn-secondary' style='margin-top:.5rem;color:var(--warning);border-color:rgba(245,158,11,.4);font-weight:600;'>📤 Générer le bon de restitution</button>
        </form></details>";
    }

    echo "<div style='display:flex; gap:2rem; flex-wrap:wrap;'>";
    
    // Colonne 1 : Infos & Parc actuel
    echo "<div style='flex:1; min-width:300px;'>";
    echo "<div style='background:var(--bg3); padding:1rem; border-radius:var(--radius-sm); margin-bottom:1.5rem;'><h4 style='color:var(--text); margin-bottom:10px;'><i class='bi bi-envelope'></i> Coordonnées</h4><div><strong>Email :</strong> " . h($agt['email']?:'Non renseigné') . "</div><div><strong>Service :</strong> " . h($agt['service_name']?:'Aucun') . "</div></div>";
    
    echo "<h4 style='color:var(--primary); margin-bottom:10px; border-bottom:1px solid var(--border); padding-bottom:5px;'><i class='bi bi-telephone'></i> Lignes attribuées</h4>";
    if(!$lines) echo "<div class='muted' style='margin-bottom:1rem;'>Aucune ligne active.</div>";
    foreach($lines as $l) {
        $byodBadge = !empty($l['personal_device']) ? "<span class='badge' style='background:rgba(56,189,248,.15);color:var(--info);margin-left:6px;'><i class='bi bi-phone'></i> Tél. perso (BYOD)</span>" : '';
        $esimBadge = !empty($l['esim']) ? "<span class='badge' style='background:rgba(139,92,246,.15);color:#a78bfa;margin-left:6px;'><i class='bi bi-sim'></i> eSIM</span>" : '';
        $esimExtra = '';
        if (!empty($l['esim'])) {
            if ($l['eid']) $esimExtra .= "<br><span class='muted' style='font-size:.72rem;'>EID: ".h($l['eid'])."</span>";
            if ($l['activation_code']) $esimExtra .= "<br><span class='muted' style='font-size:.72rem;'>Code activation : <code style='word-break:break-all;'>".h($l['activation_code'])."</code></span>";
        }
        echo "<div style='background:var(--card2); border:1px solid var(--border); padding:10px; border-radius:8px; margin-bottom:10px;'><strong style='font-size:1.1rem;'>".formatPhone($l['phone_number'])."</strong> ".statusBadge($l['status']).$byodBadge.$esimBadge."<br><span class='muted'>".h($l['plan_name']?:'Forfait inconnu')." (SIM: ".h($l['iccid']).")</span>".$esimExtra."</div>";
    }
    // Attribution rapide d'une ligne du stock
    if (empty($agt['archived'])) {
        if ($stockLines) {
            echo "<form onsubmit='quickAssign(this); return false;' style='display:flex;gap:.5rem;align-items:center;margin-bottom:1rem;padding:0;'>
                <input type='hidden' name='_entity' value='quick_assign'>
                <input type='hidden' name='_ajax' value='1'>
                <input type='hidden' name='agent_id' value='$id'>
                <input type='hidden' name='" . CSRF_TOKEN_NAME . "' value='" . h($CSRF_TOKEN) . "'>
                <select name='line_id' required style='flex:1;min-width:0;font-size:.85rem;'>
                    <option value=''>➕ Attribuer une ligne du stock (" . count($stockLines) . " disponible" . (count($stockLines) > 1 ? 's' : '') . ")…</option>";
            foreach ($stockLines as $sl) {
                $lbl = formatPhone($sl['phone_number']) . ($sl['esim'] ? ' (eSIM)' : '') . ($sl['plan_name'] ? ' — ' . $sl['plan_name'] : '') . ' — SIM ' . $sl['iccid'];
                echo "<option value='{$sl['id']}'>" . h($lbl) . "</option>";
            }
            echo "</select><button type='submit' class='btn-primary' style='padding:.45rem .8rem;font-size:.82rem;white-space:nowrap;'>Attribuer</button></form>";
        } else {
            echo "<div class='muted' style='font-size:.75rem;margin-bottom:1rem;'>Aucune ligne disponible en stock pour attribution.</div>";
        }
    }

    echo "<h4 style='color:var(--primary); margin-bottom:10px; margin-top:1.5rem; border-bottom:1px solid var(--border); padding-bottom:5px;'><i class='bi bi-phone'></i> Matériels attribués</h4>";
    $hasAnything = $devices || $byodLines;
    if(!$hasAnything) echo "<div class='muted'>Aucun matériel.</div>";
    foreach($devices as $d) { echo "<div style='background:var(--card2); border:1px solid var(--border); padding:10px; border-radius:8px; margin-bottom:10px;'><strong>".h($d['brand'].' '.$d['name'])."</strong> ".statusBadge($d['status'])."<br><span class='muted'>IMEI: ".h($d['imei'])."</span></div>"; }
    foreach($byodLines as $l) {
        echo "<div style='background:rgba(56,189,248,.07); border:1px solid rgba(56,189,248,.25); padding:10px; border-radius:8px; margin-bottom:10px;'>
                <strong style='color:var(--info);'><i class='bi bi-phone'></i> Téléphone personnel (BYOD)</strong><br>
                <span class='muted'>Ligne : ".formatPhone($l['phone_number'])." — l'agent utilise son propre appareil</span>
              </div>";
    }
    // Attribution rapide d'un matériel du stock
    if (empty($agt['archived'])) {
        if ($stockDevices) {
            echo "<form onsubmit='quickAssign(this); return false;' style='display:flex;gap:.5rem;align-items:center;margin-bottom:1rem;padding:0;'>
                <input type='hidden' name='_entity' value='quick_assign'>
                <input type='hidden' name='_ajax' value='1'>
                <input type='hidden' name='agent_id' value='$id'>
                <input type='hidden' name='" . CSRF_TOKEN_NAME . "' value='" . h($CSRF_TOKEN) . "'>
                <select name='device_id' required style='flex:1;min-width:0;font-size:.85rem;'>
                    <option value=''>➕ Attribuer un matériel du stock (" . count($stockDevices) . " disponible" . (count($stockDevices) > 1 ? 's' : '') . ")…</option>";
            foreach ($stockDevices as $sd) {
                $lbl = trim(($sd['brand'] ?? '') . ' ' . ($sd['name'] ?? '')) ?: 'Modèle inconnu';
                $lbl .= ' — ' . ($sd['serial_number'] ? 'S/N ' . $sd['serial_number'] : 'IMEI ' . $sd['imei']);
                echo "<option value='{$sd['id']}'>" . h($lbl) . "</option>";
            }
            echo "</select><button type='submit' class='btn-primary' style='padding:.45rem .8rem;font-size:.82rem;white-space:nowrap;'>Attribuer</button></form>";
        } else {
            echo "<div class='muted' style='font-size:.75rem;margin-bottom:1rem;'>Aucun matériel disponible en stock pour attribution.</div>";
        }
    }
    echo "</div>";

    // Colonne 2 : Pièces jointes & Historique
    echo "<div style='flex:1; min-width:300px; border-left:1px solid var(--border); padding-left:2rem;'>";
    
    echo "<h4 style='color:var(--text); margin-bottom:10px;'><i class='bi bi-paperclip'></i> Pièces jointes</h4>";
    echo "<form method='post' enctype='multipart/form-data' style='display:flex;gap:10px;margin-bottom:1rem;padding:0;'><input type='hidden' name='_entity' value='attachment'><input type='hidden' name='agent_id' value='$id'><input type='hidden' name='" . CSRF_TOKEN_NAME . "' value='" . h($CSRF_TOKEN) . "'><input type='file' name='file' required style='padding:5px; background:var(--bg3); color:var(--text); border:1px solid var(--border); border-radius:4px; flex:1;'><button type='submit' class='btn-primary' style='padding:5px 10px'>Uploader</button></form>";
    if($att) {
        echo "<ul style='padding-left:1.5rem; margin-bottom:2rem; color:var(--text);'>";
        // Diffusion par index.php (contrôle de session), jamais par Apache.
        foreach($att as $a) echo "<li style='margin-bottom:5px;'><a href='?page=attachment&id=".(int)$a['id']."' target='_blank' style='color:var(--info); text-decoration:none;'>".h($a['file_name'])."</a></li>";
        echo "</ul>";
    } else { echo "<div class='muted' style='margin-bottom:2rem;'>Aucun document.</div>"; }

    echo "<h4 style='color:var(--text); margin-bottom:1rem;'><i class='bi bi-clock-history'></i> Journal des affectations</h4>";
    if(!$history) echo "<div class='muted'>Aucun historique pour cet utilisateur.</div>";
    else {
        // Les entrées au-delà des 10 dernières sont masquées (bouton « Afficher plus »)
        $histShown = 10; $histTotal = count($history);
        echo "<ul style='list-style:none; padding:0; margin:0;'>";
        foreach($history as $hi => $h) {
            $icon = $h['entity_type'] === 'line' ? '📞 Ligne' : ($h['entity_type'] === 'device' ? '📱 Matériel' : '👤 Utilisateur');
            $desc = trim($h['action_desc']); $agtName = trim($h['first_name'].' '.$h['last_name']);
            if (preg_match('/(attribué[e]? à|affecté[e]? à)\s*$/', $desc)) { $desc .= ' ' . ($agtName ?: 'Utilisateur inconnu'); }
            $hiddenStyle = $hi >= $histShown ? 'display:none;' : '';
            $hiddenClass = $hi >= $histShown ? " class='agent-hist-more'" : '';
            echo "<li$hiddenClass style='{$hiddenStyle}padding-bottom:12px; margin-bottom:12px; border-bottom:1px solid var(--border)'>";
            echo "<strong style='color:var(--primary); font-size:.8rem;'>$icon - {$h['dt']}</strong><br><span style='font-size:.9rem;'>{$desc}</span><br><span style='font-size:.7rem; color:var(--text3);'>Par : " . h($h['author']?:'Système') . "</span></li>";
        } echo "</ul>";
        if ($histTotal > $histShown) {
            echo "<button type='button' class='btn-secondary' style='font-size:.78rem;padding:.4rem .9rem;margin-top:.25rem;'
                onclick=\"this.closest('div').querySelectorAll('.agent-hist-more').forEach(function(el){el.style.display='';}); this.remove();\">⏬ Afficher les " . ($histTotal - $histShown) . " entrées plus anciennes</button>";
        }
    } echo "</div></div>";

    // ── Historique des bons (appariement structurel par parent_id) ────────────
    $bonsAgent = $pdo->prepare("SELECT *, DATE_FORMAT(created_at, '%d/%m/%Y %H:%i') as created_fmt, DATE_FORMAT(signed_at, '%d/%m/%Y %H:%i') as signed_fmt FROM bons WHERE agent_id=? ORDER BY created_at DESC, id DESC LIMIT 40");
    $bonsAgent->execute([$id]); $bonsAgent = $bonsAgent->fetchAll();

    if ($bonsAgent) {
        echo "<div style='margin-top:1.5rem;'>";
        echo "<h4 style='color:var(--primary); margin-bottom:1rem; border-bottom:1px solid var(--border); padding-bottom:5px;'><i class='bi bi-file-earmark-text'></i> Historique des bons de remise / restitution</h4>";

        // Restitutions rattachées à leur bon de remise (la non-annulée en priorité)
        $childByParent = [];
        foreach ($bonsAgent as $b) {
            if ($b['type'] === 'restitution' && $b['parent_id']) $childByParent[$b['parent_id']][] = $b;
        }
        $pairs = [];
        foreach ($bonsAgent as $b) {
            if ($b['type'] === 'remise') {
                $child = null;
                foreach (($childByParent[$b['id']] ?? []) as $c) { if ($c['status'] !== 'cancelled') { $child = $c; break; } }
                if (!$child && !empty($childByParent[$b['id']])) $child = $childByParent[$b['id']][0];
                $pairs[] = ['remise' => $b, 'restitution' => $child];
            } elseif (!$b['parent_id']) {
                // Restitution orpheline (migration ancien système)
                $pairs[] = ['remise' => null, 'restitution' => $b];
            }
        }

        $pairColors = ['rgba(16,185,129,.06)', 'rgba(99,102,241,.05)', 'rgba(245,158,11,.05)', 'rgba(236,72,153,.05)'];
        $now = time();
        // Les cycles au-delà des 4 derniers sont masqués (bouton « Afficher plus »)
        $pairsShown = 4;
        foreach ($pairs as $pi => $pair):
            $bg = $pairColors[$pi % count($pairColors)];
            $hiddenStyle = $pi >= $pairsShown ? 'display:none;' : '';
            $hiddenClass = $pi >= $pairsShown ? " class='agent-bons-more'" : '';
            echo "<div$hiddenClass style='{$hiddenStyle}background:$bg;border:1px solid var(--border);border-radius:10px;padding:1rem;margin-bottom:.75rem;'>";
            foreach (['remise' => ['📥','var(--success)','Bon de Remise'], 'restitution' => ['📤','var(--warning)','Bon de Restitution']] as $type => [$icon, $color, $label]):
                $b = $pair[$type];
                if (!$b) continue;
                $isExpired = $b['expires_at'] && strtotime($b['expires_at']) < $now;
                if ($b['status'] === 'signed') {
                    $badge = "<span style='background:rgba(16,185,129,.15);color:var(--success);font-size:.7rem;font-weight:600;padding:.1rem .45rem;border-radius:999px;'><i class='bi bi-check-circle-fill'></i> Signé</span>";
                } elseif ($b['status'] === 'cancelled') {
                    $badge = "<span style='background:rgba(148,163,184,.12);color:var(--text3);font-size:.7rem;font-weight:600;padding:.1rem .45rem;border-radius:999px;' title='" . h($b['cancel_reason'] ?: '') . "'><i class='bi bi-slash-circle'></i> Annulé</span>";
                } elseif ($isExpired) {
                    $badge = "<span style='background:rgba(245,158,11,.15);color:var(--warning);font-size:.7rem;font-weight:600;padding:.1rem .45rem;border-radius:999px;'>⏰ Expiré</span>";
                } else {
                    $badge = "<span style='background:rgba(56,189,248,.15);color:var(--info);font-size:.7rem;font-weight:600;padding:.1rem .45rem;border-radius:999px;'>⏳ En attente</span>";
                }
                echo "<div style='display:flex;align-items:baseline;gap:.75rem;margin-bottom:.35rem;'>";
                echo "<span style='font-weight:700;color:$color;font-size:.9rem;'>$icon $label <span style='font-weight:600;font-size:.78rem;'>" . h($b['numero'] ?: '') . "</span></span> $badge";
                echo "<span style='font-size:.78rem;color:var(--text3);margin-left:auto;'>Créé le {$b['created_fmt']} — par " . h($b['dsi_name'] ?: $b['created_by'] ?: '—') . "</span>";
                echo "<a href='?page=pdf_bon&bon_id={$b['id']}' target='_blank' title='Voir / imprimer ce bon' style='text-decoration:none;font-size:.85rem;'>🖨️</a>";
                if ($b['status'] === 'pending' && !$isExpired) {
                    $signUrl = baseUrl($pdo) . '?page=sign&token=' . $b['token'];
                    echo "<button type='button' class='btn-icon' style='padding:0 .2rem;font-size:.85rem;' title='Copier le lien de signature' onclick=\"copySignLink(this, '" . h($signUrl) . "')\"><i class='bi bi-link-45deg'></i></button>";
                    if ($smtpConfigured && !empty($agt['email'])) {
                        echo "<form method='post' action='index.php' target='_blank' style='display:inline;margin:0;padding:0;'>
                            <input type='hidden' name='_entity' value='bon'>
                            <input type='hidden' name='_action' value='send_mail'>
                            <input type='hidden' name='bon_id' value='{$b['id']}'>
                            <input type='hidden' name='" . CSRF_TOKEN_NAME . "' value='" . h($CSRF_TOKEN) . "'>
                            <button type='submit' class='btn-icon' style='padding:0 .2rem;font-size:.85rem;' title='Envoyer le lien de signature à " . h($agt['email']) . "'><i class='bi bi-envelope'></i></button>
                        </form>";
                    }
                }
                echo "</div>";
                if ($b['status'] === 'signed' && $b['signer_name']) {
                    echo "<div style='font-size:.78rem;color:var(--success);margin-left:1.5rem;'>✍️ " . h($b['signer_name']) . " — le {$b['signed_fmt']}</div>";
                }
                if ($b['status'] === 'cancelled' && $b['cancel_reason']) {
                    echo "<div style='font-size:.72rem;color:var(--text3);margin-left:1.5rem;'>Motif : " . h($b['cancel_reason']) . "</div>";
                }
            endforeach;
            echo "</div>";
        endforeach;
        if (count($pairs) > $pairsShown) {
            echo "<button type='button' class='btn-secondary' style='font-size:.78rem;padding:.4rem .9rem;'
                onclick=\"this.closest('div').querySelectorAll('.agent-bons-more').forEach(function(el){el.style.display='';}); this.remove();\">⏬ Afficher les " . (count($pairs) - $pairsShown) . " cycles précédents</button>";
        }
        echo "</div>";
    }
    exit;
}

// ─── 6. TRAITEMENT DES FORMULAIRES POST ────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // ── Vérification CSRF (tous les formulaires POST sauf login) ─
    if (!csrf_verify()) {
        flash('error', 'Erreur de sécurité (jeton CSRF invalide). Veuillez recharger la page et réessayer.');
        $redirect = 'index.php?page=' . ($_GET['page'] ?? 'dashboard');
        if (isset($_GET['tab'])) $redirect .= '&tab=' . $_GET['tab'];
        if (isset($_GET['sub'])) $redirect .= '&sub=' . preg_replace('/[^a-z]/', '', $_GET['sub']);
        header('Location: ' . $redirect); exit;
    }

    $ent = $_POST['_entity'] ?? ''; $act = $_POST['_action'] ?? ''; $id = (int)($_POST['_id'] ?? 0); $d = $_POST;
    try {
        // Toutes les écritures d'une action sont atomiques : une erreur à
        // mi-parcours annule tout (pas d'état incohérent en base).
        $pdo->beginTransaction();
        // Traitement de la pièce jointe
        if ($ent === 'attachment') {
            $agentId = (int)($d['agent_id'] ?? 0);
            if ($agentId > 0 && isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
                // Validation taille
                if ($_FILES['file']['size'] > UPLOAD_MAX_BYTES) {
                    flash('error', 'Fichier trop volumineux (max 1 Mo).');
                } else {
                    // Validation MIME réel (pas l'extension)
                    $finfo = new finfo(FILEINFO_MIME_TYPE);
                    $mime  = $finfo->file($_FILES['file']['tmp_name']);
                    $allowedAttachMime = ['image/png','image/jpeg','image/gif','image/webp','application/pdf',
                                          'application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                                          'text/plain','text/csv'];
                    // Bloquer toute extension PHP/script dans le nom
                    $origName = basename($_FILES['file']['name'] ?? '');
                    $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
                    $blockedExt = ['php','phtml','phar','php3','php4','php5','php7','phps','cgi','pl','py','sh','rb','exe'];
                    if (!in_array($mime, $allowedAttachMime, true)) {
                        flash('error', 'Type de fichier non autorisé.');
                    } elseif (in_array($ext, $blockedExt, true)) {
                        flash('error', 'Extension de fichier non autorisée.');
                    } else {
                        $safeName = preg_replace('/[^a-zA-Z0-9.\-_]/', '_', $origName);
                        // Préfixe aléatoire (non énumérable) : le fichier est servi
                        // statiquement, un nom devinable exposerait les documents.
                        $destPath = UPLOAD_DIR . bin2hex(random_bytes(16)) . '_' . $safeName;
                        if (move_uploaded_file($_FILES['file']['tmp_name'], $destPath)) {
                            $pdo->prepare("INSERT INTO attachments (entity_type, entity_id, file_name, file_path) VALUES ('agent', ?, ?, ?)")
                                ->execute([$agentId, $safeName, $destPath]);
                            flash('success', 'Document ajouté.');
                        }
                    }
                }
            }
        } elseif ($ent === 'settings') {
            // Sauvegarde des seuils d'alerte
            foreach (['sim_stock_alert', 'device_stock_alert'] as $key) {
                if (isset($d[$key])) {
                    $val = max(0, (int)$d[$key]);
                    $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key=?")->execute([$val, $key]);
                }
            }
            // Couleur principale du site (case décochée = retour à la palette d'origine)
            if (isset($d['ui_color_form'])) {
                $c = trim($d['ui_primary_color'] ?? '');
                if (empty($d['ui_primary_color_enabled']) || !preg_match('/^#[0-9a-fA-F]{6}$/', $c)) $c = '';
                $pdo->prepare("INSERT INTO settings (setting_key, setting_value, label) VALUES ('ui_primary_color', ?, 'Couleur principale du site (vide = défaut)')
                               ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)")->execute([$c]);
            }
            // Sauvegarde de l'URL du site
            if (array_key_exists('site_url', $d)) {
                $url = trim($d['site_url'] ?? '');
                // Normaliser : retirer le slash final
                $url = rtrim($url, '/');
                $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key='site_url'")->execute([$url]);
            }
            // Configuration LDAP / Active Directory (réservée aux super-admins).
            // Les champs imposés par variable d'environnement ne sont pas écrasés.
            if (isset($d['ldap_form'])) {
                if (empty($_SESSION['is_admin'])) {
                    flash('error', "La configuration LDAP est réservée aux super-administrateurs.");
                } else {
                    $set = $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key=?");
                    // Normaliser le serveur : un schéma saisi (ldap:// ou ldaps://) est
                    // retiré du champ et bascule la case LDAPS en conséquence — seul le
                    // FQDN/IP est stocké, la case fait foi pour le mode TLS.
                    $srv = trim($d['ldap_server'] ?? '');
                    $srvLow = strtolower($srv);
                    if (str_starts_with($srvLow, 'ldaps://'))    { $srv = substr($srv, 8); $d['ldap_use_ssl'] = '1'; }
                    elseif (str_starts_with($srvLow, 'ldap://')) { $srv = substr($srv, 7); unset($d['ldap_use_ssl']); }
                    $d['ldap_server'] = trim(rtrim($srv, '/'));
                    foreach (['ldap_enabled','ldap_use_ssl','ldap_validate_cert'] as $key) {
                        if (!ldap_env_locked($key)) $set->execute([!empty($d[$key]) ? '1' : '0', $key]);
                    }
                    if (!ldap_env_locked('ldap_port')) $set->execute([(string)max(0, (int)($d['ldap_port'] ?? 0)), 'ldap_port']);
                    foreach (['ldap_server','ldap_ca_cert','ldap_domain','ldap_base_dn','ldap_required_group','ldap_bind_user'] as $key) {
                        if (!ldap_env_locked($key)) $set->execute([trim($d[$key] ?? ''), $key]);
                    }
                    // Mot de passe du compte de service : conservé si le champ est laissé vide
                    if (!ldap_env_locked('ldap_bind_password') && ($d['ldap_bind_password'] ?? '') !== '') {
                        $set->execute([$d['ldap_bind_password'], 'ldap_bind_password']);
                    }
                    ldap_init($pdo); // recharge la config (utile si « Tester » suit)
                    logHistory($pdo, 'admin', (int)$_SESSION['user_id'], "Modification de la configuration LDAP/AD");
                    flash('success', 'Configuration LDAP enregistrée.' . (ldap_auth_enabled() ? '' : (ldap_cfg('ldap_enabled') && !extension_loaded('ldap') ? " ⚠️ Extension PHP « ldap » manquante : l'authentification AD restera inactive." : '')));
                }
            }
            // Configuration SMTP (envoi des liens de signature).
            // Les champs imposés par variable d'environnement (MAIL_*) ne sont pas écrasés.
            if (isset($d['smtp_host'])) {
                foreach (['smtp_host','smtp_port','smtp_user','smtp_from','smtp_from_name'] as $key) {
                    if (!smtp_env_locked($key)) $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key=?")->execute([trim($d[$key] ?? ''), $key]);
                }
                if (!smtp_env_locked('smtp_secure')) {
                    $sec = in_array($d['smtp_secure'] ?? '', ['tls','ssl','none'], true) ? $d['smtp_secure'] : 'tls';
                    $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key='smtp_secure'")->execute([$sec]);
                }
                // Mot de passe : conservé si le champ est laissé vide
                if (!smtp_env_locked('smtp_pass') && ($d['smtp_pass'] ?? '') !== '') {
                    $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key='smtp_pass'")->execute([$d['smtp_pass']]);
                }
            }
            // Paramètres des demandes de téléphone (formulaire public + circuit)
            if (isset($d['request_form'])) {
                $set = $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key=?");
                foreach (['request_notify_email', 'request_dsi_email', 'request_dgs_email'] as $key) {
                    if (array_key_exists($key, $d)) $set->execute([(string)(fmtEmail($d[$key]) ?? ''), $key]);
                }
                foreach (['request_dsi_name', 'request_dgs_name'] as $key) {
                    if (array_key_exists($key, $d)) $set->execute([trim($d[$key]), $key]);
                }
                if (isset($d['request_reminder_days'])) $set->execute([(string)max(1, (int)$d['request_reminder_days']), 'request_reminder_days']);
            }
            // Personnalisation des textes du formulaire public de demande.
            // strip_tags : le texte est ré-échappé à l'affichage (h()), on retire
            // simplement tout balisage HTML pour éviter les surprises.
            if (isset($d['request_form_texts'])) {
                $set = $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key=?");
                foreach (['request_form_title', 'request_form_intro', 'request_form_motivation_label', 'request_form_motifs', 'request_form_nota', 'request_form_success'] as $key) {
                    if (array_key_exists($key, $d)) {
                        $val = trim(strip_tags((string)$d[$key]));
                        // Titre et libellé motivation : non vides (repli si vidés)
                        if (in_array($key, ['request_form_title', 'request_form_motivation_label'], true) && $val === '') continue;
                        $set->execute([$val, $key]);
                    }
                }
                // Au moins un motif de remplacement doit rester
                if (array_key_exists('request_form_motifs', $d) && trim(strip_tags($d['request_form_motifs'])) === '') {
                    $set->execute(["Panne\nCasse\nPerte\nVol\nObsolescence", 'request_form_motifs']);
                }
            }
            // Suppression du logo
            if (!empty($d['delete_logo'])) {
                $oldLogo = getSetting($pdo, 'pdf_logo_path', '');
                if ($oldLogo && file_exists($oldLogo)) @unlink($oldLogo);
                $pdo->prepare("UPDATE settings SET setting_value='' WHERE setting_key='pdf_logo_path'")->execute();
            }
            // Upload du logo
            if (isset($_FILES['pdf_logo']) && $_FILES['pdf_logo']['error'] === UPLOAD_ERR_OK) {
                $finfo = new finfo(FILEINFO_MIME_TYPE);
                $mime  = $finfo->file($_FILES['pdf_logo']['tmp_name']);
                // SVG retiré (défini dans config) : il peut contenir du JavaScript (XSS)
                $allowedLogoMime = UPLOAD_ALLOWED_MIME;
                if ($_FILES['pdf_logo']['size'] > UPLOAD_MAX_BYTES) {
                    flash('error', 'Logo trop volumineux (max 1 Mo).');
                } elseif (!in_array($mime, $allowedLogoMime, true)) {
                    flash('error', 'Format non autorisé. Utilisez PNG, JPG, GIF ou WEBP.');
                } else {
                    if (!is_dir(UPLOAD_DIR)) mkdir(UPLOAD_DIR, 0755, true);
                    $ext  = pathinfo($_FILES['pdf_logo']['name'], PATHINFO_EXTENSION);
                    $dest = UPLOAD_DIR . 'pdf_logo_' . bin2hex(random_bytes(8)) . '.' . strtolower($ext);
                    // Supprimer l'ancien logo
                    $oldLogo = getSetting($pdo, 'pdf_logo_path', '');
                    if ($oldLogo && file_exists($oldLogo)) @unlink($oldLogo);
                    if (move_uploaded_file($_FILES['pdf_logo']['tmp_name'], $dest)) {
                        $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key='pdf_logo_path'")->execute([$dest]);
                    }
                }
            }
            if (!isset($d['ldap_form'])) flash('success', 'Paramètres enregistrés.'); // la carte LDAP a son propre message
        } elseif ($ent === 'admin_signature') {
            // Signature manuscrite (visa DSI) — une par compte admin.
            // Chacun gère la sienne ; un super-admin peut gérer celles des autres.
            $sig      = $d['signature_data'] ?? '';
            $targetId = (int)($d['_id'] ?? 0) ?: (int)$_SESSION['user_id'];
            if ($targetId !== (int)$_SESSION['user_id'] && empty($_SESSION['is_admin'])) {
                flash('error', "Seul un super-administrateur peut modifier la signature d'un autre compte.");
            } elseif (!empty($d['delete_signature'])) {
                $pdo->prepare("UPDATE users SET signature_data=NULL WHERE id=?")->execute([$targetId]);
                flash('success', 'Signature supprimée.');
            } elseif (strpos($sig, 'data:image/png;base64,') === 0) {
                $pdo->prepare("UPDATE users SET signature_data=? WHERE id=?")->execute([$sig, $targetId]);
                flash('success', 'Signature enregistrée — elle sera apposée en visa DSI sur les prochains bons générés par ce compte.');
            } else {
                flash('error', "Signature invalide — dessinez dans le cadre avant d'enregistrer.");
            }
        } elseif ($ent === 'bulk') {
            // Actions en masse (bulk)
            $bulkAction = $d['bulk_action'] ?? '';
            $bulkType   = $d['bulk_type'] ?? '';   // 'line' ou 'device'
            $bulkIds    = array_map('intval', array_filter($_POST['bulk_ids'] ?? []));
            if (empty($bulkIds)) { flash('error', 'Aucun élément sélectionné.'); }
            elseif (!in_array($bulkAction, ['archive','restore'])) { flash('error', 'Action invalide.'); }
            else {
                $done = 0;
                foreach ($bulkIds as $bid) {
                    if ($bulkType === 'line') {
                        if ($bulkAction === 'archive') {
                            $devId = $pdo->query("SELECT device_id FROM mobile_lines WHERE id=$bid")->fetchColumn();
                            $oldAgt = $pdo->query("SELECT agent_id FROM mobile_lines WHERE id=$bid")->fetchColumn();
                            $pdo->prepare("UPDATE mobile_lines SET archived=1, status='Resiliated', device_id=NULL, agent_id=NULL, service_id=NULL WHERE id=?")->execute([$bid]);
                            logHistory($pdo, 'line', $bid, "Archivage en masse", $oldAgt);
                            if ($oldAgt) cancelPendingBons($pdo, $oldAgt, "Ligne archivée en masse");
                            if ($devId) { $pdo->prepare("UPDATE devices SET status='Stock', agent_id=NULL, service_id=NULL WHERE id=?")->execute([$devId]); logHistory($pdo,'device',$devId,"Retour stock auto (archivage masse ligne)"); }
                        } elseif ($bulkAction === 'restore') {
                            $pdo->prepare("UPDATE mobile_lines SET archived=0, status='Stock', agent_id=NULL WHERE id=?")->execute([$bid]);
                            logHistory($pdo, 'line', $bid, "Restauration en masse");
                        }
                    } elseif ($bulkType === 'device') {
                        if ($bulkAction === 'archive') {
                            $oldAgt = $pdo->query("SELECT agent_id FROM devices WHERE id=$bid")->fetchColumn();
                            $pdo->prepare("UPDATE devices SET archived=1, status='HS', agent_id=NULL, service_id=NULL WHERE id=?")->execute([$bid]);
                            logHistory($pdo, 'device', $bid, "Archivage en masse", $oldAgt);
                            if ($oldAgt) cancelPendingBons($pdo, $oldAgt, "Matériel archivé en masse");
                            $pdo->prepare("UPDATE mobile_lines SET device_id=NULL WHERE device_id=?")->execute([$bid]);
                        } elseif ($bulkAction === 'restore') {
                            $pdo->prepare("UPDATE devices SET archived=0, status='Stock', agent_id=NULL WHERE id=?")->execute([$bid]);
                            logHistory($pdo, 'device', $bid, "Restauration en masse");
                        }
                    }
                    $done++;
                }
                flash('success', "$done élément(s) traité(s) avec succès.");
            }
        } elseif ($ent === 'bon') {
            $agentId = (int)($d['agent_id'] ?? 0);
            if ($act === 'generate_remise') {
                $agentRow = $agentId ? $pdo->query("SELECT id, archived FROM agents WHERE id=$agentId")->fetch() : null;
                if (!$agentRow || $agentRow['archived']) {
                    flash('error', 'Agent introuvable ou archivé.');
                } else {
                    $items = bonSnapshotItems($pdo, $agentId);
                    // Remise partielle : si le formulaire fournit une sélection, ne garder
                    // que les équipements cochés (par défaut : toute la dotation)
                    if (!empty($d['items_selection'])) {
                        $selDev  = array_map('intval', (array)($d['ret_devices'] ?? []));
                        $selLine = array_map('intval', (array)($d['ret_lines'] ?? []));
                        $items['devices'] = array_values(array_filter($items['devices'], fn($x) => in_array((int)$x['device_id'], $selDev, true)));
                        $items['lines']   = array_values(array_filter($items['lines'],   fn($x) => in_array((int)$x['line_id'],   $selLine, true)));
                        if (empty($items['devices']) && empty($items['lines'])) {
                            flash('error', 'Sélectionnez au moins un équipement à remettre.');
                            $pdo->commit();
                            header('Location: index.php?page=refs&tab=agents'); exit;
                        }
                    }
                    if (empty($items['devices']) && empty($items['lines'])) {
                        flash('error', 'Aucun équipement attribué à cet agent — rien à remettre.');
                        $pdo->commit();
                        header('Location: index.php?page=pdf_bon&agent_id=' . $agentId); exit;
                    }
                    // ── Couverture existante : un équipement déjà listé sur un bon de remise
                    // SIGNÉ (et non restitué depuis) est exclu du nouveau bon. On rejoue les
                    // bons signés dans l'ordre chronologique : une remise couvre l'équipement,
                    // une restitution signée lève la couverture.
                    $coverage = [];
                    $actifs = $pdo->prepare("SELECT numero, type, items FROM bons WHERE agent_id=? AND status='signed' ORDER BY signed_at ASC, id ASC");
                    $actifs->execute([$agentId]);
                    foreach ($actifs->fetchAll() as $ab) {
                        $abItems = $ab['items'] ? json_decode($ab['items'], true) : null;
                        if ($abItems === null) continue;
                        foreach (['devices' => ['d', 'device_id'], 'lines' => ['l', 'line_id']] as $grp => [$prefix, $idk]) {
                            foreach (($abItems[$grp] ?? []) as $it) {
                                if (empty($it[$idk])) continue;
                                $key = $prefix . (int)$it[$idk];
                                if ($ab['type'] === 'remise') {
                                    $coverage[$key] = ['json' => json_encode($it, JSON_UNESCAPED_UNICODE), 'numero' => $ab['numero']];
                                } else {
                                    unset($coverage[$key]);
                                }
                            }
                        }
                    }
                    // Exclure les items dont le contenu est strictement identique à la couverture
                    // (un contenu qui a changé — ex. nouvelle SIM — justifie un nouveau bon)
                    $excluded = 0; $coveredBy = [];
                    foreach (['devices' => ['d', 'device_id'], 'lines' => ['l', 'line_id']] as $grp => [$prefix, $idk]) {
                        $keep = [];
                        foreach ($items[$grp] as $it) {
                            $key = $prefix . (int)($it[$idk] ?? 0);
                            if (isset($coverage[$key]) && $coverage[$key]['json'] === json_encode($it, JSON_UNESCAPED_UNICODE)) {
                                $excluded++;
                                $coveredBy[$coverage[$key]['numero']] = true;
                            } else {
                                $keep[] = $it;
                            }
                        }
                        $items[$grp] = $keep;
                    }
                    if (empty($items['devices']) && empty($items['lines'])) {
                        $nums = implode(', ', array_keys($coveredBy));
                        flash('success', "Toute la dotation est déjà couverte par le(s) bon(s) signé(s) $nums — aucun nouveau bon nécessaire.");
                        $pdo->commit();
                        $st = $pdo->prepare("SELECT id FROM bons WHERE agent_id=? AND type='remise' AND status='signed' ORDER BY signed_at DESC, id DESC LIMIT 1");
                        $st->execute([$agentId]);
                        $lastId = (int)$st->fetchColumn();
                        header('Location: index.php?page=pdf_bon&' . ($lastId ? 'bon_id=' . $lastId : 'agent_id=' . $agentId)); exit;
                    }
                    if ($excluded > 0) {
                        flash('success', "$excluded équipement(s) déjà couvert(s) par un bon signé (" . implode(', ', array_keys($coveredBy)) . ") — le nouveau bon ne liste que le reste.");
                    }
                    $itemsJson = json_encode($items, JSON_UNESCAPED_UNICODE);
                    // Un bon en attente identique à la dotation actuelle ? On le réutilise.
                    $st = $pdo->prepare("SELECT id, items FROM bons WHERE agent_id=? AND type='remise' AND status='pending' AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY created_at DESC, id DESC LIMIT 1");
                    $st->execute([$agentId]);
                    $pending = $st->fetch();
                    if ($pending && $pending['items'] === $itemsJson) {
                        $pdo->commit();
                        header('Location: index.php?page=pdf_bon&bon_id=' . (int)$pending['id']); exit;
                    }
                    // Sinon : les bons en attente ne reflètent plus la réalité → annulés
                    cancelPendingBons($pdo, $agentId, 'Nouveau bon de remise généré');
                    $bonId  = createBon($pdo, 'remise', $agentId, $items);
                    $numero = $pdo->query("SELECT numero FROM bons WHERE id=$bonId")->fetchColumn();
                    logHistory($pdo, 'agent', $agentId, "📄 Bon de remise $numero généré", $agentId);
                    $pdo->commit();
                    header('Location: index.php?page=pdf_bon&bon_id=' . $bonId); exit;
                }
            } elseif ($act === 'generate_restitution') {
                // Parent : dernier bon de remise signé de l'agent
                $st = $pdo->prepare("SELECT * FROM bons WHERE agent_id=? AND type='remise' AND status='signed' ORDER BY signed_at DESC, id DESC LIMIT 1");
                $st->execute([$agentId]);
                $parentBon = $st->fetch();
                $parentId  = $parentBon ? (int)$parentBon['id'] : 0;
                if (!$agentId || !$parentId) {
                    flash('error', 'Impossible : aucun bon de remise signé pour cet agent.');
                } elseif (bonCycleClosed($pdo, $parentBon)) {
                    // Cycle déjà clôturé : la nouvelle dotation n'a pas fait l'objet
                    // d'un bon de remise signé, il n'y a rien à restituer formellement.
                    flash('error', 'Impossible : le bon de remise ' . $parentBon['numero'] . ' est déjà entièrement restitué. Générez et faites signer un bon de remise pour la dotation actuelle avant de créer une restitution.');
                } else {
                    $full = bonSnapshotItems($pdo, $agentId);
                    if (!empty($d['ret_all'])) {
                        // Restitution complète (raccourci depuis la page du bon)
                        $items = $full;
                    } else {
                        $selDev  = array_map('intval', (array)($d['ret_devices'] ?? []));
                        $selLine = array_map('intval', (array)($d['ret_lines'] ?? []));
                        $items = [
                            'agent'   => $full['agent'],
                            'devices' => array_values(array_filter($full['devices'], fn($x) => in_array((int)$x['device_id'], $selDev, true))),
                            'lines'   => array_values(array_filter($full['lines'],   fn($x) => in_array((int)$x['line_id'],   $selLine, true))),
                        ];
                    }
                    if (empty($items['devices']) && empty($items['lines'])) {
                        flash('error', 'Sélectionnez au moins un équipement à restituer.');
                    } else {
                        // Une restitution en attente est remplacée par celle-ci
                        $pdo->prepare("UPDATE bons SET status='cancelled', cancel_reason='Remplacé par un nouveau bon de restitution' WHERE agent_id=? AND type='restitution' AND status='pending'")
                            ->execute([$agentId]);
                        $bonId  = createBon($pdo, 'restitution', $agentId, $items, $parentId);
                        $numero = $pdo->query("SELECT numero FROM bons WHERE id=$bonId")->fetchColumn();
                        logHistory($pdo, 'agent', $agentId, "📤 Bon de restitution $numero généré (" . count($items['devices']) . " matériel(s), " . count($items['lines']) . " ligne(s))", $agentId);
                        $pdo->commit();
                        header('Location: index.php?page=pdf_bon&bon_id=' . $bonId); exit;
                    }
                }
            } elseif ($act === 'cancel_pending') {
                if ($agentId) cancelPendingBons($pdo, $agentId, "Annulation manuelle par l'administrateur");
                flash('success', 'Bons en attente annulés. Générez un nouveau bon si nécessaire.');
            } elseif ($act === 'send_mail') {
                // Envoi du lien de signature à l'agent par e-mail
                $bonId = (int)($d['bon_id'] ?? 0);
                $st = $pdo->prepare("SELECT b.*, a.email, a.first_name, a.last_name FROM bons b JOIN agents a ON b.agent_id=a.id WHERE b.id=?");
                $st->execute([$bonId]);
                $b = $st->fetch();
                $isSignable = $b && $b['status'] === 'pending' && (!$b['expires_at'] || strtotime($b['expires_at']) >= time());
                if (!$b) {
                    flash('error', 'Bon introuvable.');
                } elseif (!$isSignable) {
                    flash('error', "Ce bon n'est plus signable (signé, annulé ou expiré) — rien à envoyer.");
                } elseif (empty($b['email'])) {
                    flash('error', "Cet agent n'a pas d'adresse e-mail. Renseignez-la dans sa fiche.");
                } elseif (!mailTplEnabled($pdo, 'bon')) {
                    flash('error', "L'envoi des e-mails « Signature d'un bon » est désactivé (Paramètres → Envoi d'e-mails).");
                } else {
                    $typeLbl = $b['type'] === 'remise' ? 'remise' : 'restitution';
                    $url     = baseUrl($pdo) . '?page=sign&token=' . $b['token'];
                    $expFmt  = $b['expires_at'] ? date('d/m/Y', strtotime($b['expires_at'])) : null;
                    [$subject, $html] = mailRender($pdo, 'bon', [
                        'prenom' => h($b['first_name']), 'type_bon' => $typeLbl, 'numero' => h($b['numero']),
                        'bouton' => requestMailButton($url, 'Signer le bon'), 'lien' => h($url),
                        'expiration' => $expFmt ? '<p style="font-size:13px;color:#666;">Ce lien est valable jusqu\'au <strong>' . $expFmt . '</strong>.</p>' : '',
                    ]);
                    $res = smtpSendMail($pdo, $b['email'], $subject, $html);
                    if ($res === true) {
                        logHistory($pdo, 'agent', (int)$b['agent_id'], "📧 Lien de signature du bon {$b['numero']} envoyé à {$b['email']}", (int)$b['agent_id']);
                        flash('success', "Lien de signature envoyé à {$b['email']}.");
                    } else {
                        flash('error', "Échec de l'envoi : $res");
                    }
                }
                $pdo->commit();
                header('Location: index.php?page=pdf_bon&bon_id=' . $bonId); exit;
            }
        } elseif ($ent === 'request') {
            // ── Demandes de téléphone : qualification, circuit, traitement ──
            $reqId = (int)($d['request_id'] ?? 0);
            $rq = $pdo->prepare("SELECT * FROM requests WHERE id=?"); $rq->execute([$reqId]);
            $req = $rq->fetch();
            $backTo = 'index.php?page=requests' . ($reqId ? '&view=' . $reqId : '');
            if (!$req) {
                flash('error', 'Demande introuvable.');
                $backTo = 'index.php?page=requests';
            } elseif ($act === 'link_agent') {
                $aid = IV($d, 'agent_id');
                $pdo->prepare("UPDATE requests SET agent_id=? WHERE id=?")->execute([$aid, $reqId]);
                logHistory($pdo, 'request', $reqId, $aid ? "🔗 Demande {$req['numero']} liée à la fiche de " . getAgentName($pdo, $aid) : "Demande {$req['numero']} déliée du référentiel", $aid);
                flash('success', $aid ? 'Agent du référentiel lié à la demande — sa dotation actuelle est maintenant visible des valideurs.' : 'Agent délié.');
            } elseif ($act === 'launch') {
                if ($req['status'] !== 'a_qualifier') {
                    flash('error', 'Cette demande a déjà été lancée ou close.');
                } else {
                    // Circuit saisi/ajusté par la DSI : chaque étape = libellé + e-mail
                    $labels = (array)($d['step_label'] ?? []); $names = (array)($d['step_name'] ?? []); $emails = (array)($d['step_email'] ?? []);
                    $steps = [];
                    foreach ($labels as $i => $lbl) {
                        $lbl = trim(strip_tags((string)$lbl));
                        $nm  = trim(strip_tags((string)($names[$i] ?? '')));
                        $em  = trim((string)($emails[$i] ?? ''));
                        if ($lbl === '' && $nm === '' && $em === '') continue;   // ligne vide : ignorée
                        if ($lbl === '' || !filter_var($em, FILTER_VALIDATE_EMAIL)) { $steps = null; break; }
                        $steps[] = ['label' => $lbl, 'name' => $nm, 'email' => $em];
                    }
                    if ($steps === null || !$steps) {
                        flash('error', 'Circuit invalide : chaque étape doit avoir un libellé et une adresse e-mail valide (retirez les lignes inutiles).');
                    } else {
                        $pdo->prepare("DELETE FROM request_steps WHERE request_id=?")->execute([$reqId]);
                        $insStep = $pdo->prepare("INSERT INTO request_steps (request_id, ordre, label, validator_name, validator_email, token, expires_at) VALUES (?,?,?,?,?,?,?)");
                        $expires = date('Y-m-d H:i:s', strtotime('+120 days'));
                        foreach ($steps as $i => $s) {
                            $insStep->execute([$reqId, $i + 1, $s['label'], $s['name'] ?: null, $s['email'], bin2hex(random_bytes(32)), $expires]);
                        }
                        $pdo->prepare("UPDATE requests SET status='en_validation', current_step=1, launched_at=NOW() WHERE id=?")->execute([$reqId]);
                        logHistory($pdo, 'request', $reqId, "🚀 Circuit de validation lancé (" . count($steps) . " étape(s)) — demande {$req['numero']}", $req['agent_id'] ?: null);
                        $first = $pdo->prepare("SELECT * FROM request_steps WHERE request_id=? AND ordre=1"); $first->execute([$reqId]);
                        $res = requestSendStepEmail($pdo, $req, $first->fetch());
                        flash($res === true ? 'success' : 'error', $res === true
                            ? "Circuit lancé — e-mail envoyé au premier valideur ({$steps[0]['email']})."
                            : "Circuit lancé, mais l'e-mail au premier valideur n'a pas pu partir : $res — corrigez puis utilisez « Renvoyer l'e-mail ».");
                    }
                }
            } elseif ($act === 'resend') {
                if ($req['status'] !== 'en_validation') {
                    flash('error', "Cette demande n'est pas en cours de validation.");
                } else {
                    $cs = $pdo->prepare("SELECT * FROM request_steps WHERE request_id=? AND ordre=?");
                    $cs->execute([$reqId, (int)$req['current_step']]);
                    $step = $cs->fetch();
                    $res = $step ? requestSendStepEmail($pdo, $req, $step) : 'Étape courante introuvable.';
                    flash($res === true ? 'success' : 'error', $res === true
                        ? "E-mail renvoyé à {$step['validator_email']}."
                        : "Échec de l'envoi : $res");
                }
            } elseif ($act === 'refuse') {
                if (!in_array($req['status'], ['a_qualifier', 'en_validation'], true)) {
                    flash('error', 'Cette demande est déjà close.');
                } else {
                    $reason = S($d, 'reason', 'Refus DSI');
                    $pdo->prepare("UPDATE requests SET status='refusee', refusal_reason=?, closed_at=NOW(), current_step=0 WHERE id=?")
                        ->execute([mb_substr("Refus DSI : $reason", 0, 255), $reqId]);
                    logHistory($pdo, 'request', $reqId, "⛔ Demande {$req['numero']} refusée par la DSI — $reason", $req['agent_id'] ?: null);
                    // Le demandeur consulte le refus (et son motif) via son lien de suivi.
                    flash('success', 'Demande refusée. Le demandeur peut consulter le motif via son lien de suivi.');
                }
            } elseif ($act === 'cancel') {
                if (!in_array($req['status'], ['a_qualifier', 'en_validation'], true)) {
                    flash('error', 'Cette demande est déjà close.');
                } else {
                    $pdo->prepare("UPDATE requests SET status='annulee', closed_at=NOW(), current_step=0 WHERE id=?")->execute([$reqId]);
                    logHistory($pdo, 'request', $reqId, "🚫 Demande {$req['numero']} annulée par la DSI", $req['agent_id'] ?: null);
                    flash('success', 'Demande annulée.');
                }
            } elseif ($act === 'generate_bon') {
                if ($req['status'] !== 'validee') {
                    flash('error', 'Le bon de remise se génère une fois la demande validée.');
                } elseif (!$req['agent_id']) {
                    flash('error', 'Liez d\'abord la demande à un agent du référentiel.');
                } else {
                    $items = bonSnapshotItems($pdo, (int)$req['agent_id']);
                    if (empty($items['devices']) && empty($items['lines'])) {
                        flash('error', "Aucun équipement attribué à cet agent — attribuez d'abord un matériel et/ou une ligne (fiche agent), puis générez le bon.");
                    } else {
                        cancelPendingBons($pdo, (int)$req['agent_id'], "Bon généré depuis la demande {$req['numero']}");
                        $bonId = createBon($pdo, 'remise', (int)$req['agent_id'], $items);
                        $pdo->prepare("UPDATE requests SET bon_id=? WHERE id=?")->execute([$bonId, $reqId]);
                        $numero = $pdo->query("SELECT numero FROM bons WHERE id=$bonId")->fetchColumn();
                        logHistory($pdo, 'request', $reqId, "📄 Bon de remise $numero généré depuis la demande {$req['numero']}", (int)$req['agent_id']);
                        $pdo->commit();
                        header('Location: index.php?page=pdf_bon&bon_id=' . $bonId); exit;
                    }
                }
            } elseif ($act === 'deliver') {
                if ($req['status'] !== 'validee') {
                    flash('error', 'Seule une demande validée peut être marquée livrée.');
                } else {
                    $pdo->prepare("UPDATE requests SET status='livree', delivered_at=NOW() WHERE id=?")->execute([$reqId]);
                    logHistory($pdo, 'request', $reqId, "📦 Demande {$req['numero']} marquée livrée", $req['agent_id'] ?: null);
                    flash('success', 'Demande marquée comme livrée.');
                }
            }
            if ($pdo->inTransaction()) $pdo->commit();
            header('Location: ' . $backTo); exit;
        } elseif ($ent === 'req_circuit') {
            // ── Circuits de validation enregistrés (Paramètres → Demandes) ──
            // Modèles réutilisables proposés à la qualification d'une demande.
            if ($act === 'save') {
                $name = trim(strip_tags($d['circuit_name'] ?? ''));
                // Même parsing que le lancement d'un circuit sur une demande
                $labels = (array)($d['step_label'] ?? []); $names = (array)($d['step_name'] ?? []); $emails = (array)($d['step_email'] ?? []);
                $steps = [];
                foreach ($labels as $i => $lbl) {
                    $lbl = trim(strip_tags((string)$lbl));
                    $nm  = trim(strip_tags((string)($names[$i] ?? '')));
                    $em  = trim((string)($emails[$i] ?? ''));
                    if ($lbl === '' && $nm === '' && $em === '') continue;   // ligne vide : ignorée
                    if ($lbl === '' || !filter_var($em, FILTER_VALIDATE_EMAIL)) { $steps = null; break; }
                    $steps[] = ['label' => $lbl, 'name' => $nm, 'email' => $em];
                }
                if ($name === '') {
                    flash('error', 'Donnez un nom au circuit (ex : « Circuit standard », « Direction générale »).');
                } elseif ($steps === null || !$steps) {
                    flash('error', 'Circuit invalide : chaque étape doit avoir un libellé et une adresse e-mail valide (retirez les lignes inutiles).');
                } else {
                    $json = json_encode($steps, JSON_UNESCAPED_UNICODE);
                    if ($id) {
                        $pdo->prepare("UPDATE request_circuits SET name=?, steps=? WHERE id=?")->execute([$name, $json, $id]);
                        flash('success', "Circuit « $name » mis à jour (" . count($steps) . " étape(s)). Les demandes déjà lancées ne sont pas modifiées.");
                    } else {
                        $pdo->prepare("INSERT INTO request_circuits (name, steps) VALUES (?,?)")->execute([$name, $json]);
                        flash('success', "Circuit « $name » enregistré (" . count($steps) . " étape(s)) — il est maintenant proposé à la qualification des demandes.");
                    }
                }
            } elseif ($act === 'delete' && $id) {
                $pdo->prepare("DELETE FROM request_circuits WHERE id=?")->execute([$id]);
                flash('success', 'Circuit supprimé. Les demandes déjà lancées avec ce circuit ne sont pas modifiées.');
            }
            if ($pdo->inTransaction()) $pdo->commit();
            header('Location: index.php?page=refs&tab=settings&sub=requests'); exit;
        } elseif ($ent === 'backup') {
            // Sauvegarde / restauration — super-admin uniquement
            if (empty($_SESSION['is_admin'])) {
                flash('error', 'Accès refusé — réservé aux super-administrateurs.');
            } elseif ($act === 'run') {
                try {
                    $name = simcity_backup_to_disk($pdo);
                    flash('success', "Sauvegarde créée sur le serveur : $name");
                } catch (Throwable $e) {
                    flash('error', "Échec de la sauvegarde : " . $e->getMessage());
                }
            } elseif ($act === 'delete') {
                $f = basename($d['file'] ?? '');
                if (preg_match('/^simcity_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}\.sql$/', $f)) {
                    $p = simcity_backup_dir() . $f;
                    if (is_file($p) && @unlink($p)) flash('success', "Sauvegarde supprimée : $f");
                    else flash('error', "Suppression impossible (fichier absent ou droits).");
                } else {
                    flash('error', "Nom de fichier invalide.");
                }
            } elseif ($act === 'restore') {
                if (($d['confirm_word'] ?? '') !== 'RESTAURER') {
                    flash('error', 'Mot de confirmation incorrect (tapez RESTAURER).');
                } else {
                    // Source : une sauvegarde stockée OU un fichier .sql uploadé
                    $sql = null; $srcLabel = '';
                    $f = basename($d['file'] ?? '');
                    if ($f !== '' && preg_match('/^simcity_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}\.sql$/', $f)) {
                        $p = simcity_backup_dir() . $f;
                        if (is_file($p)) { $sql = file_get_contents($p); $srcLabel = $f; }
                    } elseif (isset($_FILES['sql_file']) && $_FILES['sql_file']['error'] === UPLOAD_ERR_OK) {
                        if ($_FILES['sql_file']['size'] > 50 * 1024 * 1024) {
                            flash('error', 'Fichier trop volumineux (max 50 Mo).');
                        } else {
                            $sql = file_get_contents($_FILES['sql_file']['tmp_name']);
                            $srcLabel = basename($_FILES['sql_file']['name']);
                        }
                    }
                    if ($sql === null || trim($sql) === '') {
                        flash('error', "Aucune sauvegarde valide fournie (sélectionnez un fichier stocké ou envoyez un .sql).");
                    } else {
                        // La restauration exécute du DDL (auto-commit MySQL) : on sort d'abord de la transaction
                        if ($pdo->inTransaction()) $pdo->commit();
                        try {
                            // Filet de sécurité : photographier l'état actuel avant d'écraser
                            $safety = simcity_backup_to_disk($pdo);
                            $n = simcity_restore_sql($pdo, $sql);
                            flash('success', "Restauration effectuée depuis « $srcLabel » ($n instruction(s)). Sauvegarde de sécurité créée avant écrasement : $safety. Reconnectez-vous si besoin.");
                        } catch (Throwable $e) {
                            flash('error', "Échec de la restauration : " . $e->getMessage() . " — la base peut être incohérente ; restaurez la sauvegarde de sécurité.");
                        }
                        header('Location: index.php?page=refs&tab=settings' . (isset($_GET['sub']) ? '&sub=' . preg_replace('/[^a-z]/', '', $_GET['sub']) : '')); exit;
                    }
                }
            }
        } elseif ($ent === 'wipe_data') {
            // Vider les données (tests) — super-admin uniquement. Conserve TOUJOURS
            // les paramètres (settings), les circuits de validation et les comptes
            // admin ; les référentiels (services, modèles…) sont conservés en option.
            if (empty($_SESSION['is_admin'])) {
                flash('error', 'Accès refusé — réservé aux super-administrateurs.');
            } elseif ($act !== 'run') {
                flash('error', 'Action inconnue.');
            } elseif (($d['confirm_wipe'] ?? '') !== 'VIDER') {
                flash('error', 'Tapez VIDER dans le champ de confirmation pour lancer l\'opération.');
            } else {
                // TRUNCATE = DDL auto-commit MySQL : on sort de la transaction globale
                if ($pdo->inTransaction()) $pdo->commit();
                try {
                    // Filet de sécurité : l'opération est irréversible
                    $safety = '';
                    try { $safety = simcity_backup_to_disk($pdo); } catch (Throwable $e) { $safety = ''; }
                    // Pièces jointes : supprimer aussi les fichiers du disque
                    foreach ($pdo->query("SELECT file_path FROM attachments")->fetchAll() as $af) {
                        if (!empty($af['file_path']) && is_file($af['file_path'])) @unlink($af['file_path']);
                    }
                    // Les factures opérateur décrivent le parc qu'on efface :
                    // les laisser en base ferait analyser au module Facturation
                    // des numéros qui n'existent plus, et l'alerte « lignes
                    // facturées sans consommation » du tableau de bord
                    // continuerait de compter des lignes fantômes.
                    $tables = ['request_steps', 'requests', 'bons', 'signatures', 'sign_tokens', 'sim_history',
                               'attachments', 'history_logs', 'login_attempts', 'mobile_lines', 'devices', 'agents',
                               'invoice_lines', 'invoice_devices', 'invoices'];
                    $keepRefs = !empty($d['keep_refs']);
                    if (!$keepRefs) {
                        $tables = array_merge($tables, ['billing_accounts', 'plan_types', 'operators', 'models', 'services']);
                    }
                    $pdo->exec("SET FOREIGN_KEY_CHECKS = 0");
                    foreach ($tables as $t) $pdo->exec("TRUNCATE TABLE `$t`");
                    $pdo->exec("SET FOREIGN_KEY_CHECKS = 1");
                    // Les PDF archivés suivent leurs lignes en base.
                    $nbPdf = simcity_purge_invoice_pdfs();
                    // Journalisé APRÈS la purge : la trace de l'opération survit
                    logHistory($pdo, 'admin', (int)$_SESSION['user_id'], "🧹 Données vidées (tests) — référentiels " . ($keepRefs ? 'conservés' : 'compris')
                        . ($nbPdf ? ", $nbPdf PDF de facture supprimé(s)" : ''));
                    flash('success', 'Données vidées' . ($keepRefs ? ' — référentiels conservés' : ' (référentiels compris)')
                        . '. Paramètres, circuits de validation et comptes admin intacts.'
                        . ($safety !== '' ? " Sauvegarde de sécurité : $safety." : ''));
                } catch (Throwable $e) {
                    flash('error', 'Échec du vidage : ' . $e->getMessage());
                }
                header('Location: index.php?page=refs&tab=settings&sub=maintenance'); exit;
            }
        } elseif ($ent === 'import') {
            // Importation CSV — super-admin uniquement (l'outil peut purger la base)
            // Déroulé en deux temps : « preview » analyse le fichier et propose
            // un contrôle des utilisateurs (correspondances / créations), puis
            // « run » écrit en base avec les associations décidées.
            if (empty($_SESSION['is_admin'])) {
                flash('error', 'Accès refusé — réservé aux super-administrateurs.');
            } elseif ($act === 'cancel') {
                if (!empty($_SESSION['import_pending']['file'])) @unlink($_SESSION['import_pending']['file']);
                unset($_SESSION['import_pending']);
                flash('success', 'Importation annulée — aucune donnée modifiée.');
                header('Location: index.php?page=refs&tab=settings&sub=maintenance'); exit;
            } elseif ($act === 'preview') {
                $purge = !empty($d['truncate']);
                $err   = simcity_import_validate($_FILES['file_data'] ?? []);
                if ($purge && ($d['confirm_purge'] ?? '') !== 'PURGER') {
                    flash('error', 'Tapez PURGER dans le champ de confirmation pour activer la purge.');
                } elseif ($err !== '') {
                    flash('error', $err);
                } else {
                    // Ménage : fichiers d'analyse abandonnés (session expirée,
                    // onglet fermé) — ils contiennent des données nominatives.
                    foreach (glob(sys_get_temp_dir() . '/simcity_import_*') ?: [] as $old)
                        if (is_file($old) && @filemtime($old) < time() - 86400) @unlink($old);
                    // Le fichier téléversé est mis de côté le temps du contrôle.
                    if (!empty($_SESSION['import_pending']['file'])) @unlink($_SESSION['import_pending']['file']);
                    $tmp = tempnam(sys_get_temp_dir(), 'simcity_import_');
                    if (!@move_uploaded_file($_FILES['file_data']['tmp_name'], $tmp) || (int)@filesize($tmp) === 0) {
                        // Sans ce contrôle, un déplacement raté donnerait un
                        // fichier vide : écran de contrôle à zéro, et une purge
                        // cochée viderait la base pour importer... rien.
                        @unlink($tmp);
                        flash('error', "Le fichier n'a pas pu être mis de côté (espace disque / droits) — importation abandonnée.");
                    } else {
                        $_SESSION['import_pending'] = ['file' => $tmp, 'name' => (string)($_FILES['file_data']['name'] ?? 'import.csv'),
                                                       'purge' => $purge, 'sha1' => (string)sha1_file($tmp)];
                        header('Location: index.php?page=refs&tab=settings&sub=maintenance#import-review'); exit;
                    }
                }
            } elseif ($act !== 'run') {
                flash('error', 'Action inconnue.');
            } else {
                $pend = $_SESSION['import_pending'] ?? null;
                if (!$pend || !is_file($pend['file'])) {
                    flash('error', "Fichier d'import introuvable — relancez l'analyse du CSV.");
                } elseif (($d['pend_sha1'] ?? '') !== ($pend['sha1'] ?? '')) {
                    // L'écran de contrôle d'où vient ce POST décrivait un AUTRE
                    // fichier (nouvelle analyse lancée dans un second onglet) :
                    // appliquer ses cases cochées à ce fichier-ci serait faux.
                    flash('error', "Le fichier analysé a changé depuis cet écran de contrôle — relancez l'analyse.");
                } else {
                    $purge = !empty($pend['purge']);
                    // Associations décidées à l'étape de contrôle (clé « nom|prénom »
                    // en minuscules => id d'agent existant). Sans objet après purge.
                    $agentMap = [];
                    if (!$purge) {
                        foreach ((array)($d['agent_map'] ?? []) as $k => $v) {
                            $v = (int)$v;
                            if ($v > 0) $agentMap[mb_strtolower((string)$k)] = $v;
                        }
                    }
                    // L'import écrit beaucoup et la purge fait du DDL (auto-commit
                    // MySQL) : on sort de la transaction globale, comme la restauration.
                    if ($pdo->inTransaction()) $pdo->commit();
                    try {
                        // Filet de sécurité avant une purge : l'opération est
                        // irréversible et l'écran PROMET cette sauvegarde — si
                        // elle échoue, on refuse de purger plutôt que de
                        // continuer en silence sans filet.
                        $safety = '';
                        if ($purge) {
                            try { $safety = simcity_backup_to_disk($pdo); }
                            catch (Throwable $e) {
                                flash('error', "Purge annulée : la sauvegarde de sécurité n'a pas pu être créée ("
                                    . $e->getMessage() . "). Aucune donnée supprimée.");
                                header('Location: index.php?page=refs&tab=settings&sub=maintenance'); exit;
                            }
                            simcity_import_purge($pdo);
                        }
                        $st = simcity_import_csv($pdo, $pend['file'], $agentMap);
                        $resume = "{$st['lines']} ligne(s), {$st['devices']} matériel(s), {$st['agents']} utilisateur(s), "
                                . "{$st['services']} service(s), {$st['models']} modèle(s), {$st['plans']} forfait(s), "
                                . "{$st['operators']} opérateur(s), {$st['billings']} compte(s) de facturation";
                        if (count($agentMap)) $resume .= ", " . count($agentMap) . " rapprochement(s) d'utilisateur";
                        // Journal : écrit APRÈS l'import (la purge recrée
                        // history_logs) — jusqu'ici l'import CSV était le seul
                        // import à ne laisser aucune trace au journal.
                        logHistory($pdo, 'admin', (int)$_SESSION['user_id'],
                            ($purge ? "Purge de la base puis import CSV ({$pend['name']}) : " : "Import CSV ({$pend['name']}) : ") . $resume);
                        $prefix = $purge
                            ? 'Base purgée' . ($safety !== '' ? " (sauvegarde de sécurité : $safety)" : '') . ', puis import terminé — '
                            : 'Import terminé — ';
                        flash('success', $prefix . $resume . '.');
                    } catch (Throwable $e) {
                        $detail = (defined('APP_DEBUG') && APP_DEBUG) ? ' — ' . $e->getMessage() : '';
                        flash('error', "L'importation a échoué$detail. Les lignes déjà traitées ont été conservées.");
                    }
                    @unlink($pend['file']); unset($_SESSION['import_pending']);
                    header('Location: index.php?page=refs&tab=settings&sub=maintenance'); exit;
                }
            }
        } elseif ($ent === 'secret_purge') {
            // Effacement d'un secret stocké dans « settings ». Une variable
            // d'environnement PRIME sur la base mais ne l'efface pas : la
            // valeur historique reste en table et dans toutes les sauvegardes
            // SQL déjà produites. Ce bouton la retire pour de bon.
            if (empty($_SESSION['is_admin'])) {
                flash('error', 'Accès refusé — réservé aux super-administrateurs.');
            } else {
                $purgeable = ['smtp_pass' => 'mot de passe SMTP', 'ldap_bind_password' => 'mot de passe du compte de service AD'];
                $key = (string)($d['setting_key'] ?? '');
                if (!isset($purgeable[$key])) {
                    flash('error', 'Secret inconnu.');
                } elseif (trim((string)getSetting($pdo, $key, '')) === '') {
                    flash('success', "Aucune valeur stockée pour le {$purgeable[$key]} — rien à effacer.");
                } else {
                    $pdo->prepare("UPDATE settings SET setting_value='' WHERE setting_key=?")->execute([$key]);
                    $env = SMTP_ENV_KEYS[$key] ?? (LDAP_KEYS[$key] ?? '');
                    $fromEnv = $env !== '' && getenv($env) !== false && getenv($env) !== '';
                    logHistory($pdo, 'admin', (int)$_SESSION['user_id'],
                        "Effacement du {$purgeable[$key]} stocké en base" . ($fromEnv ? " (désormais fourni par $env)" : ''));
                    flash('success', "Le {$purgeable[$key]} a été effacé de la base."
                        . ($fromEnv ? " Il continue d'être lu depuis la variable d'environnement $env."
                                    : " L'authentification correspondante est désormais sans mot de passe."));
                }
            }
        } elseif ($ent === 'parc') {
            // Import depuis SFR — export de parc (.xlsx). Même mécanique en deux
            // temps que l'import CSV : « preview » met le fichier de côté et
            // affiche le contrôle, « run » n'écrit que les postes cochés.
            if (empty($_SESSION['is_admin'])) {
                flash('error', 'Accès refusé — réservé aux super-administrateurs.');
            } elseif ($act === 'cancel') {
                if (!empty($_SESSION['parc_pending']['file'])) @unlink($_SESSION['parc_pending']['file']);
                unset($_SESSION['parc_pending']);
                flash('success', 'Contrôle abandonné — aucune donnée modifiée.');
                header('Location: index.php?page=refs&tab=settings&sub=maintenance'); exit;
            } elseif ($act === 'preview') {
                $err = simcity_parc_validate($_FILES['file_data'] ?? []);
                if ($err !== '') { flash('error', $err); }
                else {
                    // Ménage : fichiers d'analyse abandonnés (ils contiennent
                    // des PIN/PUK en clair — ne pas les laisser traîner).
                    foreach (glob(sys_get_temp_dir() . '/simcity_parc_*') ?: [] as $old)
                        if (is_file($old) && @filemtime($old) < time() - 86400) @unlink($old);
                    if (!empty($_SESSION['parc_pending']['file'])) @unlink($_SESSION['parc_pending']['file']);
                    $tmp = tempnam(sys_get_temp_dir(), 'simcity_parc_');
                    if (!@move_uploaded_file($_FILES['file_data']['tmp_name'], $tmp) || (int)@filesize($tmp) === 0) {
                        @unlink($tmp);
                        flash('error', "Le fichier n'a pas pu être mis de côté (espace disque / droits) — contrôle abandonné.");
                    } else {
                    try {
                        $probe = simcity_parc_parse($tmp);          // valide le format tout de suite
                        $_SESSION['parc_pending'] = ['file' => $tmp,
                            'name' => (string)($_FILES['file_data']['name'] ?? 'parc.xlsx'),
                            'nb'   => count($probe['records']),
                            'sha1' => (string)sha1_file($tmp)];
                        if (!empty($probe['truncated'])) {
                            flash('error', "Attention : classeur tronqué à 20 000 lignes — les lignes au-delà passeraient pour « absentes du fichier ». Scindez l'export avant d'appliquer quoi que ce soit.");
                        }
                        header('Location: index.php?page=refs&tab=settings&sub=maintenance#parc-review'); exit;
                    } catch (Throwable $e) {
                        @unlink($tmp);
                        flash('error', "Lecture impossible : " . $e->getMessage());
                    }
                    }
                }
            } elseif ($act === 'run') {
                $pend = $_SESSION['parc_pending'] ?? null;
                if (!$pend || !is_file($pend['file'])) {
                    flash('error', "Fichier introuvable — relancez l'analyse de l'export.");
                } elseif (($d['pend_sha1'] ?? '') !== ($pend['sha1'] ?? '')) {
                    // Nouvelle analyse lancée dans un autre onglet : les postes
                    // cochés ici décrivent un autre fichier que celui en session.
                    flash('error', "Le fichier analysé a changé depuis cet écran de contrôle — relancez l'analyse.");
                } else {
                    $opts = ['billing' => !empty($d['apply_billing']), 'plan' => !empty($d['apply_plan']),
                             'status'  => !empty($d['apply_status']),  'iccid' => !empty($d['apply_iccid']),
                             'codes'   => !empty($d['apply_codes']),   'create' => !empty($d['apply_create'])];
                    if (!array_filter($opts)) {
                        flash('error', "Aucun poste coché — rien à mettre à jour. Le contrôle reste consultable.");
                    } else {
                        try {
                            $parsed = simcity_parc_parse($pend['file']);
                            $done = simcity_parc_apply($pdo, $parsed['records'], $opts);
                            $resume = [];
                            if ($done['created'])  $resume[] = "{$done['created']} ligne(s) créée(s)";
                            if ($done['billing'])  $resume[] = "{$done['billing']} compte(s) de facturation rattaché(s)";
                            if ($done['plan'])     $resume[] = "{$done['plan']} forfait(s) corrigé(s)";
                            if ($done['status'])   $resume[] = "{$done['status']} statut(s) aligné(s)";
                            if ($done['iccid'])    $resume[] = "{$done['iccid']} ICCID complété(s)";
                            if ($done['codes'])    $resume[] = "{$done['codes']} ligne(s) avec codes SIM mis à jour";
                            if ($done['accounts']) $resume[] = "{$done['accounts']} compte(s) créé(s) au référentiel";
                            if ($done['plans'])    $resume[] = "{$done['plans']} forfait(s) créé(s) au référentiel";
                            $txt = $resume ? implode(', ', $resume) : 'aucune différence à appliquer';
                            logHistory($pdo, 'admin', (int)$_SESSION['user_id'], "Import depuis SFR ({$pend['name']}) : $txt");
                            // Le bloc POST est encapsulé dans une transaction
                            // commitée tout à la fin ; comme on sort par un
                            // redirect, c'est ici qu'il faut valider, sinon PDO
                            // annule tout à la destruction du script.
                            if ($pdo->inTransaction()) $pdo->commit();
                            flash('success', "Mise à jour depuis l'export SFR — $txt.");
                        } catch (Throwable $e) {
                            if ($pdo->inTransaction()) $pdo->rollBack();
                            $detail = (defined('APP_DEBUG') && APP_DEBUG) ? ' — ' . $e->getMessage() : '';
                            flash('error', "La mise à jour a échoué$detail.");
                        }
                        @unlink($pend['file']); unset($_SESSION['parc_pending']);
                        header('Location: index.php?page=refs&tab=settings&sub=maintenance'); exit;
                    }
                }
            } else {
                flash('error', 'Action inconnue.');
            }
        } elseif ($ent === 'invoice') {
            // Module Facturation / Contrôle — factures opérateur (PDF)
            // Réservé aux super-admins comme la suppression, la ré-analyse et
            // les seuils : une facture mensuelle apporte en base la liste
            // nominative complète du parc et de ses consommations.
            if ($act === 'upload' && empty($_SESSION['is_admin'])) {
                flash('error', 'Réservé aux super-administrateurs.');
            } elseif ($act === 'upload') {
                $files = $_FILES['file_data'] ?? null;
                if (!$files || !isset($files['name'])) {
                    flash('error', 'Aucun fichier reçu.');
                } else {
                    // Normalise mono / multi-fichiers en tableau uniforme.
                    $list = is_array($files['name'])
                        ? array_map(fn($i) => ['name'=>$files['name'][$i], 'type'=>$files['type'][$i], 'tmp_name'=>$files['tmp_name'][$i], 'error'=>$files['error'][$i], 'size'=>$files['size'][$i]], array_keys($files['name']))
                        : [$files];
                    $ok = $dup = $err = 0; $msgs = []; $author = $_SESSION['username'] ?? 'admin';
                    // Compte rendu fichier par fichier, affiché après l'import :
                    // un dépôt groupé mélange nouveautés, doublons et erreurs, et
                    // le simple décompte ne dit pas lesquels.
                    $report = [];
                    foreach ($list as $one) {
                        $v = simcity_invoice_validate($one);
                        if ($v !== '') {
                            $err++; $msgs[] = $one['name'] . ' : ' . $v;
                            $report[] = ['file' => (string)$one['name'], 'status' => 'error', 'message' => $v];
                            continue;
                        }
                        // Savepoint par fichier : tout le POST partage une seule
                        // transaction, or l'échec d'un PDF est rattrapé ici sans
                        // faire échouer le lot. Sans savepoint, une facture dont
                        // l'insertion casse à mi-parcours resterait en base,
                        // partielle, et serait commitée avec le reste — avec un
                        // « déjà présente » au re-dépôt.
                        $pdo->exec("SAVEPOINT sp_invoice_file");
                        try {
                            $res = simcity_invoice_import($pdo, $one['tmp_name'], (string)$one['name'], $author);
                            if ($res['status'] === 'ok') $ok++;
                            elseif ($res['status'] === 'duplicate') $dup++;
                            else { $err++; $msgs[] = $one['name'] . ' : ' . ($res['message'] ?? 'erreur'); }
                            if ($res['status'] !== 'ok') $pdo->exec("ROLLBACK TO SAVEPOINT sp_invoice_file");
                            $report[] = $res;
                        } catch (Throwable $e) {
                            $pdo->exec("ROLLBACK TO SAVEPOINT sp_invoice_file");
                            $err++; $msgs[] = $one['name'] . ' : ' . $e->getMessage();
                            $report[] = ['file' => (string)$one['name'], 'status' => 'error', 'message' => $e->getMessage()];
                        }
                    }
                    // Détail des doublons : le mois et le n° déjà en base, pour
                    // que l'opérateur sache quoi aller chercher sur le portail.
                    foreach ($report as &$rp) {
                        if (($rp['status'] ?? '') !== 'duplicate' || empty($rp['invoice_number'])) continue;
                        $stD = $pdo->prepare("SELECT month_key, imported_at, imported_by FROM invoices WHERE invoice_number=?");
                        $stD->execute([$rp['invoice_number']]);
                        $rp['existing'] = $stD->fetch() ?: null;
                    }
                    unset($rp);
                    $_SESSION['invoice_import_report'] = $report;

                    $sum = "$ok facture(s) importée(s)";
                    if ($dup) $sum .= ", $dup déjà présente(s) — ignorée(s)";
                    if ($err) $sum .= ", $err en erreur";
                    if ($ok) logHistory($pdo, 'invoice', 0, "Import de facture(s) opérateur : $sum");
                    flash($ok || !$err ? 'success' : 'error', $sum . ($msgs ? ' — ' . implode(' · ', array_slice($msgs, 0, 4)) : '') . '.');
                }
            } elseif ($act === 'delete') {
                if (empty($_SESSION['is_admin'])) { flash('error', 'Réservé aux super-administrateurs.'); }
                else {
                    $st = $pdo->prepare("SELECT * FROM invoices WHERE id=?"); $st->execute([$id]); $inv = $st->fetch();
                    if ($inv) {
                        if (!empty($inv['pdf_path']) && is_file(__DIR__ . '/' . $inv['pdf_path'])) @unlink(__DIR__ . '/' . $inv['pdf_path']);
                        $pdo->prepare("DELETE FROM invoices WHERE id=?")->execute([$id]); // cascade sur le détail
                        logHistory($pdo, 'invoice', (int)$id, "Suppression de la facture {$inv['invoice_number']}"
                            . " ({$inv['month_key']}, " . (int)$inv['nb_lines'] . " lignes, PDF justificatif supprimé)");
                        flash('success', "Facture {$inv['invoice_number']} supprimée (avec son détail).");
                    }
                }
            } elseif ($act === 'reparse') {
                // Ré-analyse toutes les factures depuis les PDF archivés avec
                // le parseur courant (après une mise à jour de celui-ci).
                if (empty($_SESSION['is_admin'])) { flash('error', 'Réservé aux super-administrateurs.'); }
                else {
                    $ok = 0; $errs = [];
                    foreach ($pdo->query("SELECT * FROM invoices") as $inv) {
                        $e = simcity_invoice_reparse($pdo, $inv);
                        if ($e === '') $ok++; else $errs[] = $inv['invoice_number'] . " : $e";
                    }
                    $msg = "$ok facture(s) ré-analysée(s) avec le parseur courant";
                    if ($errs) $msg .= ' — ' . count($errs) . ' échec(s) : ' . h(implode(' · ', array_slice($errs, 0, 3)));
                    logHistory($pdo, 'invoice', 0, "Ré-analyse des factures depuis les PDF archivés : $ok reconstruite(s), " . count($errs) . " échec(s)");
                    flash($errs && !$ok ? 'error' : 'success', $msg . '.');
                }
            } elseif ($act === 'thresholds') {
                if (empty($_SESSION['is_admin'])) { flash('error', 'Réservé aux super-administrateurs.'); }
                else {
                    foreach (['inv_alert_var_pct','inv_alert_var_min_eur','inv_alert_zero_months','inv_alert_hf_eur','inv_alert_intl_eur','inv_alert_surtaxe_eur','inv_alert_remise_pct'] as $k) {
                        if (isset($d[$k])) {
                            $v = (string)max(0, (float)str_replace(',', '.', (string)$d[$k]));
                            $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key=?")->execute([$v, $k]);
                        }
                    }
                    flash('success', "Seuils d'alerte enregistrés.");
                }
            }
        } elseif ($ent === 'db_reset') {
            // Réinitialisation complète — super-admin uniquement
            if (empty($_SESSION['is_admin'])) { flash('error', 'Accès refusé.'); }
            elseif (($d['confirm_word'] ?? '') !== 'SUPPRIMER') { flash('error', 'Mot de confirmation incorrect.'); }
            else {
                // Le DROP TABLE (DDL) commite implicitement : on sort proprement de la transaction
                if ($pdo->inTransaction()) $pdo->commit();
                // Même mécanique que la purge de l'import CSV : sauvegarde de
                // sécurité, purge (comptes admin épargnés) puis recréation du
                // schéma — pas de détour par install.php, l'opérateur reste
                // connecté sur une base vide prête à l'emploi.
                $safety = '';
                try { $safety = simcity_backup_to_disk($pdo); } catch (Throwable $e) { $safety = ''; }
                simcity_import_purge($pdo);
                logHistory($pdo, 'admin', (int)$_SESSION['user_id'], "Réinitialisation complète de la base");
                flash('success', 'Base réinitialisée' . ($safety !== '' ? " (sauvegarde de sécurité : $safety)" : '') . ' — structure recréée, comptes d\'administration conservés.');
                header('Location: index.php?page=refs&tab=settings&sub=maintenance'); exit;
            }
        } elseif ($ent === 'service') {
            // chef/dga : valideurs par défaut du circuit des demandes de téléphone
            if ($act === 'add') $pdo->prepare("INSERT INTO services(name,direction,notes,chef_name,chef_email,dga_name,dga_email)VALUES(?,?,?,?,?,?,?)")->execute([S($d,'name'),S($d,'direction'),S($d,'notes'),NV($d,'chef_name'),fmtEmail(NV($d,'chef_email')),NV($d,'dga_name'),fmtEmail(NV($d,'dga_email'))]);
            elseif ($act === 'edit') $pdo->prepare("UPDATE services SET name=?,direction=?,notes=?,chef_name=?,chef_email=?,dga_name=?,dga_email=? WHERE id=?")->execute([S($d,'name'),S($d,'direction'),S($d,'notes'),NV($d,'chef_name'),fmtEmail(NV($d,'chef_email')),NV($d,'dga_name'),fmtEmail(NV($d,'dga_email')),$id]);
        } elseif ($ent === 'model') {
            if ($act === 'add') $pdo->prepare("INSERT INTO models(brand,name,category)VALUES(?,?,?)")->execute([S($d,'brand'),S($d,'name'),S($d,'category')]);
            elseif ($act === 'edit') $pdo->prepare("UPDATE models SET brand=?,name=?,category=? WHERE id=?")->execute([S($d,'brand'),S($d,'name'),S($d,'category'),$id]);
        } elseif ($ent === 'operator') {
            if ($act === 'add') $pdo->prepare("INSERT INTO operators(name,website,notes)VALUES(?,?,?)")->execute([S($d,'name'),NV($d,'website'),S($d,'notes')]);
            elseif ($act === 'edit') $pdo->prepare("UPDATE operators SET name=?,website=?,notes=? WHERE id=?")->execute([S($d,'name'),NV($d,'website'),S($d,'notes'),$id]);
        } elseif ($ent === 'plan') {
            $opId = IV($d,'operator_id');
            if ($act === 'add') $pdo->prepare("INSERT INTO plan_types(name,data_limit,notes,operator_id)VALUES(?,?,?,?)")->execute([S($d,'name'),S($d,'data_limit'),S($d,'notes'),$opId]);
            elseif ($act === 'edit') $pdo->prepare("UPDATE plan_types SET name=?,data_limit=?,notes=?,operator_id=? WHERE id=?")->execute([S($d,'name'),S($d,'data_limit'),S($d,'notes'),$opId,$id]);
        } elseif ($ent === 'billing') {
            if ($act === 'add') $pdo->prepare("INSERT INTO billing_accounts(account_number,name,notes)VALUES(?,?,?)")->execute([S($d,'account_number'),S($d,'name'),S($d,'notes')]);
            elseif ($act === 'edit') $pdo->prepare("UPDATE billing_accounts SET account_number=?,name=?,notes=? WHERE id=?")->execute([S($d,'account_number'),S($d,'name'),S($d,'notes'),$id]);
        } elseif ($ent === 'ldap_test') {
            // Test de la connexion LDAP/AD (réservé aux super-admins)
            if (empty($_SESSION['is_admin'])) {
                flash('error', "Action réservée aux super-administrateurs.");
            } else {
                [$ok, $msg] = ldap_test_connection();
                flash($ok ? 'success' : 'error', ($ok ? '🔌 ' : '') . $msg);
            }
        } elseif ($ent === 'mail_tpl') {
            // Personnalisation des gabarits d'e-mails : un champ vide efface
            // la surcharge (retour au gabarit par défaut).
            $up = $pdo->prepare("INSERT INTO settings (setting_key, setting_value, label) VALUES (?,?,?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)");
            foreach (mailTemplates() as $tk => $def) {
                foreach (['subject' => 'Sujet', 'title' => 'Titre', 'body' => 'Corps'] as $part => $lbl) {
                    $val = trim((string)($d["tpl_{$part}"][$tk] ?? ''));
                    // Contenu identique au gabarit par défaut -> pas de surcharge :
                    // le gabarit continuera de suivre les évolutions de l'application.
                    if ($val === trim($def[$part])) $val = '';
                    $up->execute(["mail_tpl_{$tk}_{$part}", $val, "$lbl e-mail « {$tk} » (vide = défaut)"]);
                }
                // Activation de l'envoi (le gabarit « test » n'est pas désactivable)
                if ($tk !== 'test') {
                    $up->execute(["mail_tpl_{$tk}_enabled", !empty($d['tpl_enabled'][$tk]) ? '1' : '0', "Envoi de l'e-mail « {$tk} » activé (0/1)"]);
                }
            }
            // Couleurs du bandeau (validées : hex 6 chiffres, sinon ignorées)
            $c1 = trim($d['banner_color'] ?? ''); $c2 = trim($d['banner_color2'] ?? '');
            if (preg_match('/^#[0-9a-fA-F]{6}$/', $c1)) $up->execute(['mail_banner_color', $c1, 'Couleur du bandeau des e-mails']);
            if (preg_match('/^#[0-9a-fA-F]{6}$/', $c2)) $up->execute(['mail_banner_color2', $c2, 'Seconde couleur du bandeau (dégradé)']);
            $up->execute(['mail_banner_gradient', !empty($d['banner_gradient']) ? '1' : '0', 'Bandeau des e-mails en dégradé (0/1)']);
            logHistory($pdo, 'admin', (int)$_SESSION['user_id'], "Modification des gabarits d'e-mails");
            flash('success', 'Gabarits d\'e-mails enregistrés.');
        } elseif ($ent === 'smtp_test') {
            // Envoi d'un e-mail de test avec la configuration SMTP enregistrée
            $to = fmtEmail(trim($d['test_email'] ?? ''));
            if ($to === '' || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
                flash('error', "Renseignez une adresse e-mail de destination valide pour le test.");
            } else {
                // Envoie les gabarits cochés avec des données fictives [DÉMO] :
                // on juge le rendu réel (et les personnalisations) dans le
                // client de messagerie, pas un aperçu.
                $demoVars = mailDemoVars($pdo);
                $keys = array_values(array_intersect(array_keys($demoVars), (array)($d['tpl'] ?? [])));
                if (!$keys) {
                    flash('error', "Cochez au moins un e-mail à tester.");
                } else {
                    $sent = 0; $err = null;
                    foreach ($keys as $key) {
                        [$subject, $html] = mailRender($pdo, $key, $demoVars[$key]);
                        $res = smtpSendMail($pdo, $to, '[DÉMO] ' . $subject, $html);
                        if ($res === true) $sent++; elseif ($err === null) $err = $res;
                    }
                    if ($sent === count($keys)) {
                        flash('success', "📧 $sent e-mail(s) de démonstration envoyé(s) à $to — vérifiez la boîte de réception (et les indésirables).");
                    } elseif ($sent > 0) {
                        flash('error', "Envoi partiel : $sent/" . count($keys) . " e-mails partis. Première erreur : $err");
                    } else {
                        flash('error', "Échec de l'envoi : $err");
                    }
                }
            }
        } elseif ($ent === 'admin') {
            $isSuper = !empty($_SESSION['is_admin']);
            $selfId  = (int)$_SESSION['user_id'];
            // La gestion d'un compte AUTRE que le sien (création, modification d'un
            // tiers, activation, suppression) est réservée aux super-administrateurs.
            // Un admin simple ne peut modifier que son propre profil (mot de passe, e-mail…).
            $managingOther = ($act !== 'edit') || ($id !== $selfId);
            // État courant de la cible (pour protéger le dernier super-admin)
            $targetIsSuper = ($act !== 'add' && $id) ? (int)$pdo->query("SELECT is_admin FROM users WHERE id=$id")->fetchColumn() === 1 : false;
            $superCount    = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE is_admin=1")->fetchColumn();
            $isAdminVal = $isSuper ? (!empty($d['is_admin']) ? 1 : 0) : null;

            if ($managingOther && !$isSuper) {
                flash('error', "Action réservée aux super-administrateurs.");
            } elseif ($act === 'add') {
                $pdo->prepare("INSERT INTO users(username, password, first_name, last_name, email, is_admin) VALUES(?,?,?,?,?,?)")->execute([S($d,'username'), password_hash(S($d,'password'), PASSWORD_DEFAULT), fmtFirstName(NV($d,'first_name')), fmtLastName(NV($d,'last_name')), fmtEmail(NV($d,'email')), $isAdminVal ?? 0]);
                logHistory($pdo, 'admin', $pdo->lastInsertId(), "Création de l'administrateur ".S($d,'username'));
                flash('success', 'Compte créé.');
            } elseif ($act === 'edit') {
                // Empêcher qu'on retire le dernier super-admin en le rétrogradant
                if ($targetIsSuper && $isAdminVal === 0 && $superCount <= 1) {
                    flash('error', 'Impossible : ce compte est le dernier super-administrateur.');
                } else {
                    // Compte provisionné depuis l'AD : pas de mot de passe local
                    // (il s'authentifie toujours via LDAP — on ignore le champ).
                    $targetSource = $pdo->prepare("SELECT IFNULL(auth_source,'local') FROM users WHERE id=?");
                    $targetSource->execute([$id]);
                    if ($targetSource->fetchColumn() === 'ldap') $d['password'] = '';
                    $isAdminSet = $isAdminVal !== null ? ', is_admin=?' : '';
                    $params = [S($d,'username'), fmtFirstName(NV($d,'first_name')), fmtLastName(NV($d,'last_name')), fmtEmail(NV($d,'email'))];
                    if (!empty($d['password'])) {
                        $sql = "UPDATE users SET username=?, password=?, first_name=?, last_name=?, email=?$isAdminSet WHERE id=?";
                        array_splice($params, 1, 0, [password_hash(S($d,'password'), PASSWORD_DEFAULT)]);
                    } else {
                        $sql = "UPDATE users SET username=?, first_name=?, last_name=?, email=?$isAdminSet WHERE id=?";
                    }
                    if ($isAdminVal !== null) $params[] = $isAdminVal;
                    $params[] = $id;
                    $pdo->prepare($sql)->execute($params);
                    logHistory($pdo, 'admin', $id, "Modification du compte administrateur ".S($d,'username'));
                    flash('success', 'Compte mis à jour.');
                }
            } elseif ($act === 'disable') {
                // Empêcher la désactivation de son propre compte
                if ($id === $selfId) {
                    flash('error', 'Vous ne pouvez pas désactiver votre propre compte.');
                } elseif ($targetIsSuper && $superCount <= 1) {
                    flash('error', 'Impossible : ce compte est le dernier super-administrateur.');
                } else {
                    // Empêcher de désactiver le dernier compte actif
                    $activeCount = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE active=1")->fetchColumn();
                    if ($activeCount <= 1) {
                        flash('error', 'Impossible : ce compte est le dernier compte actif.');
                    } else {
                        $row = $pdo->prepare("SELECT username FROM users WHERE id=?"); $row->execute([$id]); $row = $row->fetch();
                        $pdo->prepare("UPDATE users SET active=0 WHERE id=?")->execute([$id]);
                        logHistory($pdo, 'admin', $id, "Compte désactivé : ".($row['username']??''));
                        flash('success', 'Compte désactivé.');
                    }
                }
            } elseif ($act === 'enable') {
                $row = $pdo->prepare("SELECT username FROM users WHERE id=?"); $row->execute([$id]); $row = $row->fetch();
                $pdo->prepare("UPDATE users SET active=1 WHERE id=?")->execute([$id]);
                logHistory($pdo, 'admin', $id, "Compte réactivé : ".($row['username']??''));
                flash('success', 'Compte réactivé.');
            } elseif ($act === 'delete') {
                // Empêcher la suppression de son propre compte
                if ($id === $selfId) {
                    flash('error', 'Vous ne pouvez pas supprimer votre propre compte.');
                } elseif ($targetIsSuper && $superCount <= 1) {
                    flash('error', 'Impossible : ce compte est le dernier super-administrateur.');
                } else {
                    // Empêcher la suppression du dernier compte actif
                    $activeCount = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE active=1")->fetchColumn();
                    $targetActive = (int)$pdo->query("SELECT active FROM users WHERE id=$id")->fetchColumn();
                    if ($targetActive && $activeCount <= 1) {
                        flash('error', 'Impossible : ce compte est le dernier compte actif.');
                    } else {
                        $pdo->prepare("DELETE FROM users WHERE id=?")->execute([$id]);
                        flash('success', 'Compte supprimé.');
                    }
                }
            }
        } elseif ($ent === 'agent') {
            if ($act === 'add') {
                $pdo->prepare("INSERT INTO agents(first_name,last_name,fonction,email,service_id)VALUES(?,?,?,?,?)")->execute([fmtFirstName(S($d,'first_name')),fmtLastName(S($d,'last_name')),NV($d,'fonction'),fmtEmail(NV($d,'email')),IV($d,'service_id')]);
                logHistory($pdo, 'agent', $pdo->lastInsertId(), "Création de la fiche utilisateur");
            } elseif ($act === 'edit') {
                $pdo->prepare("UPDATE agents SET first_name=?,last_name=?,fonction=?,email=?,service_id=? WHERE id=?")->execute([fmtFirstName(S($d,'first_name')),fmtLastName(S($d,'last_name')),NV($d,'fonction'),fmtEmail(NV($d,'email')),IV($d,'service_id'),$id]);
                logHistory($pdo, 'agent', $id, "Mise à jour des coordonnées", $id);
            } elseif ($act === 'archive') {
                $agtRow = $pdo->query("SELECT first_name, last_name FROM agents WHERE id=$id")->fetch();
                $agtName = trim(($agtRow['first_name']??'').' '.($agtRow['last_name']??''));
                $pdo->prepare("UPDATE agents SET archived=1 WHERE id=?")->execute([$id]);
                logHistory($pdo, 'agent', $id, "Agent archivé (départ de la société)", $id);
                // Annuler les bons en attente de l'agent (les bons signés restent en historique)
                cancelPendingBons($pdo, $id, "Agent archivé (départ de la société)");
                // Libérer tous les matériels de cet agent
                $devIds = $pdo->query("SELECT id FROM devices WHERE agent_id=$id AND archived=0")->fetchAll(PDO::FETCH_COLUMN);
                if ($devIds) {
                    $pdo->prepare("UPDATE devices SET status='Stock', agent_id=NULL, service_id=NULL WHERE agent_id=? AND archived=0")->execute([$id]);
                    foreach ($devIds as $did) {
                        logHistory($pdo, 'device', (int)$did, "Retourné au stock automatiquement (Agent \"$agtName\" a quitté la société)");
                    }
                }
                // Libérer toutes les lignes mobiles de cet agent
                $lineRows = $pdo->query("SELECT id, device_id FROM mobile_lines WHERE agent_id=$id AND archived=0")->fetchAll();
                if ($lineRows) {
                    foreach ($lineRows as $lr) {
                        logHistory($pdo, 'line', (int)$lr['id'], "Ligne libérée automatiquement (Agent \"$agtName\" a quitté la société)");
                        if ($lr['device_id']) {
                            $pdo->prepare("UPDATE devices SET status='Stock', agent_id=NULL, service_id=NULL WHERE id=? AND archived=0")->execute([$lr['device_id']]);
                            logHistory($pdo, 'device', (int)$lr['device_id'], "Retourné au stock automatiquement via libération de ligne (Agent \"$agtName\")");
                        }
                    }
                    $pdo->prepare("UPDATE mobile_lines SET agent_id=NULL, service_id=NULL, device_id=NULL, status='Stock' WHERE agent_id=? AND archived=0")->execute([$id]);
                }
            } elseif ($act === 'restore') {
                $pdo->prepare("UPDATE agents SET archived=0 WHERE id=?")->execute([$id]);
                logHistory($pdo, 'agent', $id, "Agent restauré (retour dans la société)", $id);
            }
        } elseif ($ent === 'quick_assign') {
            // Attribution rapide depuis la fiche utilisateur : ligne ou matériel pris dans le stock
            $qaError = null;
            $agentId = (int)($d['agent_id'] ?? 0);
            $agtRow = $pdo->query("SELECT id, service_id, archived FROM agents WHERE id=$agentId")->fetch();
            if (!$agtRow || $agtRow['archived']) {
                $qaError = "Utilisateur introuvable ou archivé.";
            } elseif (!empty($d['line_id'])) {
                $lid = (int)$d['line_id'];
                $line = $pdo->query("SELECT id, device_id, COALESCE(personal_device,0) as personal_device FROM mobile_lines WHERE id=$lid AND archived=0 AND agent_id IS NULL AND sim_vierge=0")->fetch();
                if (!$line) { $qaError = "Cette ligne n'est plus disponible en stock."; }
                else {
                    $pdo->prepare("UPDATE mobile_lines SET agent_id=?, service_id=?, status='Active' WHERE id=?")->execute([$agentId, $agtRow['service_id'], $lid]);
                    $agtName = getAgentName($pdo, $agentId);
                    logHistory($pdo, 'line', $lid, "Ligne/SIM attribuée à $agtName", $agentId);
                    if ($line['device_id']) {
                        $pdo->prepare("UPDATE devices SET status='Deployed', agent_id=?, service_id=? WHERE id=?")->execute([$agentId, $agtRow['service_id'], $line['device_id']]);
                        logHistory($pdo, 'device', $line['device_id'], "Déployé et associé à la ligne", $agentId);
                    } elseif (empty($line['personal_device'])) {
                        // La ligne n'a pas de mobile : lier au mobile de l'agent
                        // qui n'est encore associé à aucune ligne active
                        $st = $pdo->prepare("SELECT d.id, d.imei FROM devices d WHERE d.agent_id=? AND d.archived=0
                            AND d.id NOT IN (SELECT device_id FROM mobile_lines WHERE device_id IS NOT NULL AND archived=0)
                            ORDER BY d.id LIMIT 1");
                        $st->execute([$agentId]);
                        if ($freeDev = $st->fetch()) {
                            $pdo->prepare("UPDATE mobile_lines SET device_id=? WHERE id=?")->execute([(int)$freeDev['id'], $lid]);
                            $pdo->prepare("UPDATE devices SET status='Deployed' WHERE id=? AND status='Stock'")->execute([(int)$freeDev['id']]);
                            logHistory($pdo, 'line', $lid, "Associée automatiquement au mobile en dotation (IMEI {$freeDev['imei']})", $agentId);
                        }
                    }
                    cancelPendingBons($pdo, $agentId, "Nouvelle ligne attribuée");
                }
            } elseif (!empty($d['device_id'])) {
                $did = (int)$d['device_id'];
                $devRow = $pdo->query("SELECT id FROM devices WHERE id=$did AND archived=0 AND agent_id IS NULL AND status='Stock'")->fetch();
                if (!$devRow) { $qaError = "Ce matériel n'est plus disponible en stock."; }
                else {
                    $pdo->prepare("UPDATE devices SET status='Deployed', agent_id=?, service_id=? WHERE id=?")->execute([$agentId, $agtRow['service_id'], $did]);
                    $agtName = getAgentName($pdo, $agentId);
                    logHistory($pdo, 'device', $did, "Matériel affecté à $agtName", $agentId);
                    // L'agent a une ligne « en attente de mobile » : l'associer à ce matériel
                    $st = $pdo->prepare("SELECT id, phone_number FROM mobile_lines WHERE agent_id=? AND archived=0 AND sim_vierge=0
                        AND COALESCE(personal_device,0)=0 AND device_id IS NULL ORDER BY id LIMIT 1");
                    $st->execute([$agentId]);
                    if ($freeLine = $st->fetch()) {
                        $pdo->prepare("UPDATE mobile_lines SET device_id=? WHERE id=?")->execute([$did, (int)$freeLine['id']]);
                        logHistory($pdo, 'device', $did, "Associé automatiquement à la ligne " . formatPhone($freeLine['phone_number']), $agentId);
                    }
                    cancelPendingBons($pdo, $agentId, "Nouveau matériel affecté");
                }
            } else {
                $qaError = "Aucun élément sélectionné.";
            }
            if (empty($d['_ajax'])) { $qaError ? flash('error', $qaError) : flash('success', 'Attribution enregistrée.'); }
        } elseif ($ent === 'device') {
            $mod = IV($d,'model_id'); $agt = IV($d,'agent_id'); $svc = IV($d,'service_id'); $pd = NV($d,'purchase_date');
            if ($act === 'add') {
                $pdo->prepare("INSERT INTO devices(imei,imei2,serial_number,inventory_label,model_id,status,agent_id,service_id,purchase_date,notes)VALUES(?,?,?,?,?,?,?,?,?,?)")->execute([S($d,'imei'),S($d,'imei2'),S($d,'serial_number'),NV($d,'inventory_label'),$mod,S($d,'status','Stock'),$agt,$svc,$pd,S($d,'notes')]);
                $newId = $pdo->lastInsertId();
                if ($agt) { $agtName = getAgentName($pdo, $agt); logHistory($pdo, 'device', $newId, "Matériel affecté à $agtName", $agt); cancelPendingBons($pdo, $agt, "Nouveau matériel affecté"); }
            } elseif ($act === 'edit') {
                $old = $pdo->query("SELECT agent_id FROM devices WHERE id=$id")->fetchColumn();
                $pdo->prepare("UPDATE devices SET imei=?,imei2=?,serial_number=?,inventory_label=?,model_id=?,status=?,agent_id=?,service_id=?,purchase_date=?,notes=? WHERE id=?")->execute([S($d,'imei'),S($d,'imei2'),S($d,'serial_number'),NV($d,'inventory_label'),$mod,S($d,'status'),$agt,$svc,$pd,S($d,'notes'),$id]);
                if ($old != $agt) {
                    if ($old) { logHistory($pdo, 'device', $id, "Matériel retiré de la dotation", $old); cancelPendingBons($pdo, $old, "Matériel retiré"); }
                    if ($agt) { $agtName = getAgentName($pdo, $agt); logHistory($pdo, 'device', $id, "Matériel affecté à $agtName", $agt); cancelPendingBons($pdo, $agt, "Nouveau matériel affecté"); } 
                    else { logHistory($pdo, 'device', $id, "Matériel désattribué (retourné au stock)"); }
                }
            } elseif ($act === 'archive') {
                $old = $pdo->query("SELECT agent_id FROM devices WHERE id=$id")->fetchColumn();
                $archiveReason = S($d,'archive_reason','Non précisé');
                $archiveComment = S($d,'archive_comment','');
                $statusMap = ['Perdu'=>'Lost','Volé'=>'Lost','Cassé'=>'HS','Obsolète'=>'HS'];
                $archiveStatus = $statusMap[$archiveReason] ?? 'HS';
                $logMsg = "Matériel Archivé — Motif : $archiveReason" . ($archiveComment ? " — Commentaire : $archiveComment" : "");
                $pdo->prepare("UPDATE devices SET archived=1, status=?, agent_id=NULL, service_id=NULL WHERE id=?")->execute([$archiveStatus, $id]);
                logHistory($pdo, 'device', $id, $logMsg, $old);
                if ($old) cancelPendingBons($pdo, $old, "Matériel archivé — $archiveReason");
                $linesAff = $pdo->query("SELECT id, agent_id FROM mobile_lines WHERE device_id=$id AND archived=0")->fetchAll();
                $archiveAlsoLineId = !empty($d['archive_also_line']) && !empty($d['archive_also_line_id']) ? (int)$d['archive_also_line_id'] : 0;
                foreach($linesAff as $la) {
                    if ($archiveAlsoLineId && $la['id'] == $archiveAlsoLineId) {
                        $pdo->prepare("UPDATE mobile_lines SET archived=1, status='Resiliated', device_id=NULL, agent_id=NULL, service_id=NULL WHERE id=?")->execute([$la['id']]);
                        logHistory($pdo, 'line', $la['id'], "Ligne archivée automatiquement — téléphone associé archivé ($archiveReason)" . ($archiveComment ? " — $archiveComment" : ""), $la['agent_id']);
                    } else {
                        $pdo->prepare("UPDATE mobile_lines SET device_id=NULL WHERE id=?")->execute([$la['id']]);
                        logHistory($pdo, 'line', $la['id'], "Matériel dissocié automatiquement (Terminal déclaré HS/Perdu/Archivé)", $la['agent_id']);
                    }
                    // La dotation de l'agent de la ligne a changé (si différent de celui du matériel)
                    if ($la['agent_id']) cancelPendingBons($pdo, $la['agent_id'], "Téléphone de la ligne archivé — $archiveReason");
                }
            } elseif ($act === 'restore') {
                $pdo->prepare("UPDATE devices SET archived=0, status='Stock', agent_id=NULL WHERE id=?")->execute([$id]); 
                logHistory($pdo, 'device', $id, "Matériel restauré depuis les archives vers le Stock");
            }
        } elseif ($ent === 'sim_swap') {
            $lid = (int)$d['line_id'];
            $cur = $pdo->query("SELECT iccid, pin, puk, agent_id FROM mobile_lines WHERE id=$lid")->fetch();
            $newIccid = preg_replace('/[^a-zA-Z0-9]/', '', S($d,'new_iccid'));
            $newPin   = S($d,'new_pin');
            $newPuk   = S($d,'new_puk');
            $reason   = S($d,'reason', 'Non précisé');
            $author   = $_SESSION['username'] ?? 'Inconnu';
            // Si une SIM vierge du stock a été sélectionnée, on la retire du stock
            $stockSimId = !empty($d['stock_sim_id']) ? (int)$d['stock_sim_id'] : null;
            if ($stockSimId) {
                $pdo->prepare("DELETE FROM mobile_lines WHERE id=? AND sim_vierge=1")->execute([$stockSimId]);
            }
            // Archiver dans sim_history
            $pdo->prepare("INSERT INTO sim_history (line_id, old_iccid, old_pin, old_puk, new_iccid, new_pin, new_puk, reason, author) VALUES (?,?,?,?,?,?,?,?,?)")
                ->execute([$lid, $cur['iccid'], $cur['pin'], $cur['puk'], $newIccid, $newPin, $newPuk, $reason, $author]);
            // Mettre à jour la ligne (+ EID et code activation si eSIM)
            $newEid  = NV($d, 'new_eid');
            $newCode = NV($d, 'new_activation_code');
            $updateEsimPart = '';
            $updateParams = [$newIccid, $newPin, $newPuk];
            if ($newEid !== null)  { $updateEsimPart .= ', eid=?';             $updateParams[] = $newEid; }
            if ($newCode !== null) { $updateEsimPart .= ', activation_code=?'; $updateParams[] = $newCode; }
            $updateParams[] = $lid;
            $pdo->prepare("UPDATE mobile_lines SET iccid=?, pin=?, puk=?, sim_vierge=0$updateEsimPart WHERE id=?")
                ->execute($updateParams);
            logHistory($pdo, 'line', $lid, "🔄 Changement de SIM — Motif : $reason (ancien ICCID : {$cur['iccid']})", $cur['agent_id']);
            // Détecter si c'est une migration eSIM pour régénérer le bon
            $isEsimSwap = (stripos($reason, 'esim') !== false || stripos($reason, 'eSIM') !== false || !empty($d['new_eid']) || !empty($d['new_activation_code']));
            if ($cur['agent_id']) {
                cancelPendingBons($pdo, $cur['agent_id'], "Changement de carte SIM ($reason)");
                if ($isEsimSwap) {
                    flash('success', "Migration eSIM enregistrée — un nouveau bon de remise doit être généré et signé. Générez-le via l'icône 🖨️ de la ligne ou la fiche agent.");
                } else {
                    flash('success', 'Changement de SIM enregistré. Un nouveau bon de remise doit être généré et signé.');
                }
            } else {
                flash('success', 'Changement de SIM enregistré avec succès.');
            }

        } elseif ($ent === 'line') {
            $phoneNum = str_replace(' ', '', S($d,'phone_number'));
            $agt = IV($d,'agent_id'); $bil = IV($d,'billing_id'); $pln = IV($d,'plan_id'); $svc = IV($d,'service_id'); $dev = IV($d,'device_id');
            if ($act === 'add') {
                $simVierge = !empty($d['sim_vierge']) ? 1 : 0;
                $isEsim    = !empty($d['esim']) ? 1 : 0;
                $phoneNum  = $simVierge ? null : $phoneNum;
                $statusVal = $simVierge ? 'Stock' : S($d,'status','Stock');
                $pdo->prepare("INSERT INTO mobile_lines(phone_number,iccid,pin,pin2,puk,puk2,rio,agent_id,billing_id,plan_id,service_id,device_id,activation_date,options_details,status,notes,personal_device,sim_vierge,esim,eid,activation_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")->execute([$phoneNum,S($d,'iccid'),S($d,'pin'),S($d,'pin2'),S($d,'puk'),S($d,'puk2'),S($d,'rio'),$agt,$bil,$pln,$svc,$dev,NV($d,'activation_date'),S($d,'options_details'),$statusVal,S($d,'notes'),!empty($d['personal_device'])?1:0,$simVierge,$isEsim,NV($d,'eid'),NV($d,'activation_code')]);
                $newId = $pdo->lastInsertId();
                if ($agt) { $agtName = getAgentName($pdo, $agt); logHistory($pdo, 'line', $newId, "Ligne/SIM".($isEsim?" (eSIM)":" ")." attribuée à $agtName", $agt); cancelPendingBons($pdo, $agt, "Nouvelle ligne attribuée"); }
                if ($dev) {
                    $pdo->prepare("UPDATE devices SET status='Deployed', agent_id=?, service_id=? WHERE id=?")->execute([$agt, $svc, $dev]);
                    logHistory($pdo, 'device', $dev, "Déployé et associé à la ligne", $agt);
                }
            } elseif ($act === 'edit') {
                $simVierge = !empty($d['sim_vierge']) ? 1 : 0;
                $isEsim    = !empty($d['esim']) ? 1 : 0;
                $phoneNum  = $simVierge ? null : $phoneNum;
                $statusVal = $simVierge ? 'Stock' : S($d,'status');
                $oldData = $pdo->query("SELECT agent_id, device_id FROM mobile_lines WHERE id=$id")->fetch();
                $oldAgt = $oldData['agent_id']; $oldDev = $oldData['device_id'];
                $pdo->prepare("UPDATE mobile_lines SET phone_number=?,iccid=?,pin=?,pin2=?,puk=?,puk2=?,rio=?,agent_id=?,billing_id=?,plan_id=?,service_id=?,device_id=?,activation_date=?,options_details=?,status=?,notes=?,personal_device=?,sim_vierge=?,esim=?,eid=?,activation_code=? WHERE id=?")->execute([$phoneNum,S($d,'iccid'),S($d,'pin'),S($d,'pin2'),S($d,'puk'),S($d,'puk2'),S($d,'rio'),$agt,$bil,$pln,$svc,$dev,NV($d,'activation_date'),S($d,'options_details'),$statusVal,S($d,'notes'),!empty($d['personal_device'])?1:0,$simVierge,$isEsim,NV($d,'eid'),NV($d,'activation_code'),$id]);
                
                if ($oldAgt != $agt) {
                    if ($oldAgt) logHistory($pdo, 'line', $id, "Ligne retirée de la dotation", $oldAgt);
                    if ($agt) { $agtName = getAgentName($pdo, $agt); logHistory($pdo, 'line', $id, "Ligne/SIM attribuée à $agtName", $agt); }
                    else { logHistory($pdo, 'line', $id, "Ligne désattribuée"); }
                    // Changement d'utilisateur (avec ou sans téléphone) → bons en attente annulés des deux côtés
                    if ($agt)    cancelPendingBons($pdo, $agt,    "Ligne transférée à cet agent");
                    if ($oldAgt) cancelPendingBons($pdo, $oldAgt, "Ligne retirée de la dotation");
                }
                
                if ($oldDev != $dev) {
                    if ($oldDev) {
                        $pdo->prepare("UPDATE devices SET status='Stock', agent_id=NULL, service_id=NULL WHERE id=?")->execute([$oldDev]);
                        logHistory($pdo, 'device', $oldDev, "Détaché de la ligne (Retour au stock)", $oldAgt);
                    }
                    if ($dev) {
                        $pdo->prepare("UPDATE devices SET status='Deployed', agent_id=?, service_id=? WHERE id=?")->execute([$agt, $svc, $dev]);
                        logHistory($pdo, 'device', $dev, "Associé à la ligne", $agt);
                    }
                    // Téléphone changé → les bons en attente ne reflètent plus la dotation
                    if ($agt) cancelPendingBons($pdo, $agt, "Téléphone associé modifié sur la ligne");
                    if ($oldAgt && $oldAgt != $agt) cancelPendingBons($pdo, $oldAgt, "Téléphone retiré de la ligne");
                } elseif ($dev && $oldAgt != $agt) {
                    // (annulation des bons déjà traitée dans le bloc changement d'utilisateur ci-dessus)
                    $pdo->prepare("UPDATE devices SET agent_id=?, service_id=? WHERE id=?")->execute([$agt, $svc, $dev]);
                    logHistory($pdo, 'device', $dev, "Transféré suite au changement d'utilisateur sur la ligne", $agt);
                }

            } elseif ($act === 'archive') {
                $devId = $pdo->query("SELECT device_id FROM mobile_lines WHERE id=$id")->fetchColumn();
                $old = $pdo->query("SELECT agent_id FROM mobile_lines WHERE id=$id")->fetchColumn();
                $archiveReason = S($d,'archive_reason','Résiliation');
                $archiveComment = S($d,'archive_comment','');
                $logMsg = "Ligne Archivée — Motif : $archiveReason" . ($archiveComment ? " — Commentaire : $archiveComment" : "");
                $pdo->prepare("UPDATE mobile_lines SET archived=1, status='Resiliated', device_id=NULL, agent_id=NULL, service_id=NULL WHERE id=?")->execute([$id]);
                logHistory($pdo, 'line', $id, $logMsg, $old);
                if ($old) cancelPendingBons($pdo, $old, "Ligne archivée — $archiveReason");

                if ($devId) {
                    $archiveAlsoDev = !empty($d['archive_also_device']) && !empty($d['archive_also_device_id']) && (int)$d['archive_also_device_id'] === $devId;
                    if ($archiveAlsoDev) {
                        $oldDevAgt = $pdo->query("SELECT agent_id FROM devices WHERE id=$devId")->fetchColumn();
                        $pdo->prepare("UPDATE devices SET archived=1, status='HS', agent_id=NULL, service_id=NULL WHERE id=?")->execute([$devId]);
                        logHistory($pdo, 'device', $devId, "Matériel archivé automatiquement — ligne associée archivée ($archiveReason)" . ($archiveComment ? " — $archiveComment" : ""));
                        if ($oldDevAgt) cancelPendingBons($pdo, $oldDevAgt, "Téléphone archivé avec la ligne");
                    } else {
                        $pdo->prepare("UPDATE devices SET status='Stock', agent_id=NULL, service_id=NULL WHERE id=?")->execute([$devId]);
                        logHistory($pdo, 'device', $devId, "Retourné au stock automatiquement (La ligne a été résiliée/archivée)");
                    }
                }
            } elseif ($act === 'restore') {
                $pdo->prepare("UPDATE mobile_lines SET archived=0, status='Stock', agent_id=NULL WHERE id=?")->execute([$id]); 
                logHistory($pdo, 'line', $id, "Restaurée depuis les archives");
            }
        }
        
        // Réponse JSON pour l'attribution rapide (fiche utilisateur, sans rechargement)
        if ($ent === 'quick_assign' && !empty($d['_ajax'])) {
            if ($pdo->inTransaction()) $pdo->commit();
            header('Content-Type: application/json');
            echo json_encode(['ok' => empty($qaError), 'error' => $qaError ?: null]);
            exit;
        }

        // On ne flashe "Opération réussie" que si ce n'est pas un attachment, car l'attachment a déjà flashé "Document ajouté"
        if (!in_array($ent, ['attachment', 'bon', 'bulk', 'settings', 'admin', 'admin_signature', 'quick_assign', 'backup', 'import', 'invoice', 'parc', 'secret_purge', 'ldap_test', 'smtp_test', 'mail_tpl'])) flash('success', 'Opération réussie.');
        if ($pdo->inTransaction()) $pdo->commit();

    } catch (Exception $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        $detail = (defined('APP_DEBUG') && APP_DEBUG) ? ' — ' . $e->getMessage() : '';
        flash('error', "L'opération a échoué et a été annulée (aucune donnée modifiée)$detail.");
    }
    $redirect = 'index.php?page=' . ($_GET['page'] ?? 'dashboard'); if(isset($_GET['tab'])) $redirect .= '&tab='.$_GET['tab']; if(isset($_GET['sub'])) $redirect .= '&sub='.preg_replace('/[^a-z]/', '', $_GET['sub']); header('Location: ' . $redirect); exit;
}

// ─── 7. ROUTAGE & VUES ────────────────────────────────────────
$page = preg_replace('/[^a-z_]/', '', $_GET['page'] ?? 'dashboard');
$tab = preg_replace('/[^a-z_]/', '', $_GET['tab'] ?? 'active');

$pageTitles = ['dashboard' => 'Tableau de bord', 'lines' => 'Gestion des Lignes & SIM', 'devices' => 'Parc Matériel & Terminaux', 'brands' => 'Parc par marque et modèle', 'invoices' => 'Facturation / Contrôle', 'refs' => 'Référentiels et Paramètres', 'settings' => 'Paramètres', 'history' => 'Historique des Bons de Remise', 'requests' => 'Demandes de téléphone', 'stats' => 'Statistiques'];
ob_start();

// ==================================================================
// VUE : TABLEAU DE BORD
// ==================================================================
if ($page === 'dashboard') {
    $cLinesAct = $pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived=0 AND status='Active'")->fetchColumn();
    $cLinesStk = $pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived=0 AND status='Stock'")->fetchColumn();
    $cDevDep   = $pdo->query("SELECT COUNT(*) FROM devices WHERE archived=0 AND status='Deployed'")->fetchColumn();
    $cDevStk   = $pdo->query("SELECT COUNT(*) FROM devices WHERE archived=0 AND status='Stock'")->fetchColumn();

    $threshSim    = (int)getSetting($pdo, 'sim_stock_alert', 5);
    $threshDevice = (int)getSetting($pdo, 'device_stock_alert', 3);
    
    $recent = $pdo->query("SELECT l.id as line_id, l.phone_number, l.agent_id, a.first_name, a.last_name, p.name as plan_type, l.status FROM mobile_lines l LEFT JOIN agents a ON l.agent_id = a.id LEFT JOIN plan_types p ON l.plan_id = p.id WHERE l.archived=0 ORDER BY l.created_at DESC LIMIT 5")->fetchAll();

    $alertSuspended = $pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived=0 AND status='Suspended'")->fetchColumn();

    // ── Facturation : lignes payées sans être utilisées ───────────
    // Le module Facturation sait lesquelles sont réellement inactives : c'est
    // l'information qui manquait ici pour que l'alerte « pensez à les résilier »
    // porte un chiffre. Même règle que les alertes du module (N mois de silence
    // consécutifs jusqu'au dernier mois facturé).
    $invZeroNb = 0; $invZeroEur = 0.0; $invLastMonth = null;
    $invZeroMonths = max(1, (int)getSetting($pdo, 'inv_alert_zero_months', 2));
    try {
        $invLastMonth = $pdo->query("SELECT MAX(month_key) FROM invoice_lines")->fetchColumn() ?: null;
        if ($invLastMonth) {
            $serie = [];
            $stZ = $pdo->prepare("SELECT phone_number, month_key, total_ht,
                        calls_count + sms_count + mms_count + data_ko + intl_count + surtaxe_count AS conso
                    FROM invoice_lines WHERE month_key <= ? ORDER BY month_key");
            $stZ->execute([$invLastMonth]);
            foreach ($stZ as $z) $serie[$z['phone_number']][$z['month_key']] = $z;
            foreach ($serie as $byMonth) {
                if (!isset($byMonth[$invLastMonth])) continue;
                $streak = 0;
                foreach (array_reverse(array_keys($byMonth)) as $mk) {
                    if ((int)$byMonth[$mk]['conso'] === 0) $streak++; else break;
                }
                if ($streak >= $invZeroMonths) { $invZeroNb++; $invZeroEur += (float)$byMonth[$invLastMonth]['total_ht']; }
            }
        }
    } catch (Throwable $e) { $invZeroNb = 0; }   // module non encore alimenté

    $brandData = $pdo->query("SELECT m.brand, COUNT(d.id) as c FROM devices d JOIN models m ON d.model_id=m.id WHERE d.archived=0 GROUP BY m.brand")->fetchAll();
    $brands = []; $bCounts = []; foreach($brandData as $b) { $brands[] = $b['brand']; $bCounts[] = $b['c']; }

    $svcData = $pdo->query("SELECT s.name, COUNT(l.id) as c FROM mobile_lines l JOIN services s ON l.service_id=s.id WHERE l.archived=0 GROUP BY s.name ORDER BY c DESC LIMIT 5")->fetchAll();
    $svcs = []; $sCounts = []; foreach($svcData as $s) { $svcs[] = $s['name'] ?: 'Non assigné'; $sCounts[] = $s['c']; }

    // Bons en attente de signature (avec expiration proche ou dépassée)
    $pendingBons = $pdo->query("SELECT b.id, b.numero, b.type, b.expires_at, b.agent_id,
            DATE_FORMAT(b.created_at, '%d/%m/%Y') as created_fmt,
            CONCAT(IFNULL(a.first_name,''), ' ', IFNULL(a.last_name,'')) as agent_name
        FROM bons b JOIN agents a ON b.agent_id = a.id
        WHERE b.status = 'pending'
        ORDER BY b.expires_at ASC, b.created_at ASC LIMIT 12")->fetchAll();
    $bonsExpSoon = 0; $bonsExpired = 0;
    foreach ($pendingBons as $pb) {
        if ($pb['expires_at'] && strtotime($pb['expires_at']) < time()) $bonsExpired++;
        elseif ($pb['expires_at'] && strtotime($pb['expires_at']) < time() + 7*86400) $bonsExpSoon++;
    }

    // Demandes de téléphone en cours (à qualifier / en validation)
    $reqDays = max(1, (int)getSetting($pdo, 'request_reminder_days', 5));
    $pendingReqs = $pdo->query("SELECT r.*, DATE_FORMAT(r.created_at, '%d/%m/%Y') as created_fmt,
            (SELECT label FROM request_steps s WHERE s.request_id=r.id AND s.ordre=r.current_step LIMIT 1) as current_label,
            (SELECT COUNT(*) FROM request_steps s WHERE s.request_id=r.id) as nb_steps,
            (SELECT COALESCE(s.reminded_at, s.notified_at) FROM request_steps s WHERE s.request_id=r.id AND s.ordre=r.current_step LIMIT 1) as last_contact
        FROM requests r
        WHERE r.status IN ('a_qualifier','en_validation','validee')
        ORDER BY FIELD(r.status,'a_qualifier','validee','en_validation'), r.created_at ASC LIMIT 12")->fetchAll();
    $reqToQualify = 0; $reqValidated = 0; $reqStalled = 0;
    foreach ($pendingReqs as $pr) {
        if ($pr['status'] === 'a_qualifier') $reqToQualify++;
        elseif ($pr['status'] === 'validee') $reqValidated++;
        elseif ($pr['last_contact'] && strtotime($pr['last_contact']) < time() - $reqDays * 86400) $reqStalled++;
    }
    ?>
    <div class="dashboard-grid">
        
      <div style="position:relative; margin-bottom: 1rem;">
        <div class="search-bar" style="background: var(--card); border: 2px solid var(--primary-dim); box-shadow: var(--shadow);">
          <span class="search-bar-icon" style="color:var(--primary)"><i class="bi bi-search"></i></span>
          <input type="text" id="dash-search" placeholder="Recherche globale : N° de ligne, IMEI, ICCID, Utilisateur..." oninput="doGlobalSearch(this.value)" autocomplete="off" style="font-size: 1rem; padding: .5rem;">
          <button class="search-bar-clear" id="dash-clear" onclick="document.getElementById('dash-search').value=''; doGlobalSearch('');" style="display:none; font-size:1.2rem;"><i class="bi bi-x-lg"></i></button>
        </div>
        <div id="dash-search-results" style="display:none; position:absolute; top:100%; left:0; right:0; background:var(--card); border:1px solid var(--border); border-radius:var(--radius); margin-top:.5rem; overflow:hidden; box-shadow:var(--shadow-lg); z-index:100;"></div>
      </div>

      <!-- Blocs fusionnés : chiffre clé (→ liste) + action d'ajout, par entité -->
      <div class="kpi-row">
        <div class="kpi-card kpi-green">
          <a href="?page=refs&tab=agents" class="kpi-main">
            <div class="kpi-icon"><i class="bi bi-building"></i></div>
            <div class="kpi-info"><span class="kpi-val"><?=$pdo->query("SELECT COUNT(*) FROM agents WHERE archived=0")->fetchColumn()?></span><span class="kpi-label">Utilisateurs</span></div>
          </a>
          <a href="?page=refs&tab=agents&open=modal-add-agent" class="kpi-add" title="Créer un utilisateur"><i class="bi bi-plus-lg"></i> Nouvel utilisateur</a>
        </div>
        <div class="kpi-card kpi-blue">
          <a href="?page=lines&tab=active" class="kpi-main">
            <div class="kpi-icon"><i class="bi bi-telephone"></i></div>
            <div class="kpi-info"><span class="kpi-val"><?=h($cLinesAct)?></span><span class="kpi-label">Lignes actives</span><span class="kpi-sub"><?=$cLinesStk?> en stock (non attribuée<?=($cLinesStk > 1 ? 's' : '')?>)</span></div>
          </a>
          <a href="?page=lines&open=modal-add-line" class="kpi-add" title="Créer une ligne / SIM"><i class="bi bi-plus-lg"></i> Nouvelle ligne</a>
        </div>
        <div class="kpi-card kpi-violet">
          <a href="?page=devices&tab=active" class="kpi-main">
            <div class="kpi-icon"><i class="bi bi-phone"></i></div>
            <div class="kpi-info"><span class="kpi-val"><?=h($cDevDep)?></span><span class="kpi-label">Mobiles déployés</span><span class="kpi-sub"><?=$cDevStk?> <?=($cDevStk > 1 ? 'terminaux' : 'terminal')?> en stock</span></div>
          </a>
          <a href="?page=devices&open=modal-add-device" class="kpi-add" title="Ajouter un matériel"><i class="bi bi-plus-lg"></i> Nouveau matériel</a>
        </div>
      </div>

      <?php if($cLinesStk <= $threshSim || $cDevStk <= $threshDevice || $alertSuspended > 0 || $invZeroNb > 0 || $bonsExpired > 0 || $bonsExpSoon > 0 || $reqToQualify > 0 || $reqValidated > 0 || $reqStalled > 0): ?>
      <div style="background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.3);padding:1.25rem;border-radius:var(--radius);margin-bottom:1.5rem;">
          <h4 style="color:var(--danger);margin-bottom:10px;display:flex;align-items:center;gap:8px;"><i class="bi bi-exclamation-triangle-fill"></i> Points d'attention immédiats</h4>
          <ul style="color:var(--text);margin:0;padding-left:1.5rem;font-size:0.9rem;line-height:1.8;">
              <?php if($cLinesStk <= $threshSim): ?>
              <li><strong>Stock SIM bas :</strong> Il ne reste que <strong style="color:var(--warning)"><?=$cLinesStk?></strong> carte(s) SIM disponible(s) (seuil : <?=$threshSim?>). <a href="?page=refs&tab=settings" style="color:var(--primary);font-size:.82rem;">Modifier le seuil →</a></li>
              <?php endif; ?>
              <?php if($cDevStk <= $threshDevice): ?>
              <li><strong>Stock Smartphones bas :</strong> Il ne reste que <strong style="color:var(--danger)"><?=$cDevStk?></strong> terminal(aux) disponible(s) (seuil : <?=$threshDevice?>). <a href="?page=refs&tab=settings" style="color:var(--primary);font-size:.82rem;">Modifier le seuil →</a></li>
              <?php endif; ?>
              <?php if($alertSuspended > 0): ?>
              <li><strong><a href="?page=lines&tab=suspended" style="color:inherit;">Lignes Suspendues</a> :</strong> <span style="color:var(--warning);font-weight:bold;"><?=$alertSuspended?></span> ligne(s) hors service (pensez à les résilier si inactives).</li>
              <?php endif; ?>
              <?php if($invZeroNb > 0): ?>
              <li><strong><a href="?page=invoices&tab=alerts&type=zero" style="color:inherit;">Lignes facturées sans consommation</a> :</strong>
                  <span style="color:var(--info);font-weight:bold;"><?=$invZeroNb?></span> ligne(s) payée(s) sans aucun usage depuis
                  au moins <?=$invZeroMonths?> mois — <strong><?=number_format($invZeroEur, 2, ',', ' ')?> € HT/mois</strong>,
                  soit <?=number_format($invZeroEur * 12, 2, ',', ' ')?> € par an.
                  <a href="?page=invoices&tab=alerts&type=zero" style="color:var(--primary);font-size:.82rem;">Voir le détail →</a></li>
              <?php endif; ?>
              <?php if($bonsExpired > 0): ?>
              <li><strong>Bons expirés :</strong> <span style="color:var(--danger);font-weight:bold;"><?=$bonsExpired?></span> bon(s) en attente dont le lien de signature a expiré — regénérez-les depuis la fiche agent.</li>
              <?php endif; ?>
              <?php if($bonsExpSoon > 0): ?>
              <li><strong>Bons à relancer :</strong> <span style="color:var(--warning);font-weight:bold;"><?=$bonsExpSoon?></span> bon(s) en attente expirent sous 7 jours — relancez les agents (bouton 📧).</li>
              <?php endif; ?>
              <?php if($reqToQualify > 0): ?>
              <li><strong>Demandes à qualifier :</strong> <span style="color:var(--warning);font-weight:bold;"><?=$reqToQualify?></span> demande(s) de téléphone attendent le lancement de leur circuit de validation. <a href="?page=requests" style="color:var(--primary);font-size:.82rem;">Ouvrir les demandes →</a></li>
              <?php endif; ?>
              <?php if($reqValidated > 0): ?>
              <li><strong>Demandes validées à traiter :</strong> <span style="color:var(--success);font-weight:bold;"><?=$reqValidated?></span> demande(s) ont terminé leur circuit — attribuez le matériel et générez le bon de remise. <a href="?page=requests" style="color:var(--primary);font-size:.82rem;">Ouvrir les demandes →</a></li>
              <?php endif; ?>
              <?php if($reqStalled > 0): ?>
              <li><strong>Circuits au ralenti :</strong> <span style="color:var(--warning);font-weight:bold;"><?=$reqStalled?></span> demande(s) sans réponse du valideur depuis plus de <?=$reqDays?> jours (relances automatiques actives).</li>
              <?php endif; ?>
          </ul>
      </div>
      <?php endif; ?>

      <?php if($pendingBons): ?>
      <div class="card">
        <div class="card-header"><span class="card-title">✍️ Bons en attente de signature (<?=count($pendingBons)?>)</span>
          <a href="?page=history" style="font-size:.8rem;color:var(--primary);text-decoration:none;">Voir tout l'historique →</a></div>
        <table class="data-table">
          <thead><tr><th>Bon</th><th>Utilisateur</th><th>Généré le</th><th>Expire le</th><th>Actions</th></tr></thead>
          <tbody>
          <?php foreach($pendingBons as $pb):
              $expTs   = $pb['expires_at'] ? strtotime($pb['expires_at']) : null;
              $expired = $expTs && $expTs < time();
              $soon    = !$expired && $expTs && $expTs < time() + 7*86400;
              [$icon, $lbl] = $pb['type'] === 'remise' ? ['📥','Remise'] : ['📤','Restitution'];
          ?>
          <tr>
            <td><?=$icon?> <strong style="font-family:var(--font-mono);font-size:.85rem;"><?=h($pb['numero'])?></strong> <span class="muted" style="font-size:.78rem;"><?=$lbl?></span></td>
            <td><strong style="cursor:pointer;border-bottom:1px dashed var(--border2);" onclick="viewAgent(<?=$pb['agent_id']?>, '<?=h(trim($pb['agent_name']))?>')" title="Voir la fiche"><?=h(trim($pb['agent_name']))?></strong></td>
            <td><?=h($pb['created_fmt'])?></td>
            <td>
              <?php if($expired): ?><span style="color:var(--danger);font-weight:600;">⏰ Expiré</span>
              <?php elseif($soon): ?><span style="color:var(--warning);font-weight:600;"><?=date('d/m/Y', $expTs)?> ⚠️</span>
              <?php else: ?><span class="muted"><?=$expTs ? date('d/m/Y', $expTs) : '—'?></span>
              <?php endif; ?>
            </td>
            <td><a href="?page=pdf_bon&bon_id=<?=$pb['id']?>" target="_blank" class="btn-icon" title="Voir / imprimer / envoyer" style="text-decoration:none;"><i class="bi bi-printer"></i></a></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php endif; ?>

      <?php if($pendingReqs): ?>
      <div class="card">
        <div class="card-header"><span class="card-title">📱 Demandes de téléphone en cours (<?=count($pendingReqs)?>)</span>
          <a href="?page=requests" style="font-size:.8rem;color:var(--primary);text-decoration:none;">Voir toutes les demandes →</a></div>
        <table class="data-table">
          <thead><tr><th>N°</th><th>Agent</th><th>Demandeur</th><th>Service</th><th>Statut</th><th>Étape en cours</th><th></th></tr></thead>
          <tbody>
          <?php foreach($pendingReqs as $pr): [$plbl, $pcls] = requestStatusInfo($pr['status']);
              $stalled = ($pr['status'] === 'en_validation' && $pr['last_contact'] && strtotime($pr['last_contact']) < time() - $reqDays * 86400); ?>
          <tr>
            <td><a href="?page=requests&view=<?=$pr['id']?>" class="cell-link" style="font-family:var(--font-mono);font-weight:700;color:var(--primary);font-size:.85rem;"><?=h($pr['numero'])?></a></td>
            <td><strong><?=h($pr['agent_name'])?></strong></td>
            <td class="muted" <?=$pr['requester_email'] ? 'title="' . h($pr['requester_email']) . '"' : ''?>><?=h($pr['requester_name'] ?: '—')?></td>
            <td class="muted"><?=h($pr['service_name'] ?: '—')?></td>
            <td><span class="badge <?=$pcls?>"><?=h($plbl)?></span></td>
            <td class="muted" style="font-size:.8rem;">
              <?php if($pr['status'] === 'en_validation'): ?><?=(int)$pr['current_step']?>/<?=(int)$pr['nb_steps']?><?=$pr['current_label'] ? ' — ' . h($pr['current_label']) : ''?><?=$stalled ? ' <span style="color:var(--warning);">⚠️ sans réponse</span>' : ''?>
              <?php elseif($pr['status'] === 'a_qualifier'): ?>Déposée le <?=h($pr['created_fmt'])?>
              <?php else: ?>À attribuer / livrer<?php endif; ?>
            </td>
            <td><a href="?page=requests&view=<?=$pr['id']?>" class="btn-icon" title="Ouvrir" style="text-decoration:none;color:var(--primary);"><i class="bi bi-eye"></i></a></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php endif; ?>

      <div style="display:grid; grid-template-columns: 1fr 1fr; gap:1.5rem; margin-top:1rem; margin-bottom:1rem;">
          <div class="card" style="margin-bottom:0;">
              <div class="card-header" style="display:flex;align-items:center;justify-content:space-between;gap:1rem;"><span><i class="bi bi-phone"></i> Répartition par marque</span><a href="?page=brands" class="card-see-all" title="Synthèse du parc par marque et modèle">Voir tout <i class="bi bi-arrow-right"></i></a></div>
              <div style="padding:1rem; height:250px;">
                <?php if(empty($brands)): ?>
                <div style="height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;color:var(--text3);font-size:.88rem;gap:.35rem;"><i class="bi bi-bar-chart" style="font-size:1.6rem;opacity:.5;"></i>Aucun matériel enregistré.</div>
                <?php else: ?><canvas id="chartBrand"></canvas><?php endif; ?>
              </div>
          </div>
          <div class="card" style="margin-bottom:0;">
              <div class="card-header" style="display:flex;align-items:center;justify-content:space-between;gap:1rem;"><span><i class="bi bi-building"></i> Top 5 Services (Lignes actives)</span><a href="?page=refs&tab=services" class="card-see-all">Voir tout <i class="bi bi-arrow-right"></i></a></div>
              <div style="padding:1rem; height:250px;">
                <?php if(empty($svcs)): ?>
                <div style="height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;color:var(--text3);font-size:.88rem;gap:.35rem;padding:0 1rem;"><i class="bi bi-building" style="font-size:1.6rem;opacity:.5;"></i>Aucune ligne active rattachée à un service.<br><span style="font-size:.8rem;">Assignez un service aux lignes pour voir la répartition.</span></div>
                <?php else: ?><canvas id="chartSvc"></canvas><?php endif; ?>
              </div>
          </div>
      </div>

      <div class="card" style="margin-top:1rem">
        <div class="card-header"><span class="card-title"><i class="bi bi-telephone"></i> Dernières lignes enregistrées</span></div>
        <table class="data-table">
          <thead><tr><th>Numéro</th><th>Utilisateur</th><th>Forfait</th><th>Statut</th></tr></thead>
          <tbody>
            <?php if(empty($recent)): ?><tr><td colspan="4" class="empty-cell">Aucune ligne récente</td></tr><?php endif; ?>
            <?php foreach($recent as $r): ?>
            <tr>
              <td><a href="?page=lines&open_line=<?=$r['line_id']?>" class="cell-link" style="font-family:var(--font-mono);color:var(--primary);font-size:1.05rem;font-weight:700;white-space:nowrap;" title="Ouvrir la fiche de la ligne"><?=formatPhone($r['phone_number'])?></a></td>
              <td><?php if($r['agent_id']): ?><span class="cell-link" onclick="viewAgent(<?=$r['agent_id']?>, '<?=h(addslashes($r['first_name'].' '.$r['last_name']))?>')" title="Ouvrir la fiche utilisateur"><?=h($r['first_name'].' '.$r['last_name'])?></span><?php else: ?><span class="muted">—</span><?php endif; ?></td>
              <td><span class="badge badge-muted"><?=h($r['plan_type']?:'Non défini')?></span></td>
              <td><?=statusBadge($r['status'])?></td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>

    </div>
    
    <script src="vendor/chart.umd.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Chaque graphique est indépendant : un canvas absent (aucune donnée →
        // message affiché à la place) n'empêche pas l'autre de s'initialiser.
        const elBrand = document.getElementById('chartBrand');
        if(elBrand){
            const brandLabels = <?php echo json_encode($brands); ?>;
            new Chart(elBrand, {
                type: 'doughnut',
                data: {
                    labels: brandLabels,
                    datasets: [{
                        data: <?php echo json_encode($bCounts); ?>,
                        backgroundColor: ['#4f46e5', '#2563eb', '#7c3aed', '#d97706', '#059669', '#dc2626'],
                        borderWidth: 0
                    }]
                },
                // Un clic sur une part ouvre la synthèse par marque/modèle,
                // pré-filtrée sur la marque cliquée.
                options: { responsive: true, maintainAspectRatio: false,
                    onClick: (e, a) => { if(a.length) location = '?page=brands&q=' + encodeURIComponent(brandLabels[a[0].index]); },
                    onHover: (e, a) => { e.native.target.style.cursor = a.length ? 'pointer' : 'default'; },
                    plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } } }
            });
        }
        const elSvc = document.getElementById('chartSvc');
        if(elSvc){
            new Chart(elSvc, {
                type: 'bar',
                data: {
                    labels: <?php echo json_encode($svcs); ?>,
                    datasets: [{
                        label: 'Nombre de lignes',
                        data: <?php echo json_encode($sCounts); ?>,
                        backgroundColor: '<?=uiPrimaryColor($pdo) ?: '#4f46e5'?>',
                        borderRadius: 5
                    }]
                },
                // Un clic sur une barre ouvre la liste des lignes actives
                // filtrée sur le service cliqué.
                options: { responsive: true, maintainAspectRatio: false,
                    onClick: (e, a) => { const l = <?php echo json_encode($svcs); ?>; if(a.length) location = '?page=lines&tab=active&q=' + encodeURIComponent(l[a[0].index]); },
                    onHover: (e, a) => { e.native.target.style.cursor = a.length ? 'pointer' : 'default'; },
                    scales: { y: { beginAtZero: true, grid: { color: 'rgba(148,163,184,0.18)' }, ticks: { color: '#94a3b8' } }, x: { ticks: { color: '#94a3b8' } } }, plugins: { legend: { display: false } } }
            });
        }
    });

    let dashSearchTimer;
    function doGlobalSearch(q) {
        const resDiv = document.getElementById('dash-search-results');
        const clearBtn = document.getElementById('dash-clear');
        if (clearBtn) clearBtn.style.display = q.trim() ? 'block' : 'none';
        if (q.trim().length < 2) { resDiv.style.display = 'none'; return; }
        
        clearTimeout(dashSearchTimer);
        dashSearchTimer = setTimeout(async () => {
            resDiv.innerHTML = '<div style="padding:1rem;color:var(--text3);text-align:center">⏳ Recherche en cours...</div>';
            resDiv.style.display = 'block';
            try {
                const req = await fetch('index.php?ajax_global_search=1&q=' + encodeURIComponent(q));
                const data = await req.json();
                if (!data || data.length === 0) {
                    resDiv.innerHTML = '<div style="padding:1rem;color:var(--text3);text-align:center">Aucun résultat trouvé pour "'+q+'"</div>';
                    return;
                }
                let html = '<table class="data-table"><tbody>';
                data.forEach(r => {
                    let badge = '';
                    if(r.type === 'Ligne') badge = `<span class="badge" style="background:var(--success-dim);color:var(--success)"><i class="bi bi-telephone"></i> Ligne</span>`;
                    if(r.type === 'Matériel') badge = `<span class="badge" style="background:var(--primary-dim);color:var(--primary)"><i class="bi bi-phone"></i> Matériel</span>`;
                    if(r.type === 'Agent') badge = `<span class="badge" style="background:var(--info-dim);color:var(--info)"><i class="bi bi-person"></i> Agent</span>`;
                    
                    html += `<tr style="cursor:pointer; transition:background .15s;" onmouseover="this.style.background='rgba(0,0,0,0.03)'" onmouseout="this.style.background='none'" onclick="window.location.href='${r.link}'">
                        <td style="width:100px">${badge}</td>
                        <td><strong style="font-size:1.05rem;color:var(--text)">${r.title}</strong><br><span class="muted">${r.subtitle}</span></td>
                        <td style="text-align:right"><span style="color:var(--primary);font-size:.8rem;font-weight:bold;">Voir →</span></td>
                    </tr>`;
                });
                html += '</tbody></table>';
                resDiv.innerHTML = html;
            } catch(e) { resDiv.innerHTML = '<div style="padding:1rem;color:var(--danger);text-align:center">❌ Erreur de recherche</div>'; }
        }, 300);
    }
    </script>
    <?php
}

// ==================================================================
// VUE : LIGNES (Actives / Stock / Archives)
// ==================================================================
elseif ($page === 'lines') {
    $isArchive = ($tab === 'archive'); $isStock = ($tab === 'stock'); $isSuspended = ($tab === 'suspended');
    $where = "l.archived=" . ($isArchive ? "1" : "0");
    if ($isStock) $where .= " AND l.status='Stock'";
    elseif ($isSuspended) $where .= " AND l.status='Suspended'";
    elseif (!$isArchive) $where .= " AND l.status NOT IN ('Stock','Suspended')";

    $lines = $pdo->query("SELECT l.id, l.phone_number, l.iccid, l.pin, l.pin2, l.puk, l.puk2, l.rio, l.agent_id, l.billing_id, l.plan_id, l.service_id, l.device_id, l.activation_date, l.options_details, l.status, l.notes, l.archived, l.created_at, IFNULL(l.personal_device,0) as personal_device, IFNULL(l.sim_vierge,0) as sim_vierge, IFNULL(l.esim,0) as esim, l.eid, l.activation_code, a.first_name, a.last_name, s.name as service_name, b.account_number, p.name as plan_name, IFNULL(o.name,'') as operator_name, d.imei, d.serial_number, m.brand, m.name as model_name FROM mobile_lines l LEFT JOIN agents a ON l.agent_id=a.id LEFT JOIN services s ON l.service_id=s.id LEFT JOIN billing_accounts b ON l.billing_id=b.id LEFT JOIN plan_types p ON l.plan_id=p.id LEFT JOIN operators o ON p.operator_id=o.id LEFT JOIN devices d ON l.device_id=d.id LEFT JOIN models m ON d.model_id=m.id WHERE $where ORDER BY l.created_at DESC")->fetchAll();
    
    $services = $pdo->query("SELECT id, name FROM services ORDER BY name")->fetchAll();
    $plans = $pdo->query("SELECT p.id, p.name, IFNULL(o.name,'') as operator_name FROM plan_types p LEFT JOIN operators o ON p.operator_id=o.id ORDER BY o.name, p.name")->fetchAll();
    $billings = $pdo->query("SELECT id, account_number, name FROM billing_accounts ORDER BY name")->fetchAll();
    $devices = $pdo->query("SELECT d.id, d.imei, d.serial_number, m.brand, m.name FROM devices d LEFT JOIN models m ON d.model_id=m.id WHERE d.archived=0 AND d.status='Stock' ORDER BY m.brand, m.name")->fetchAll();
    // Toutes les SIM en stock (pour le swap) — vierges ET numérotées non affectées
    $simStock = $pdo->query("SELECT id, iccid, pin, puk, IFNULL(esim,0) as esim FROM mobile_lines WHERE archived=0 AND sim_vierge=1 ORDER BY iccid")->fetchAll();
    ?>
    <?php if(!$isArchive): ?>
    <div class="page-header">
      <button class="btn-primary" onclick="openModal('modal-add-line')">+ Ajouter une Ligne / SIM</button>
    </div>
    <?php endif; ?>

    <div style="display:flex; gap:10px; margin-bottom:1rem; border-bottom:2px solid var(--border)">
        <a href="?page=lines&tab=active" class="tab-btn <?=$tab==='active'?'active':''?>"><i class="bi bi-telephone"></i> Lignes Actives</a>
        <a href="?page=lines&tab=stock" class="tab-btn <?=$tab==='stock'?'active':''?>"><i class="bi bi-box-seam"></i> Stock et SIM vierges</a>
        <a href="?page=lines&tab=suspended" class="tab-btn <?=$tab==='suspended'?'active':''?>"><i class="bi bi-pause-circle"></i> Lignes suspendues</a>
        <a href="?page=lines&tab=archive" class="tab-btn <?=$tab==='archive'?'active':''?>"><i class="bi bi-archive"></i> Lignes Résiliées (Archives)</a>
    </div>

    <div class="search-bar-wrap">
      <div class="search-bar">
        <span class="search-bar-icon"><i class="bi bi-search"></i></span>
        <input type="text" placeholder="Rechercher numéro, nom, ICCID, compte de facturation..." oninput="tableSearch(this,'tbody-data','count')">
      </div>
      <div class="search-count" id="count"></div>
    </div>

    <!-- BARRE D'ACTIONS EN MASSE (cachée par défaut) -->
    <div id="bulk-bar-line" style="display:none;align-items:center;gap:1rem;background:var(--primary-dim);border:1px solid var(--border2);border-radius:var(--radius-sm);padding:.75rem 1.25rem;margin-bottom:1rem;flex-wrap:wrap;">
      <span id="bulk-count-line" style="font-weight:700;color:var(--primary);min-width:130px;"></span>
      <form method="post" id="bulk-form-line" style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:center;">
        <input type="hidden" name="_entity" value="bulk">
        <input type="hidden" name="bulk_type" value="line">
        <div id="bulk-ids-line"></div>
        <select name="bulk_action" style="padding:.45rem .75rem;background:var(--card2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:.88rem;">
          <option value="">-- Choisir une action --</option>
          <?php if(!$isArchive): ?><option value="archive">🗄️ Archiver la sélection</option><?php endif; ?>
          <?php if($isArchive): ?><option value="restore">♻️ Restaurer la sélection</option><?php endif; ?>
        </select>
        <button type="button" class="btn-primary" style="padding:.45rem 1rem;font-size:.88rem;" onclick="submitBulk('line')">Appliquer</button>
        <button type="button" class="btn-secondary" style="padding:.45rem .75rem;font-size:.88rem;" onclick="clearBulk('line')"><i class="bi bi-x-lg"></i> Annuler</button>
      </form>
    </div>

    <div class="card" style="overflow-x:auto;">
      <table class="data-table">
        <thead><tr>
          <th style="width:36px;cursor:default;"><input type="checkbox" id="chk-all-line" title="Tout sélectionner" onchange="toggleAllBulk('line',this.checked)" style="cursor:pointer;accent-color:var(--primary);width:15px;height:15px;"></th>
          <th>Ligne & SIM</th><th>Utilisateur & Service</th><th>Facturation & Forfait</th><th>Matériel Associé</th><th>Statut</th><th>Actions</th></tr></thead>
        <tbody id="tbody-data">
        <?php if(empty($lines)): ?><tr><td colspan="7" class="empty-cell">Aucune ligne dans cet onglet</td></tr><?php endif; ?>
        <?php foreach($lines as $l): ?>
        <tr>
          <td><input type="checkbox" class="bulk-chk-line" value="<?=$l['id']?>" onchange="updateBulkBar('line')" style="cursor:pointer;accent-color:var(--primary);width:15px;height:15px;"></td>
          <td><strong class="cell-link" onclick="this.closest('tr').querySelector('.btn-edit').click()" title="Ouvrir la fiche de la ligne" style="font-family:var(--font-mono);font-size:1.05rem;color:var(--primary);white-space:nowrap;"><?= !empty($l['sim_vierge']) ? '<span style="color:var(--text3);font-style:italic;font-family:var(--font);">Sans numéro</span>' : formatPhone($l['phone_number']) ?></strong><br>
          <?php if(!empty($l['sim_vierge'])): ?><span class="badge" style="background:rgba(245,158,11,.15);color:var(--warning);font-size:.7rem;"><i class="bi bi-box-seam"></i> SIM Vierge</span>
          <?php elseif(!empty($l['esim'])): ?><span class="badge" style="background:rgba(139,92,246,.15);color:#a78bfa;font-size:.7rem;"><i class="bi bi-sim"></i> eSIM</span>
          <?php endif; ?>
          <code class="ref" title="ICCID"><?=h($l['iccid']?:'Pas de SIM')?></code><?php if(!empty($l['eid'])): ?><br><span class="muted" style="font-size:.72rem;">EID: <?=h($l['eid'])?></span><?php endif; ?>
          <br><span class="muted">PIN: <?=h($l['pin']?:'-')?> | PUK: <?=h($l['puk']?:'-')?><?php
            // Codes secondaires et RIO : affichés seulement s'ils sont renseignés
            // (alimentés par l'import depuis SFR), pour ne pas alourdir la ligne.
            if(!empty($l['pin2']) || !empty($l['puk2'])): ?><br>PIN 2: <?=h($l['pin2']?:'-')?> | PUK 2: <?=h($l['puk2']?:'-')?><?php endif; ?><?php
            if(!empty($l['rio'])): ?><br>RIO: <?=h($l['rio'])?><?php endif; ?></span></td>
          <td>
            <?php if($l['agent_id']): ?>
              <strong style="cursor:pointer;border-bottom:1px dashed var(--border2);color:var(--text);"
                onclick="viewAgent(<?=$l['agent_id']?>, '<?=h($l['first_name'].' '.$l['last_name'])?>')"
                title="👁️ Voir la fiche de cet utilisateur">
                <?=h($l['first_name'].' '.$l['last_name'])?>
              </strong>
            <?php else: ?>
              <strong><?=h($l['first_name'].' '.$l['last_name'])?></strong>
            <?php endif; ?>
            <br><span class="muted"><i class="bi bi-building"></i> <?=h($l['service_name']?:'Aucun service')?></span>
          </td>
          <td>CF: <strong class="muted"><?=h($l['account_number']?:'-')?></strong><br>
            <?php if($l['operator_name']): ?><span class="muted" style="font-size:.72rem;"><i class="bi bi-broadcast"></i> <?=h($l['operator_name'])?></span><br><?php endif; ?>
            <span class="badge badge-muted"><?=h($l['plan_name']?:'Aucun forfait')?></span>
          </td>
          <td>
            <?php if(!empty($l['personal_device'])): ?>
                <span class="badge" style="background:rgba(56,189,248,.15);color:var(--info);"><i class="bi bi-phone"></i> Téléphone perso</span>
            <?php elseif($l['imei']): ?>
                <strong><?=h($l['brand'].' '.$l['model_name'])?></strong><br><span class="muted">IMEI: <?=h($l['imei'])?></span>
            <?php elseif($l['status'] === 'Active'): ?>
                <span class="badge" style="background:rgba(245,158,11,.15);color:var(--warning);font-size:0.75rem;"><i class="bi bi-exclamation-triangle"></i> En attente de mobile</span>
            <?php else: ?>
                <span class="muted">Aucun appareil</span>
            <?php endif; ?>
          </td>
          <td><?=statusBadge($l['status'])?></td>
          <td class="actions">
            <?php $hist = fetchEntityHistory($pdo, 'line', $l['id']); ?>
            <?php if(!$isArchive): ?>
                <button class="btn-icon btn-edit" data-line-id="<?=$l['id']?>" title="Modifier" onclick='openEditModal(<?=json_encode($l, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>,"line")'><i class="bi bi-pencil"></i></button>
                <button class="btn-icon" title="Historique" onclick='showHistory(<?=json_encode($hist, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>)'><i class="bi bi-clock-history"></i></button>
                <a href="?page=invoices&tab=conso&line=<?=h(simcity_phone_canon($l['phone_number']))?>" class="btn-icon" title="Consommations facturées de cette ligne" style="text-decoration:none;"><i class="bi bi-bar-chart-line"></i></a>
                <?php if($l['agent_id']): ?>
                <a href="index.php?page=pdf_bon&agent_id=<?=$l['agent_id']?>" target="_blank" class="btn-icon" title="Voir / générer le bon de remise" style="text-decoration:none;"><i class="bi bi-printer"></i></a>
                <?php endif; ?>
                <button class="btn-icon" title="Changer la SIM (garder le numéro)" style="color:var(--warning)"
                    onclick="openSimSwap(<?=$l['id']?>, '<?=h($l['phone_number'])?>', '<?=h($l['iccid'])?>', <?=!empty($l['esim'])?'true':'false'?>, '<?=h($l['eid']?:'')?>')"><i class="bi bi-arrow-repeat"></i></button>
                <button type="button" class="btn-icon btn-del" title="Résilier / Archiver" onclick="openArchiveLine(<?=$l['id']?>, <?=(int)$l['device_id']?>, <?=json_encode($l['device_id'] ? ($l['brand'].' '.$l['model_name'].' — S/N: '.($l['serial_number']?:($l['imei']?:'—'))) : '')?>)"><i class="bi bi-archive"></i></button>
            <?php else: ?>
                <button class="btn-icon" title="Historique" onclick='showHistory(<?=json_encode($hist, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>)'><i class="bi bi-clock-history"></i></button>
                <a href="?page=invoices&tab=conso&line=<?=h(simcity_phone_canon($l['phone_number']))?>" class="btn-icon" title="Consommations facturées de cette ligne" style="text-decoration:none;"><i class="bi bi-bar-chart-line"></i></a>
                <form method="post" style="display:inline"><input type="hidden" name="_entity" value="line"><input type="hidden" name="_action" value="restore"><input type="hidden" name="_id" value="<?=$l['id']?>"><button type="submit" class="btn-icon" title="Restaurer" style="color:var(--success)"><i class="bi bi-arrow-counterclockwise"></i></button></form>
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>

    <?php foreach(['add'=>'Nouvelle Ligne / SIM', 'edit'=>'Modifier'] as $act => $title): ?>
    <div class="modal-overlay" id="modal-<?=$act?>-line">
      <div class="modal modal-lg"><div class="modal-header"><h3><?=$title?></h3><button type="button" class="modal-close" onclick="closeModal('modal-<?=$act?>-line')"><i class="bi bi-x-lg"></i></button></div>
      <form method="post" onsubmit="return lineFormCheck('<?=$act?>')"><input type="hidden" name="_entity" value="line"><input type="hidden" name="_action" value="<?=$act?>"><?php if($act==='edit') echo '<input type="hidden" name="_id" id="edit-id-line">'; ?>
      <div class="form-grid">
        <div class="form-group"><label>Numéro de Ligne</label>
          <div id="<?=$act?>-phone-wrapper"><input type="text" name="phone_number" id="<?=$act?>-phone_number" placeholder="06 xx xx xx xx"></div>
          <?php if($act === 'add'): ?>
          <label style="display:flex;align-items:center;gap:.5rem;margin-top:.5rem;cursor:pointer;">
            <input type="checkbox" name="sim_vierge" id="<?=$act?>-sim_vierge" value="1"
              onchange="toggleSimVierge('<?=$act?>')"
              style="width:15px;height:15px;accent-color:var(--warning);cursor:pointer;flex-shrink:0;">
            <span style="font-size:.83rem;color:var(--warning);font-weight:600;"><i class="bi bi-box-seam"></i> SIM vierge</span>
            <span style="font-size:.78rem;color:var(--text3);">— pas de numéro pour le moment</span>
          </label>
          <?php endif; ?>
        </div>
        <div class="form-group"><label>Utilisateur affecté</label><div style="position:relative;">
          <input type="text" id="<?=$act?>-agent_search" placeholder="🔎 Nom, prénom ou e-mail (vide = aucun)" autocomplete="off">
          <input type="hidden" name="agent_id" id="<?=$act?>-agent_id">
          <div class="adp-box" id="<?=$act?>-agent_suggest"></div>
        </div></div>
        <div class="form-group"><label>Compte de Facturation</label><div class="qa-row"><select name="billing_id" id="<?=$act?>-billing_id"><option value="">-- Sélectionner --</option><?php foreach($billings as $b): ?><option value="<?=$b['id']?>"><?=h($b['account_number'].' - '.$b['name'])?></option><?php endforeach; ?></select><button type="button" class="btn-quickadd" onclick="quickAddOpen('billing','<?=$act?>-billing_id')" title="Ajouter un compte de facturation"><i class="bi bi-plus-lg"></i></button></div></div>
        <div class="form-group"><label>Forfait</label><div class="qa-row"><select name="plan_id" id="<?=$act?>-plan_id"><option value="">-- Sélectionner --</option><?php foreach($plans as $p): ?><option value="<?=$p['id']?>"><?= $p['operator_name'] ? h($p['operator_name']).' — ' : '' ?><?=h($p['name'])?></option><?php endforeach; ?></select><button type="button" class="btn-quickadd" onclick="quickAddOpen('plan','<?=$act?>-plan_id')" title="Ajouter un forfait"><i class="bi bi-plus-lg"></i></button></div></div>
        <div class="form-group"><label>Service / Direction</label><div class="qa-row"><select name="service_id" id="<?=$act?>-service_id"><option value="">-- Sélectionner --</option><?php foreach($services as $s): ?><option value="<?=$s['id']?>"><?=h($s['name'])?></option><?php endforeach; ?></select><button type="button" class="btn-quickadd" onclick="quickAddOpen('service','<?=$act?>-service_id')" title="Ajouter un service"><i class="bi bi-plus-lg"></i></button></div></div>
        <div class="form-group"><label>Statut de la ligne</label>
          <div id="<?=$act?>-status-wrapper" style="position:relative;">
            <select name="status" id="<?=$act?>-status"><option value="Active">Active</option><option value="Stock">En Stock (Non activée)</option><option value="Suspended">Suspendue</option></select>
          </div>
        </div>
        <div class="form-group form-full"><label style="color:var(--primary)"><i class="bi bi-sim"></i> Informations SIM</label><hr style="border:0;border-top:1px solid var(--border);margin-top:-5px"></div>
        <div class="form-group form-full">
          <label style="display:flex;align-items:center;gap:.5rem;cursor:pointer;">
            <input type="checkbox" name="esim" id="<?=$act?>-esim" value="1"
              onchange="toggleEsim('<?=$act?>')"
              style="width:15px;height:15px;accent-color:#a78bfa;cursor:pointer;flex-shrink:0;">
            <span style="font-size:.83rem;color:#a78bfa;font-weight:600;"><i class="bi bi-sim"></i> eSIM</span>
            <span style="font-size:.78rem;color:var(--text3);">— profil opérateur embarqué dans l'appareil</span>
          </label>
        </div>
        <div class="form-group"><label>N° SIM (ICCID)</label><input type="text" name="iccid" id="<?=$act?>-iccid" placeholder="893310..."></div>
        <div class="form-group"><div style="display:flex;gap:1rem;"><div style="flex:1"><label>Code PIN</label><input type="text" name="pin" id="<?=$act?>-pin"></div><div style="flex:1"><label>Code PUK</label><input type="text" name="puk" id="<?=$act?>-puk"></div></div></div>
        <!-- Codes secondaires : renseignés par l'import depuis SFR (PIN 2 / PUK 2), modifiables ici -->
        <div class="form-group"><div style="display:flex;gap:1rem;"><div style="flex:1"><label>Code PIN 2</label><input type="text" name="pin2" id="<?=$act?>-pin2"></div><div style="flex:1"><label>Code PUK 2</label><input type="text" name="puk2" id="<?=$act?>-puk2"></div></div></div>
        <div class="form-group"><label>RIO <span style="font-weight:400;text-transform:none;">(portabilité)</span></label><input type="text" name="rio" id="<?=$act?>-rio" maxlength="20"></div>
        <!-- Champs spécifiques eSIM (masqués par défaut) -->
        <div class="form-group" id="<?=$act?>-esim-fields" style="display:none;">
          <label>EID <span style="color:var(--text3);font-weight:400;text-transform:none;">(identifiant du composant eSIM, propre à l'appareil)</span></label>
          <input type="text" name="eid" id="<?=$act?>-eid" placeholder="89049032...">
        </div>
        <div class="form-group form-full" id="<?=$act?>-esim-code" style="display:none;">
          <label>Code d'activation opérateur <span style="color:var(--text3);font-weight:400;text-transform:none;">(QR code ou code alphanumérique)</span></label>
          <textarea name="activation_code" id="<?=$act?>-activation_code" rows="2" placeholder="LPA:1$..."></textarea>
        </div>
        <div class="form-group form-full"><label style="color:var(--primary)"><i class="bi bi-phone"></i> Matériel & Notes</label><hr style="border:0;border-top:1px solid var(--border);margin-top:-5px"></div>
        <div class="form-group form-full">
          <label style="display:flex;align-items:center;gap:.6rem;cursor:pointer;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.7rem 1rem;">
            <input type="checkbox" name="personal_device" id="<?=$act?>-personal_device" value="1"
              onchange="togglePersonalDevice('<?=$act?>')"
              style="width:16px;height:16px;accent-color:var(--info);cursor:pointer;flex-shrink:0;">
            <span>
              <strong style="color:var(--info);"><i class="bi bi-phone"></i> Téléphone personnel</strong>
              <span style="color:var(--text3);font-size:.82rem;margin-left:.4rem;">— L'agent utilise son propre appareil (BYOD)</span>
            </span>
          </label>
        </div>
        <div class="form-group" id="<?=$act?>-device-wrapper">
          <label>Téléphone associé</label>
          <select name="device_id" id="<?=$act?>-device_id">
            <option value="">-- Actuellement aucun ou Conserver le même --</option>
            <?php foreach($devices as $d): ?><option value="<?=$d['id']?>"><?=h($d['brand'].' '.$d['name'].' (S/N: '.($d['serial_number']?:$d['imei']).')')?></option><?php endforeach; ?>
          </select>
        </div>
        <div class="form-group"><label>Date d'activation</label><input type="date" name="activation_date" id="<?=$act?>-activation_date"></div>
        <div class="form-group form-full"><label>Options / Détails forfait</label><textarea name="options_details" id="<?=$act?>-options_details" rows="2" placeholder="Ex: Option international, roaming..."></textarea></div>
        <div class="form-group form-full"><label>Notes internes</label><textarea name="notes" id="<?=$act?>-notes" rows="2"></textarea></div>
      </div>
      <div class="modal-footer"><button type="button" class="btn-secondary" onclick="closeModal('modal-<?=$act?>-line')">Annuler</button><button type="submit" class="btn-primary">Enregistrer</button></div>
      </form></div>
    </div>
    <?php endforeach;

    // ── MODAL : CHANGER LA SIM ──────────────────────────────────
    ?>
    <div class="modal-overlay" id="modal-sim-swap">
      <div class="modal"><div class="modal-header">
        <h3><i class="bi bi-arrow-repeat"></i> Changement de Carte SIM</h3>
        <button type="button" class="modal-close" onclick="closeModal('modal-sim-swap')"><i class="bi bi-x-lg"></i></button>
      </div>
      <form method="post" style="padding:1.5rem;">
        <input type="hidden" name="_entity" value="sim_swap">
        <input type="hidden" name="_action" value="swap">
        <input type="hidden" name="line_id" id="swap-line-id">
        <input type="hidden" name="stock_sim_id" id="swap-stock-sim-id">

        <!-- Récapitulatif de la ligne -->
        <div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:1rem;margin-bottom:1.5rem;">
          <div style="font-size:.78rem;font-weight:600;color:var(--text3);text-transform:uppercase;margin-bottom:.5rem;">Ligne concernée</div>
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem;">
            <div>
              <strong id="swap-phone" style="font-family:var(--font-mono);font-size:1.1rem;color:var(--primary)"></strong>
              <span id="swap-esim-badge" style="display:none;background:rgba(139,92,246,.15);color:#a78bfa;font-size:.72rem;font-weight:600;padding:.15rem .5rem;border-radius:999px;margin-left:8px;"><i class="bi bi-sim"></i> eSIM</span>
            </div>
            <span style="font-size:.82rem;color:var(--text2);">SIM actuelle : <code id="swap-old-iccid" style="color:var(--warning)"></code></span>
          </div>
        </div>

        <!-- Bouton pour voir l'historique SIM de cette ligne -->
        <div style="text-align:right;margin-bottom:1.25rem;">
          <button type="button" onclick="loadSimHistory()" style="background:none;border:none;color:var(--primary);font-size:.83rem;cursor:pointer;text-decoration:underline;"><i class="bi bi-clock-history"></i> Voir l'historique des SIM précédentes</button>
        </div>
        <div id="sim-history-panel" style="display:none;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:1rem;margin-bottom:1.5rem;max-height:180px;overflow-y:auto;"></div>

        <div class="form-grid">
          <div class="form-group form-full">
            <label>Motif du changement *</label>
            <select name="reason" required style="">
              <option value="">-- Sélectionner --</option>
              <option value="Perte du téléphone">📵 Perte du téléphone</option>
              <option value="Vol du téléphone">🚨 Vol du téléphone</option>
              <option value="Casse du téléphone">💥 Casse du téléphone</option>
              <option value="SIM défectueuse">⚠️ SIM défectueuse</option>
              <option value="Changement de format SIM">📐 Changement de format SIM</option>
              <option value="Migration eSIM">📲 Migration eSIM</option>
              <option value="Autre">✏️ Autre</option>
            </select>
          </div>

          <div class="form-group form-full">
            <label>Choisir une SIM en stock</label>
            <select id="swap-sim-stock" onchange="fillSwapFromStock(this)">
              <option value="">-- <?= count($simStock) > 0 ? count($simStock).' SIM(s) disponible(s) en stock' : 'Aucune SIM en stock' ?> --</option>
              <?php foreach($simStock as $sv): ?>
              <option value="<?=h($sv['iccid'])?>"
                data-pin="<?=h($sv['pin'])?>"
                data-puk="<?=h($sv['puk'])?>"
                data-id="<?=$sv['id']?>"
                data-esim="<?=!empty($sv['esim'])?'1':'0'?>">
                <?= !empty($sv['esim']) ? '📲 SIM vierge eSIM' : '💳 SIM vierge' ?>
                <?= $sv['iccid'] ? ' — IMEI: '.h($sv['iccid']) : ' — Sans IMEI' ?>
                <?= $sv['pin'] ? ' — PIN: '.$sv['pin'] : '' ?>
              </option>
              <?php endforeach; ?>
            </select>
          </div>

          <div id="swap-manual-iccid-sep" class="form-group form-full" style="border-top:1px solid var(--border);padding-top:1rem;margin-top:-.25rem;">
            <label style="color:var(--text3);">— ou saisir manuellement l'IMEI / ICCID —</label>
          </div>

          <div class="form-group form-full" id="swap-iccid-row">
            <label>Nouvel IMEI / ICCID *</label>
            <input type="text" name="new_iccid" id="swap-new-iccid" placeholder="893310..." required>
          </div>
          <div class="form-group">
            <label>Nouveau code PIN</label>
            <input type="text" name="new_pin" id="swap-new-pin" placeholder="0000">
          </div>
          <div class="form-group">
            <label>Nouveau code PUK</label>
            <input type="text" name="new_puk" id="swap-new-puk" placeholder="12345678">
          </div>
          <div class="form-group form-full" id="swap-eid-row" style="display:none;">
            <label>Nouvel EID <span style="color:var(--text3);font-weight:400;text-transform:none;">(si l'appareil change)</span></label>
            <input type="text" name="new_eid" id="swap-new-eid" placeholder="89049032...">
          </div>
          <div class="form-group form-full" id="swap-code-row" style="display:none;">
            <label>Nouveau code d'activation opérateur</label>
            <textarea name="new_activation_code" id="swap-new-code" rows="2" placeholder="LPA:1$..."></textarea>
          </div>
        </div>

        <div style="background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.3);border-radius:var(--radius-sm);padding:.85rem 1rem;margin-top:.5rem;font-size:.85rem;color:var(--warning);">
          ⚠️ L'ancien IMEI/ICCID <strong id="swap-old-iccid-confirm"></strong> sera archivé dans l'historique. Cette action est irréversible.
        </div>

        <div class="modal-footer">
          <button type="button" class="btn-secondary" onclick="closeModal('modal-sim-swap')">Annuler</button>
          <button type="submit" class="btn-primary"><i class="bi bi-arrow-repeat"></i> Confirmer le changement</button>
        </div>
      </form></div>
    </div>

    <!-- Modal archivage ligne -->
    <div class="modal-overlay" id="modal-archive-line">
      <div class="modal" style="max-width:480px;">
        <div class="modal-header"><h3><i class="bi bi-archive"></i> Archiver / Résilier une ligne</h3><button type="button" class="modal-close" onclick="closeModal('modal-archive-line')"><i class="bi bi-x-lg"></i></button></div>
        <form method="post" style="padding:1.5rem;">
          <input type="hidden" name="_entity" value="line">
          <input type="hidden" name="_action" value="archive">
          <input type="hidden" name="_id" id="archive-line-id">
          <input type="hidden" name="archive_also_device_id" id="archive-line-device-id">
          <div class="form-grid">
            <div class="form-group form-full">
              <label>Motif *</label>
              <select name="archive_reason" required>
                <option value="">-- Sélectionner --</option>
                <option value="Perte">📵 Perte du téléphone / SIM</option>
                <option value="HS">⚠️ Hors service / Dysfonctionnement</option>
                <option value="Résiliation">✂️ Résiliation du contrat</option>
                <option value="Départ agent">👤 Départ de l'agent</option>
              </select>
            </div>
            <div class="form-group form-full">
              <label>Commentaire <span style="font-weight:400;text-transform:none;">(optionnel)</span></label>
              <textarea name="archive_comment" rows="2" placeholder="Informations complémentaires..."></textarea>
            </div>
            <!-- Section téléphone associé (affichée si un device est lié) -->
            <div id="archive-line-device-section" class="form-group form-full" style="display:none;">
              <label style="display:flex;align-items:center;gap:.6rem;cursor:pointer;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.75rem 1rem;text-transform:none;font-size:.88rem;font-weight:400;">
                <input type="checkbox" name="archive_also_device" id="archive-line-also-device" value="1" style="width:15px;height:15px;accent-color:var(--danger);flex-shrink:0;">
                <span>
                  <strong style="color:var(--text);font-size:.9rem;">Archiver aussi le téléphone associé</strong>
                  <span id="archive-line-device-label" style="display:block;color:var(--text2);font-size:.82rem;margin-top:.15rem;"></span>
                </span>
              </label>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn-secondary" onclick="closeModal('modal-archive-line')">Annuler</button>
            <button type="submit" class="btn-primary" style="background:var(--danger);box-shadow:none;"><i class="bi bi-archive"></i> Archiver</button>
          </div>
        </form>
      </div>
    </div>
    <?php
}

// ==================================================================
// VUE : MATERIELS / DEVICES (Déployés / Stock / Archives)
// ==================================================================
elseif ($page === 'devices') {
    $isArchive = ($tab === 'archive'); $isStock = ($tab === 'stock');
    $where = "d.archived=" . ($isArchive ? "1" : "0");
    if ($isStock) $where .= " AND d.status='Stock'"; elseif (!$isArchive) $where .= " AND d.status!='Stock'";

    $devices = $pdo->query("SELECT d.id, d.imei, d.imei2, d.serial_number, d.inventory_label, d.model_id, d.status, d.agent_id, d.service_id, d.purchase_date, d.notes, d.archived, d.created_at, a.first_name, a.last_name, s.name as service_name, m.brand, m.name as model_name, m.category,
        (SELECT id FROM mobile_lines WHERE device_id=d.id AND archived=0 LIMIT 1) as line_id,
        (SELECT phone_number FROM mobile_lines WHERE device_id=d.id AND archived=0 LIMIT 1) as line_phone
        FROM devices d LEFT JOIN agents a ON d.agent_id=a.id LEFT JOIN services s ON d.service_id=s.id LEFT JOIN models m ON d.model_id=m.id WHERE $where ORDER BY d.created_at DESC")->fetchAll();
    
    $models = $pdo->query("SELECT id, brand, name FROM models ORDER BY brand, name")->fetchAll();
    $services = $pdo->query("SELECT id, name FROM services ORDER BY name")->fetchAll();
    ?>
    <?php if(!$isArchive): ?>
    <div class="page-header">
      <button class="btn-primary" onclick="openModal('modal-add-device')">+ Ajouter un équipement</button>
    </div>
    <?php endif; ?>

    <div style="display:flex; gap:10px; margin-bottom:1rem; border-bottom:2px solid var(--border)">
        <a href="?page=devices&tab=active" class="tab-btn <?=$tab==='active'?'active':''?>"><i class="bi bi-phone"></i> Matériels Déployés / Réparation</a>
        <a href="?page=devices&tab=stock" class="tab-btn <?=$tab==='stock'?'active':''?>"><i class="bi bi-box-seam"></i> Stock (Disponibles)</a>
        <a href="?page=devices&tab=archive" class="tab-btn <?=$tab==='archive'?'active':''?>"><i class="bi bi-archive"></i> Archives (Perdus / Cassés)</a>
    </div>

    <div class="search-bar-wrap">
      <div class="search-bar"><span class="search-bar-icon"><i class="bi bi-search"></i></span><input type="text" placeholder="Rechercher IMEI, Modèle, Agent..." oninput="tableSearch(this,'tbody-dev','count')"></div>
      <div class="search-count" id="count"></div>
    </div>

    <!-- BARRE D'ACTIONS EN MASSE MATÉRIELS -->
    <div id="bulk-bar-device" style="display:none;align-items:center;gap:1rem;background:var(--primary-dim);border:1px solid var(--border2);border-radius:var(--radius-sm);padding:.75rem 1.25rem;margin-bottom:1rem;flex-wrap:wrap;">
      <span id="bulk-count-device" style="font-weight:700;color:var(--primary);min-width:130px;"></span>
      <form method="post" id="bulk-form-device" style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:center;">
        <input type="hidden" name="_entity" value="bulk">
        <input type="hidden" name="bulk_type" value="device">
        <div id="bulk-ids-device"></div>
        <select name="bulk_action" style="padding:.45rem .75rem;background:var(--card2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:.88rem;">
          <option value="">-- Choisir une action --</option>
          <?php if(!$isArchive): ?><option value="archive">🗄️ Archiver la sélection</option><?php endif; ?>
          <?php if($isArchive): ?><option value="restore">♻️ Restaurer la sélection</option><?php endif; ?>
        </select>
        <button type="button" class="btn-primary" style="padding:.45rem 1rem;font-size:.88rem;" onclick="submitBulk('device')">Appliquer</button>
        <button type="button" class="btn-secondary" style="padding:.45rem .75rem;font-size:.88rem;" onclick="clearBulk('device')"><i class="bi bi-x-lg"></i> Annuler</button>
      </form>
    </div>

    <div class="card" style="overflow-x:auto;">
      <table class="data-table">
        <thead><tr>
          <th style="width:36px;cursor:default;"><input type="checkbox" id="chk-all-device" title="Tout sélectionner" onchange="toggleAllBulk('device',this.checked)" style="cursor:pointer;accent-color:var(--primary);width:15px;height:15px;"></th>
          <th>Modèle</th><th>Type</th><th>Identifiants</th><th>Affectation</th><th>Statut</th><th>Date d'achat</th><th>Actions</th></tr></thead>
        <tbody id="tbody-dev">
        <?php if(empty($devices)): ?><tr><td colspan="8" class="empty-cell">Aucun équipement dans cet onglet</td></tr><?php endif; ?>
        <?php foreach($devices as $d): ?>
        <tr>
          <td><input type="checkbox" class="bulk-chk-device" value="<?=$d['id']?>" onchange="updateBulkBar('device')" style="cursor:pointer;accent-color:var(--primary);width:15px;height:15px;"></td>
          <td><strong><?=h($d['brand'].' '.$d['model_name'])?></strong></td>
          <td><span class="badge badge-muted"><?=h($d['category']?:'N/A')?></span></td>
          <td>IMEI: <code class="ref"><?=h($d['imei'])?></code><br><span class="muted">S/N: <?=h($d['serial_number']?:'-')?></span><?php if($d['inventory_label']): ?><br><span class="badge badge-muted" style="font-size:.68rem;"><i class="bi bi-tag"></i> <?=h($d['inventory_label'])?></span><?php endif; ?></td>
          <td><?php if($d['agent_id']): ?><strong class="cell-link" onclick="viewAgent(<?=$d['agent_id']?>, '<?=h(addslashes($d['first_name'].' '.$d['last_name']))?>')" title="Ouvrir la fiche utilisateur"><?=h($d['first_name'].' '.$d['last_name'])?></strong><?php else: ?><strong class="muted">Non affecté</strong><?php endif; ?><br><span class="muted"><i class="bi bi-building"></i> <?=h($d['service_name']?:'-')?></span></td>
          <td><?=statusBadge($d['status'])?></td>
          <td><?=$d['purchase_date']?date('d/m/Y',strtotime($d['purchase_date'])):'-'?></td>
          <td class="actions">
            <?php $hist = fetchEntityHistory($pdo, 'device', $d['id']); ?>
            <?php if(!$isArchive): ?>
                <button class="btn-icon btn-edit" title="Modifier" onclick='openEditModal(<?=json_encode($d, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>,"device")'><i class="bi bi-pencil"></i></button>
                <button class="btn-icon" title="Historique de ce matériel" onclick='showHistory(<?=json_encode($hist, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>)'><i class="bi bi-clock-history"></i></button>
                <button type="button" class="btn-icon btn-del" title="Archiver (Casse, Perte...)" onclick="openArchiveDevice(<?=$d['id']?>, <?=(int)$d['line_id']?>, <?=json_encode($d['line_id'] ? formatPhone($d['line_phone']) : '')?>)"><i class="bi bi-archive"></i></button>
            <?php else: ?>
                <button class="btn-icon" title="Historique de ce matériel" onclick='showHistory(<?=json_encode($hist, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>)'><i class="bi bi-clock-history"></i></button>
                <form method="post" style="display:inline"><input type="hidden" name="_entity" value="device"><input type="hidden" name="_action" value="restore"><input type="hidden" name="_id" value="<?=$d['id']?>"><button type="submit" class="btn-icon" title="Restaurer au Stock" style="color:var(--success)"><i class="bi bi-arrow-counterclockwise"></i></button></form>
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>

    <!-- Modal archivage matériel -->
    <div class="modal-overlay" id="modal-archive-device">
      <div class="modal" style="max-width:480px;">
        <div class="modal-header"><h3><i class="bi bi-archive"></i> Archiver un matériel</h3><button type="button" class="modal-close" onclick="closeModal('modal-archive-device')"><i class="bi bi-x-lg"></i></button></div>
        <form method="post" style="padding:1.5rem;">
          <input type="hidden" name="_entity" value="device">
          <input type="hidden" name="_action" value="archive">
          <input type="hidden" name="_id" id="archive-device-id">
          <input type="hidden" name="archive_also_line_id" id="archive-device-line-id">
          <div class="form-grid">
            <div class="form-group form-full">
              <label>Motif de l'archivage *</label>
              <select name="archive_reason" required>
                <option value="">-- Sélectionner --</option>
                <option value="Perdu">📵 Perdu</option>
                <option value="Volé">🚨 Volé</option>
                <option value="Cassé">💥 Cassé / HS</option>
                <option value="Obsolète">⚡ Obsolète / Réformé</option>
              </select>
            </div>
            <div class="form-group form-full">
              <label>Commentaire <span style="font-weight:400;text-transform:none;">(optionnel)</span></label>
              <textarea name="archive_comment" rows="2" placeholder="Informations complémentaires..."></textarea>
            </div>
            <!-- Section ligne associée (affichée si une ligne est liée) -->
            <div id="archive-device-line-section" class="form-group form-full" style="display:none;">
              <label style="display:flex;align-items:center;gap:.6rem;cursor:pointer;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.75rem 1rem;text-transform:none;font-size:.88rem;font-weight:400;">
                <input type="checkbox" name="archive_also_line" id="archive-device-also-line" value="1" style="width:15px;height:15px;accent-color:var(--danger);flex-shrink:0;">
                <span>
                  <strong style="color:var(--text);font-size:.9rem;">Archiver aussi la ligne associée</strong>
                  <span id="archive-device-line-label" style="display:block;color:var(--text2);font-size:.82rem;margin-top:.15rem;"></span>
                </span>
              </label>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn-secondary" onclick="closeModal('modal-archive-device')">Annuler</button>
            <button type="submit" class="btn-primary" style="background:var(--danger);box-shadow:none;"><i class="bi bi-archive"></i> Archiver</button>
          </div>
        </form>
      </div>
    </div>

    <?php foreach(['add'=>'Ajouter', 'edit'=>'Modifier'] as $act => $title): ?>
    <div class="modal-overlay" id="modal-<?=$act?>-device">
      <div class="modal"><div class="modal-header"><h3><?=$title?> un Matériel</h3><button type="button" class="modal-close" onclick="closeModal('modal-<?=$act?>-device')"><i class="bi bi-x-lg"></i></button></div>
      <form method="post" onsubmit="return deviceFormCheck('<?=$act?>')"><input type="hidden" name="_entity" value="device"><input type="hidden" name="_action" value="<?=$act?>"><?php if($act==='edit') echo '<input type="hidden" name="_id" id="edit-id-device">'; ?>
      <div class="form-grid">
        <div class="form-group form-full"><label>Modèle *</label>
          <div class="qa-row">
          <select name="model_id" id="<?=$act?>-model_id" required><option value="">-- Choisir le modèle --</option>
          <?php foreach($models as $m): ?><option value="<?=$m['id']?>"><?=h($m['brand'].' '.$m['name'])?></option><?php endforeach; ?></select>
          <button type="button" class="btn-quickadd" onclick="quickAddOpen('model','<?=$act?>-model_id')" title="Ajouter un modèle"><i class="bi bi-plus-lg"></i></button>
          </div>
        </div>
        <div class="form-group"><label>IMEI 1 *</label><input type="text" name="imei" id="<?=$act?>-imei" required></div>
        <div class="form-group"><label>IMEI 2</label><input type="text" name="imei2" id="<?=$act?>-imei2"></div>
        <div class="form-group"><label>Numéro de série</label><input type="text" name="serial_number" id="<?=$act?>-serial_number"></div>
        <div class="form-group"><label><i class="bi bi-tag"></i> Libellé d'inventaire</label><input type="text" name="inventory_label" id="<?=$act?>-inventory_label" placeholder="Ex: MOB-0042, IT-2024-001..."></div>
        <div class="form-group"><label>Date d'achat</label><input type="date" name="purchase_date" id="<?=$act?>-purchase_date"></div>
        <div class="form-group"><label>Statut</label>
          <select name="status" id="<?=$act?>-status"><option value="Stock">En Stock</option><option value="Deployed">Déployé</option><option value="Repair">En réparation</option></select>
        </div>
        <div class="form-group"><label>Utilisateur (Agent)</label>
          <div style="position:relative;">
            <input type="text" id="<?=$act?>-agent_search" placeholder="🔎 Nom, prénom ou e-mail (vide = aucun)" autocomplete="off">
            <input type="hidden" name="agent_id" id="<?=$act?>-agent_id">
            <div class="adp-box" id="<?=$act?>-agent_suggest"></div>
          </div>
        </div>
        <div class="form-group form-full"><label>Service</label>
          <div class="qa-row">
          <select name="service_id" id="<?=$act?>-service_id"><option value="">-- Sélectionner --</option>
          <?php foreach($services as $s): ?><option value="<?=$s['id']?>"><?=h($s['name'])?></option><?php endforeach; ?></select>
          <button type="button" class="btn-quickadd" onclick="quickAddOpen('service','<?=$act?>-service_id')" title="Ajouter un service"><i class="bi bi-plus-lg"></i></button>
          </div>
        </div>
        <div class="form-group form-full"><label>Notes</label><textarea name="notes" id="<?=$act?>-notes" rows="2"></textarea></div>
      </div>
      <div class="modal-footer"><button type="button" class="btn-secondary" onclick="closeModal('modal-<?=$act?>-device')">Annuler</button><button type="submit" class="btn-primary">Enregistrer</button></div>
      </form></div>
    </div>
    <?php endforeach;
}

// ==================================================================
// VUE : PARC PAR MARQUE ET MODÈLE (synthèse cliquable depuis les graphiques)
// ==================================================================
elseif ($page === 'brands') {
    $bmRows = $pdo->query("SELECT IFNULL(m.brand,'(sans modèle)') brand, IFNULL(m.name,'—') model,
            IFNULL(m.category,'') category, COUNT(*) total,
            SUM(d.status='Deployed') deployed, SUM(d.status='Stock') stock, SUM(d.status='Repair') repair
        FROM devices d LEFT JOIN models m ON d.model_id=m.id
        WHERE d.archived=0
        GROUP BY brand, model, category
        ORDER BY brand, total DESC, model")->fetchAll();
    // Regroupement par marque, avec sous-totaux.
    $byBrand = [];
    foreach ($bmRows as $r) $byBrand[$r['brand']][] = $r;
    uasort($byBrand, fn($a, $b) => array_sum(array_column($b, 'total')) <=> array_sum(array_column($a, 'total')));
    $gTot = array_sum(array_column($bmRows, 'total'));
    ?>
    <p class="muted" style="margin-bottom:1rem;font-size:.85rem;"><i class="bi bi-info-circle"></i>
      Matériels <strong>actifs</strong> (archives exclues), regroupés par marque puis modèle.
      Cliquez sur un modèle pour ouvrir la liste des matériels correspondants ; cette page s'ouvre
      pré-filtrée depuis les graphiques « Répartition par marque » du tableau de bord et des statistiques.</p>
    <div class="search-bar-wrap">
      <div class="search-bar"><span class="search-bar-icon"><i class="bi bi-search"></i></span><input type="text" placeholder="Filtrer par marque, modèle, catégorie..." oninput="tableSearch(this,'tbody-brands','count-brands')"></div>
      <div class="search-count" id="count-brands"></div>
    </div>
    <div class="card" style="overflow-x:auto;">
      <table class="data-table" style="font-size:.87rem;">
        <thead><tr><th>Marque</th><th>Modèle</th><th>Catégorie</th>
          <th style="text-align:right;">Déployés</th><th style="text-align:right;">En stock</th>
          <th style="text-align:right;">Réparation</th><th style="text-align:right;">Total</th><th style="width:50px;"></th></tr></thead>
        <tbody id="tbody-brands">
        <?php if(!$bmRows): ?><tr><td colspan="8" class="empty-cell">Aucun matériel actif au parc</td></tr><?php endif; ?>
        <?php foreach($byBrand as $brand => $models): ?>
          <tr style="background:var(--primary-dim);font-weight:700;">
            <td><?=h($brand)?></td>
            <td class="muted" style="font-weight:400;"><?=count($models)?> modèle(s)</td>
            <td></td>
            <td style="text-align:right;"><?=array_sum(array_column($models,'deployed'))?></td>
            <td style="text-align:right;"><?=array_sum(array_column($models,'stock'))?></td>
            <td style="text-align:right;"><?=array_sum(array_column($models,'repair'))?></td>
            <td style="text-align:right;"><?=array_sum(array_column($models,'total'))?></td>
            <td></td>
          </tr>
          <?php foreach($models as $m): ?>
          <tr>
            <td class="muted" style="font-size:.78rem;"><?=h($brand)?></td>
            <td><a href="?page=devices&q=<?=urlencode($m['model'] !== '—' ? $m['model'] : $brand)?>" title="Voir ces matériels dans le parc"><?=h($m['model'])?></a></td>
            <td class="muted"><?=h($m['category'] ?: '—')?></td>
            <td style="text-align:right;"><?=(int)$m['deployed'] ?: '—'?></td>
            <td style="text-align:right;"><?=(int)$m['stock'] ?: '—'?></td>
            <td style="text-align:right;"><?=(int)$m['repair'] ?: '—'?></td>
            <td style="text-align:right;font-weight:600;"><?=(int)$m['total']?></td>
            <td class="actions"><a class="btn-icon" href="?page=devices&q=<?=urlencode($m['model'] !== '—' ? $m['model'] : $brand)?>" title="Voir dans le parc matériel" style="text-decoration:none;"><i class="bi bi-box-arrow-up-right"></i></a></td>
          </tr>
          <?php endforeach; ?>
        <?php endforeach; ?>
        </tbody>
        <?php if($bmRows): ?>
        <tfoot><tr style="border-top:2px solid var(--border);font-weight:700;">
          <td colspan="3">Total du parc actif — <?=count($byBrand)?> marque(s), <?=count($bmRows)?> modèle(s)</td>
          <td style="text-align:right;"><?=array_sum(array_column($bmRows,'deployed'))?></td>
          <td style="text-align:right;"><?=array_sum(array_column($bmRows,'stock'))?></td>
          <td style="text-align:right;"><?=array_sum(array_column($bmRows,'repair'))?></td>
          <td style="text-align:right;"><?=$gTot?></td>
          <td></td>
        </tr></tfoot>
        <?php endif; ?>
      </table>
    </div>
    <?php
}

// ==================================================================
// VUE : FACTURATION / CONTRÔLE (factures opérateur)
// ==================================================================
elseif ($page === 'invoices') {
    $tab = in_array($tab, ['dash','import','reconcile','conso','alerts']) ? $tab : 'dash';

    // Formatteurs locaux : durées « 1h23 », volumes data « 2,4 Go ».
    $fmtDur = function(int $sec): string {
        if ($sec <= 0) return '—';
        $h = intdiv($sec, 3600); $m = intdiv($sec % 3600, 60);
        return $h > 0 ? sprintf('%dh%02d', $h, $m) : sprintf('%dmin', max(1, $m));
    };
    $fmtData = function(int $ko): string {
        if ($ko <= 0) return '—';
        if ($ko >= 1048576) return number_format($ko / 1048576, 1, ',', ' ') . ' Go';
        return number_format($ko / 1024, 0, ',', ' ') . ' Mo';
    };
    $fmtEur = fn($v) => number_format((float)$v, 2, ',', ' ') . ' €';
    $fmtMois = function(?string $mk): string {
        if (!$mk) return '—';
        $noms = [1=>'janv.',2=>'févr.',3=>'mars',4=>'avr.',5=>'mai',6=>'juin',7=>'juil.',8=>'août',9=>'sept.',10=>'oct.',11=>'nov.',12=>'déc.'];
        [$y, $m] = array_pad(explode('-', $mk), 2, 0);
        return ($noms[(int)$m] ?? '?') . ' ' . $y;
    };

    // ── COMPTE DE FACTURATION — second axe de filtrage de la page ──
    // Les comptes viennent des factures importées (le référentiel n'est pas
    // forcément renseigné) ; son libellé est repris quand il l'est.
    $accountRows = $pdo->query("SELECT i.billing_account acc, MAX(b.name) label, COUNT(*) nb
            FROM invoices i LEFT JOIN billing_accounts b ON REPLACE(b.account_number, ' ', '') = i.billing_account
            WHERE i.billing_account IS NOT NULL AND i.billing_account <> ''
            GROUP BY i.billing_account ORDER BY i.billing_account")->fetchAll();
    $accounts = [];
    foreach ($accountRows as $ar) $accounts[$ar['acc']] = $ar['label'] ?: '';
    $acct = (isset($_GET['acct']) && isset($accounts[$_GET['acct']])) ? (string)$_GET['acct'] : '';
    $acctLabel = $acct === '' ? 'tous les comptes' : ($accounts[$acct] ? "$acct — {$accounts[$acct]}" : $acct);

    // Le compte est recopié sur chaque ligne de détail (invoice_lines.
    // billing_account) : le filtre est donc un simple critère, sans jointure.
    $accWhere = $acct !== '' ? ' AND l.billing_account = ?' : '';
    $accArgs  = $acct !== '' ? [$acct] : [];
    $accQuery = function (string $sql, array $args = []) use ($pdo, $accArgs) {
        $st = $pdo->prepare($sql);
        $st->execute(array_merge($args, $accArgs));
        return $st;
    };

    // Mois disponibles (détail par ligne), pour le compte retenu.
    $months = $accQuery("SELECT DISTINCT l.month_key FROM invoice_lines l
            WHERE 1=1 $accWhere ORDER BY l.month_key DESC")->fetchAll(PDO::FETCH_COLUMN);

    // ── PÉRIODE D'ANALYSE — état commun à toute la page ──────────
    // Un seul couple de bornes (mois de départ / mois d'arrivée) pilote les
    // compteurs, les graphiques, les tops, le rapprochement et les alertes.
    // Le mois d'arrivée fait office de « mois courant » pour les vues qui ne
    // regardent qu'un mois (rapprochement, consommations, alertes).
    $monthly = $months ? $accQuery("SELECT l.month_key, SUM(l.total_ht) t, SUM(l.abo_ht) abo, SUM(l.conso_ht) conso,
                SUM(l.hf_ht) hf, SUM(l.surtaxe_ht) s, SUM(l.intl_ht) i, SUM(l.data_ko) ko,
                SUM(l.calls_seconds) secs, SUM(l.sms_count+l.mms_count) sms, COUNT(*) n
            FROM invoice_lines l WHERE 1=1 $accWhere
            GROUP BY l.month_key ORDER BY l.month_key")->fetchAll() : [];
    $byKey = [];
    foreach ($monthly as $mrow) $byKey[$mrow['month_key']] = $mrow;

    $firstKey = $monthly ? $monthly[0]['month_key'] : null;
    $lastKey  = $monthly ? end($monthly)['month_key'] : null;
    $axisFrom = $axisTo = null;
    $axis = $axisLabels = $axisData = $axisNb = [];
    $periodLabel = '—'; $axisGaps = 0;
    if ($monthly) {
        $bound = fn(?string $v, string $def) => ($v !== null && preg_match('/^\d{4}-(0[1-9]|1[0-2])$/', $v)
                                                 && $v >= $firstKey && $v <= $lastKey) ? $v : $def;
        $axisTo   = $bound($_GET['to']   ?? null, $lastKey);
        $axisFrom = $bound($_GET['from'] ?? null, max($firstKey, date('Y-m', strtotime("$axisTo-01 -11 months"))));
        if ($axisFrom > $axisTo) [$axisFrom, $axisTo] = [$axisTo, $axisFrom];   // bornes inversées

        // Axe des mois CONTINU : un point par mois, y compris ceux sans facture
        // importée. Un mois manquant doit se lire comme une interruption du
        // tracé, jamais comme un mois à 0 € — ce serait un contresens (c'est
        // aussi le signal « il me manque une facture »).
        for ($k = $axisFrom; $k <= $axisTo && count($axis) < 240; $k = date('Y-m', strtotime("$k-01 +1 month"))) $axis[] = $k;

        // Étiquettes sur deux lignes : le mois, et l'année seulement au début,
        // à la fin et à chaque janvier (présentation de la synthèse du parc).
        foreach ($axis as $i => $k) {
            $showYear = $i === 0 || $i === count($axis) - 1 || substr($k, 5, 2) === '01';
            $mois = explode(' ', $fmtMois($k))[0];
            $axisLabels[] = $showYear ? [$mois, substr($k, 0, 4)] : [$mois];
        }
        $axisData = array_map(fn($k) => isset($byKey[$k]) ? round((float)$byKey[$k]['t'], 2) : null, $axis);
        $axisNb   = array_map(fn($k) => isset($byKey[$k]) ? (int)$byKey[$k]['n'] : null, $axis);

        $monthsInPeriod = array_values(array_filter(array_map(fn($k) => $byKey[$k] ?? null, $axis)));
        $periodLabel = $axisFrom === $axisTo ? $fmtMois($axisFrom)
                                            : $fmtMois($axisFrom) . ' → ' . $fmtMois($axisTo);
        $axisGaps    = count($axis) - count($monthsInPeriod);
    }
    $selMonth = $axisTo;                       // mois de référence des vues mensuelles
    $qsPeriod = 'from=' . urlencode((string)$axisFrom) . '&to=' . urlencode((string)$axisTo)
              . ($acct !== '' ? '&acct=' . urlencode($acct) : '');

    // Barre de filtres commune aux onglets : période + compte de facturation.
    // $extra conserve les paramètres propres à un onglet (critère du top, statut…).
    $periodPicker = function(string $forTab, array $extra = []) use ($months, $axisFrom, $axisTo, $firstKey, $lastKey, $fmtMois, $accounts, $acct) {
        $asc = array_reverse($months);
        $keep = $extra + ['page' => 'invoices', 'tab' => $forTab];
        ob_start(); ?>
        <form method="get" style="display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem;">
          <input type="hidden" name="page" value="invoices"><input type="hidden" name="tab" value="<?=h($forTab)?>">
          <?php foreach($extra as $k => $v): ?><input type="hidden" name="<?=h($k)?>" value="<?=h((string)$v)?>"><?php endforeach; ?>
          <label style="margin:0;">Période — de</label>
          <select name="from" onchange="this.form.submit()" style="width:auto;">
            <?php foreach($asc as $mk): ?><option value="<?=h($mk)?>" <?=$mk===$axisFrom?'selected':''?>><?=h($fmtMois($mk))?></option><?php endforeach; ?>
          </select>
          <label style="margin:0;">à</label>
          <select name="to" onchange="this.form.submit()" style="width:auto;">
            <?php foreach($asc as $mk): ?><option value="<?=h($mk)?>" <?=$mk===$axisTo?'selected':''?>><?=h($fmtMois($mk))?></option><?php endforeach; ?>
          </select>
          <?php if(count($accounts) > 1): ?>
          <label style="margin:0 0 0 .75rem;">Compte de facturation</label>
          <select name="acct" onchange="this.form.submit()" style="width:auto;">
            <option value="">Tous les comptes</option>
            <?php foreach($accounts as $a => $lbl): ?>
            <option value="<?=h($a)?>" <?=$a===$acct?'selected':''?>><?=h($a . ($lbl ? " — $lbl" : ''))?></option>
            <?php endforeach; ?>
          </select>
          <?php endif; ?>
          <?php if($axisFrom !== $firstKey || $axisTo !== $lastKey || $acct !== ''): ?>
          <a href="?<?=h(http_build_query($keep + ['from' => (string)$firstKey, 'to' => (string)$lastKey]))?>"
             class="muted" style="font-size:.8rem;white-space:nowrap;" title="Tout l'historique, tous les comptes"><i class="bi bi-arrows-angle-expand"></i> tout réinitialiser</a>
          <?php endif; ?>
        </form>
        <?php return ob_get_clean();
    };

    // Lignes du référentiel indexées par numéro (rapprochement / affichage).
    // « acct » = compte de facturation du référentiel, pour pouvoir restreindre
    // le rapprochement au même compte que la facture.
    // Clé = numéro CANONIQUE (simcity_phone_canon, +33 compris) : la même
    // normalisation que le SQL de l'onglet Consommations — sinon une ligne
    // saisie « +33 6… » est reconnue dans un onglet et « hors SimCity » dans
    // les autres. À numéro égal, la ligne active écrase l'archivée.
    $appLines = [];
    foreach ($pdo->query("SELECT l.phone_number, l.archived, l.status, l.agent_id, COALESCE(l.sim_vierge,0) sim_vierge,
            IFNULL(a.first_name,'') fn, IFNULL(a.last_name,'') ln, IFNULL(s.name,'') service_name,
            REPLACE(IFNULL(b.account_number,''), ' ', '') acct
        FROM mobile_lines l LEFT JOIN agents a ON l.agent_id=a.id LEFT JOIN services s ON l.service_id=s.id
             LEFT JOIN billing_accounts b ON l.billing_id=b.id
        WHERE l.phone_number IS NOT NULL AND l.phone_number != ''
        ORDER BY l.archived DESC, l.id") as $al) {
        $appLines[simcity_phone_canon($al['phone_number'])] = $al;
    }

    // Seuils d'alerte.
    $thr = [
        'var_pct'     => (float)getSetting($pdo, 'inv_alert_var_pct', 50),
        'var_min_eur' => (float)getSetting($pdo, 'inv_alert_var_min_eur', 1),
        'zero_months' => max(1, (int)getSetting($pdo, 'inv_alert_zero_months', 2)),
        'hf_eur'      => (float)getSetting($pdo, 'inv_alert_hf_eur', 5),
        'intl_eur'    => (float)getSetting($pdo, 'inv_alert_intl_eur', 1),
        'surtaxe_eur' => (float)getSetting($pdo, 'inv_alert_surtaxe_eur', 1),
        'remise_pct'  => (float)getSetting($pdo, 'inv_alert_remise_pct', 90),
    ];

    // ── Calcul des alertes (à la volée, sur le mois d'arrivée de la période) ──
    // Chaque alerte porte un « impact » en € HT/mois : c'est lui qui permet de
    // trier et de totaliser l'enjeu, tous types confondus.
    $alertGroups = ['missing'=>[], 'zero'=>[], 'hf'=>[], 'surtaxe'=>[], 'intl'=>[], 'remise'=>[], 'var'=>[], 'global'=>[]];
    // Mois de référence : le mois d'arrivée s'il est facturé, sinon le dernier
    // mois facturé qui le précède. Un ?to= pointant un mois « trou » (URL
    // tapée, marque-page) rendrait sinon toutes les alertes muettes et ferait
    // déclarer tout le parc « absent de la facture » au rapprochement.
    $latestMonth = $axisTo;
    if ($latestMonth !== null && !isset($byKey[$latestMonth])) {
        $prev = null;
        foreach ($byKey as $bk => $_) if ($bk <= $axisTo && ($prev === null || $bk > $prev)) $prev = $bk;
        $latestMonth = $prev;
    }
    if ($latestMonth) {
        // Séries par numéro, limitées au mois d'arrivée (une période qui
        // s'arrête en mars ne doit pas voir les consommations d'avril).
        $series = [];
        foreach ($accQuery("SELECT l.* FROM invoice_lines l
                WHERE l.month_key <= ? $accWhere ORDER BY l.month_key", [$latestMonth]) as $il) {
            $series[$il['phone_number']][$il['month_key']] = $il;
        }

        foreach ($series as $phone => $byMonth) {
            $cur = $byMonth[$latestMonth] ?? null;
            if (!$cur) continue;
            $app  = $appLines[$phone] ?? null;
            $who  = $cur['sfr_user'] ?: ($app ? trim($app['ln'] . ' ' . $app['fn']) : '');
            $base = ['phone' => $phone, 'who' => $who, 'plan' => $cur['plan_name']];

            // Hors-forfait / surtaxés / international du mois de référence.
            if ((float)$cur['hf_ht'] >= $thr['hf_eur'])
                $alertGroups['hf'][] = $base + ['impact' => (float)$cur['hf_ht'],
                    'detail' => 'Consommations hors forfait facturées ce mois-ci'];
            if ((float)$cur['surtaxe_ht'] >= $thr['surtaxe_eur'])
                $alertGroups['surtaxe'][] = $base + ['impact' => (float)$cur['surtaxe_ht'],
                    'detail' => $cur['surtaxe_count'] . ' appel(s) vers des numéros surtaxés, ' . $fmtDur((int)$cur['surtaxe_seconds'])];
            if ((float)$cur['intl_ht'] >= $thr['intl_eur'])
                $alertGroups['intl'][] = $base + ['impact' => (float)$cur['intl_ht'],
                    'detail' => $cur['intl_count'] . ' appel(s) international(aux) ou en itinérance, ' . $fmtDur((int)$cur['intl_seconds'])];

            // Remise marché : la facture écrit le taux et le prix catalogue en
            // clair (« Remise sur abonnement (96,00% de 20,00€ HT) »). On les
            // compare au taux attendu ; à défaut de remise lisible, on retombe
            // sur l'ancien indice (abonnement au prix catalogue).
            if ($cur['remise_pct'] !== null) {
                if ((float)$cur['remise_pct'] + 0.001 < $thr['remise_pct']) {
                    $manque = max(0.0, (float)$cur['catalog_ht'] * ($thr['remise_pct'] - (float)$cur['remise_pct']) / 100);
                    $alertGroups['remise'][] = $base + ['impact' => round($manque, 2),
                        'detail' => 'Remise de ' . number_format((float)$cur['remise_pct'], 2, ',', ' ') . ' % sur '
                                  . $fmtEur($cur['catalog_ht']) . ' catalogue, au lieu des '
                                  . number_format($thr['remise_pct'], 2, ',', ' ') . ' % attendus'];
                }
            } elseif ((float)$cur['abo_ht'] >= 15) {
                $alertGroups['remise'][] = $base + ['impact' => (float)$cur['abo_ht'],
                    'detail' => 'Abonnement facturé ' . $fmtEur($cur['abo_ht']) . ' HT sans ligne de remise — remise marché absente ?'];
            }

            // Zéro consommation depuis N mois consécutifs.
            $zero = 0;
            foreach (array_reverse(array_keys($byMonth)) as $mk) {
                $x = $byMonth[$mk];
                // Itinérance et surtaxés compris : une ligne utilisée
                // uniquement à l'étranger n'est pas « sans consommation ».
                if ((int)$x['calls_count'] + (int)$x['sms_count'] + (int)$x['mms_count'] + (int)$x['data_ko']
                    + (int)$x['intl_count'] + (int)$x['surtaxe_count'] === 0) $zero++;
                else break;
            }
            if ($zero >= $thr['zero_months']) {
                $alertGroups['zero'][] = $base + ['impact' => (float)$cur['total_ht'], 'months' => $zero,
                    'detail' => "Aucune consommation depuis $zero mois — candidate à suspension / résiliation"];
            }

            // Variations vs moyenne des 3 mois précédents. Seul le hors-forfait
            // a un impact en euros : une variation de data ou d'appels comprise
            // dans le forfait ne coûte rien de plus.
            $prev = array_values(array_filter(array_keys($byMonth), fn($mk) => $mk < $latestMonth));
            $prev = array_slice($prev, -3);
            if ($prev) {
                $avg = fn($col) => array_sum(array_map(fn($mk) => (float)$byMonth[$mk][$col], $prev)) / count($prev);
                $checks = [
                    ['col'=>'hf_ht',         'floor'=>$thr['var_min_eur'], 'fmt'=>fn($v)=>$fmtEur($v),      'lbl'=>'hors-forfait', 'eur'=>true],
                    ['col'=>'data_ko',       'floor'=>1048576,             'fmt'=>fn($v)=>$fmtData((int)$v), 'lbl'=>'data',         'eur'=>false],
                    ['col'=>'calls_seconds', 'floor'=>3600,                'fmt'=>fn($v)=>$fmtDur((int)$v),  'lbl'=>'appels',       'eur'=>false],
                ];
                foreach ($checks as $c) {
                    $a = $avg($c['col']); $v = (float)$cur[$c['col']]; $diff = $v - $a;
                    if (abs($diff) < $c['floor']) continue;
                    if ($a > 0 && abs($diff) / $a * 100 < $thr['var_pct']) continue;
                    $f = $c['fmt'];
                    $dir = $diff > 0 ? '▲' : '▼';
                    $alertGroups['var'][] = $base + ['impact' => $c['eur'] ? max(0.0, $diff) : 0.0,
                        'detail' => $dir . ' ' . $c['lbl'] . ' : ' . $f($v) . ' ce mois vs ' . $f(round($a)) . ' en moyenne sur 3 mois'];
                }
            }
        }
        // Alerte globale : montant du mois de référence vs mois précédent, dans
        // les deux sens — une baisse brutale est tout aussi parlante (nouveau
        // marché appliqué… ou facture manquante).
        $upTo = array_values(array_filter(array_keys($byKey), fn($mk) => $mk <= $latestMonth));
        $n = count($upTo);
        if ($n >= 2) {
            $prevK = $upTo[$n-2]; $curK = $upTo[$n-1];
            $a = (float)$byKey[$prevK]['t']; $b = (float)$byKey[$curK]['t'];
            $pct = $a > 0 ? ($b - $a) / $a * 100 : 0;
            if (abs($pct) >= 20) {
                $alertGroups['global'][] = ['phone'=>'', 'who'=>'', 'plan'=>'', 'impact' => abs($b - $a),
                    'detail' => 'Total des lignes mobiles : ' . $fmtEur($b) . ' HT en ' . $fmtMois($curK)
                              . ' contre ' . $fmtEur($a) . ' en ' . $fmtMois($prevK)
                              . ' — ' . ($pct > 0 ? 'hausse' : 'baisse') . ' de ' . abs(round($pct)) . ' %'];
            }
        }
    }

    // ── Factures manquantes ──────────────────────────────────────
    // Chaque compte de facturation émet une facture par mois. Un mois sans
    // facture pour un compte qui en a avant ET après est un trou : les
    // compteurs de ce mois sont faux et personne ne contrôle la dépense.
    if ($axis) {
        $seen = [];   // compte => [mois => true]
        $stSeen = $pdo->prepare("SELECT billing_account, month_key FROM invoices
                WHERE invoice_type = 'lines' AND month_key IS NOT NULL AND billing_account IS NOT NULL"
                . ($acct !== '' ? ' AND billing_account = ?' : '')
                . " GROUP BY billing_account, month_key");
        $stSeen->execute($acct !== '' ? [$acct] : []);
        foreach ($stSeen as $r) $seen[$r['billing_account']][$r['month_key']] = true;

        // Montant mensuel moyen par compte : estime ce qui n'est pas contrôlé.
        $avgByAcct = [];
        $stAvg = $pdo->prepare("SELECT i.billing_account acc, SUM(l.total_ht) / COUNT(DISTINCT l.month_key) moy
                FROM invoice_lines l JOIN invoices i ON i.id = l.invoice_id
                WHERE i.billing_account IS NOT NULL GROUP BY i.billing_account");
        $stAvg->execute();
        foreach ($stAvg as $r) $avgByAcct[$r['acc']] = (float)$r['moy'];

        foreach ($axis as $mk) {
            foreach ($seen as $a => $monthsOfAcct) {
                if (isset($monthsOfAcct[$mk])) continue;
                // « Encadré » : le compte a des factures avant et après ce mois,
                // donc il était bien actif — sinon on ne signale rien (compte
                // ouvert plus tard ou clôturé).
                $before = false; $after = false;
                foreach (array_keys($monthsOfAcct) as $k2) {
                    if ($k2 < $mk) $before = true;
                    if ($k2 > $mk) $after = true;
                }
                if (!$before || !$after) continue;
                $alertGroups['missing'][] = ['phone' => '', 'plan' => null,
                    'who'    => 'Compte ' . $a . (($accounts[$a] ?? '') !== '' ? ' — ' . $accounts[$a] : ''),
                    'impact' => round($avgByAcct[$a] ?? 0, 2),
                    'detail' => 'Aucune facture importée pour ' . $fmtMois($mk)
                              . ' — les compteurs de ce mois sont incomplets'
                              . (isset($avgByAcct[$a]) ? ' (environ ' . $fmtEur($avgByAcct[$a]) . ' HT non contrôlés)' : '')];
            }
        }
    }

    $nbAlerts = array_sum(array_map('count', $alertGroups));
    ?>

    <div style="display:flex; gap:10px; margin-bottom:1rem; border-bottom:2px solid var(--border); flex-wrap:wrap;">
        <a href="?page=invoices&tab=dash&<?=$qsPeriod?>" class="tab-btn <?=$tab==='dash'?'active':''?>"><i class="bi bi-graph-up"></i> Tableau de bord</a>
        <a href="?page=invoices&tab=import" class="tab-btn <?=$tab==='import'?'active':''?>"><i class="bi bi-cloud-upload"></i> Import des factures</a>
        <a href="?page=invoices&tab=conso&<?=$qsPeriod?>" class="tab-btn <?=$tab==='conso'?'active':''?>"><i class="bi bi-bar-chart-line"></i> Consommations</a>
        <a href="?page=invoices&tab=alerts&<?=$qsPeriod?>" class="tab-btn <?=$tab==='alerts'?'active':''?>"><i class="bi bi-bell"></i> Alertes
          <?php if($nbAlerts): ?><span class="badge badge-danger" style="font-size:.68rem;"><?=$nbAlerts?></span><?php endif; ?></a>
        <a href="?page=invoices&tab=reconcile&<?=$qsPeriod?>" class="tab-btn <?=$tab==='reconcile'?'active':''?>"><i class="bi bi-person-check"></i> Rapprochement des noms</a>
    </div>

    <?php if(!$months && $tab !== 'import'): ?>
    <div class="card" style="padding:2.5rem;text-align:center;">
      <div style="font-size:2.2rem;margin-bottom:.5rem;"><i class="bi bi-filetype-pdf" style="color:var(--primary);"></i></div>
      <?php if($acct !== ''): ?>
      <p style="color:var(--text2);max-width:560px;margin:0 auto 1.25rem;">Aucune facture avec détail par ligne pour le compte
        <strong><?=h($acctLabel)?></strong>. Les autres comptes ont peut-être des factures importées.</p>
      <a href="?page=invoices&tab=<?=h($tab)?>" class="btn-secondary" style="text-decoration:none;display:inline-flex;align-items:center;gap:6px;"><i class="bi bi-arrows-angle-expand"></i> Voir tous les comptes</a>
      <?php else: ?>
      <p style="color:var(--text2);max-width:520px;margin:0 auto 1.25rem;">Aucune facture avec détail par ligne n'est encore importée.
      Déposez vos factures mensuelles PDF de l'opérateur (type <code>9A…</code>) — y compris les mois passés pour construire l'historique.</p>
      <a href="?page=invoices&tab=import" class="btn-primary" style="text-decoration:none;display:inline-flex;align-items:center;gap:6px;"><i class="bi bi-cloud-upload"></i> Importer des factures</a>
      <?php endif; ?>
    </div>
    <?php endif; ?>

    <?php if($tab === 'dash' && $months):
        // Tous les compteurs portent sur la période choisie. $cur = « photo »
        // pour les indicateurs instantanés (nombre de lignes, coût moyen par
        // ligne) : le mois d'arrivée s'il a une facture, sinon le dernier mois
        // facturé DANS la période. Le repli sur le dernier mois connu tous
        // mois confondus affichait un chiffre venu d'ailleurs sous l'étiquette
        // du mois d'arrivée.
        $curKey = isset($byKey[$axisTo]) ? $axisTo
                : ($monthsInPeriod ? end($monthsInPeriod)['month_key'] : null);
        $cur    = $curKey !== null ? $byKey[$curKey] : null;
        $periodTotal = array_sum(array_map(fn($r) => (float)$r['t'],  $monthsInPeriod));
        $periodHF    = array_sum(array_map(fn($r) => (float)$r['hf'], $monthsInPeriod));
        $periodSx    = array_sum(array_map(fn($r) => (float)$r['s'],  $monthsInPeriod));
        $periodIntl  = array_sum(array_map(fn($r) => (float)$r['i'],  $monthsInPeriod));
        $periodKo    = array_sum(array_map(fn($r) => (float)$r['ko'], $monthsInPeriod));
        $periodSms   = array_sum(array_map(fn($r) => (int)$r['sms'],  $monthsInPeriod));
        $lineMonths  = array_sum(array_map(fn($r) => (int)$r['n'],    $monthsInPeriod));
        $nbMois      = max(1, count($monthsInPeriod));

        // ── Régularisations (9AF) et avoirs (9AA) depuis le début de période ──
        // Elles n'ont pas de détail par ligne : aucun des compteurs ci-dessus,
        // tous bâtis sur invoice_lines, ne les voit. Sans ce bloc, une facture
        // de régularisation était lue par le parseur, stockée, affichée dans
        // l'onglet Import — puis absente de tous les euros du module.
        //
        // Pas de borne haute, volontairement. Ces documents corrigent toujours
        // du passé et sont émis après coup : sur le jeu réel, les douze
        // régularisations de juillet portent sur des mois antérieurs, alors que
        // la période s'arrête au dernier mois ayant un détail par ligne (juin).
        // Les borner en haut ne ferait que les cacher — le mois d'émission est
        // affiché dans le tableau, le lecteur situe lui-même chaque document.
        $stAdj = $pdo->prepare("SELECT invoice_number, invoice_type, invoice_date, month_key, total_ht, billing_account
                FROM invoices WHERE invoice_type IN ('manual','credit')
                  AND month_key IS NOT NULL AND month_key >= ?"
            . ($acct !== '' ? ' AND billing_account = ?' : '')
            . " ORDER BY invoice_date DESC, invoice_number");
        $stAdj->execute(array_merge([(string)$axisFrom], $acct !== '' ? [$acct] : []));
        $adjRows   = $stAdj->fetchAll();
        $adjManual = array_sum(array_map(fn($r) => (float)$r['total_ht'], array_filter($adjRows, fn($r) => $r['invoice_type'] === 'manual')));
        $adjCredit = array_sum(array_map(fn($r) => (float)$r['total_ht'], array_filter($adjRows, fn($r) => $r['invoice_type'] === 'credit')));
        $adjNet    = $adjManual + $adjCredit;   // les avoirs sont déjà négatifs

        // Lignes dormantes à la fin de la période (même règle que les alertes).
        $nbZero = count($alertGroups['zero']);
        $eurZero = array_sum(array_map(fn($a) => (float)$a['impact'], $alertGroups['zero']));

        // ── Top 10 : critère au choix, cumulé sur la période ──────────
        $topDefs = [
            'cost'    => ['Les plus chères',        'SUM(l.total_ht)',                'Total HT',      fn($v) => $fmtEur($v)],
            'sms'     => ['Le plus de SMS / MMS',   'SUM(l.sms_count+l.mms_count)',   'SMS + MMS',     fn($v) => number_format((float)$v, 0, ',', ' ')],
            'hf'      => ['Hors-forfait',           'SUM(l.hf_ht)',                   'Hors-forfait',  fn($v) => $fmtEur($v)],
            'intl'    => ['International',          'SUM(l.intl_ht)',                 'International', fn($v) => $fmtEur($v)],
            'surtaxe' => ['Numéros surtaxés',       'SUM(l.surtaxe_ht)',              'Surtaxés',      fn($v) => $fmtEur($v)],
            'data'    => ['Le plus de data',        'SUM(l.data_ko)',                 'Data',          fn($v) => $fmtData((int)$v)],
            'voice'   => ['Le plus d\'appels',      'SUM(l.calls_seconds)',           'Durée d\'appel', fn($v) => $fmtDur((int)$v)],
        ];
        $topCrit = isset($_GET['top'], $topDefs[$_GET['top']]) ? $_GET['top'] : 'cost';
        [$topLabel, $topExpr, $topCol, $topFmt] = $topDefs[$topCrit];
        // $topExpr est une expression littérale du tableau ci-dessus, jamais
        // une entrée utilisateur : seule la clé est reprise de l'URL.
        $ph  = implode(',', array_fill(0, count($axis), '?'));
        $top = $accQuery("SELECT l.phone_number, $topExpr val, SUM(l.total_ht) ht, COUNT(*) nbm,
                (SELECT x.sfr_user FROM invoice_lines x WHERE x.phone_number = l.phone_number
                   AND x.month_key <= ? ORDER BY x.month_key DESC LIMIT 1) sfr_user
            FROM invoice_lines l WHERE l.month_key IN ($ph) $accWhere
            GROUP BY l.phone_number HAVING val > 0 ORDER BY val DESC, ht DESC LIMIT 10",
            array_merge([$axisTo], $axis))->fetchAll();

        // ── Statistiques thématiques (sections repliables) ────────────
        // Photo du mois d'arrivée : forfaits, remise, prix unitaires.
        // Même mois de référence que la carte « Lignes facturées » ($curKey) :
        // un mois d'arrivée sans facture aurait rendu ces sections vides sans
        // dire pourquoi.
        $snap = $curKey === null ? [] : $accQuery("SELECT l.phone_number, l.plan_name, l.abo_ht, l.total_ht, l.data_ko,
                l.catalog_ht, l.remise_pct FROM invoice_lines l
                WHERE l.month_key = ? $accWhere", [$curKey])->fetchAll();

        // 1. Par forfait : effectif, prix médian, et lignes hors médiane (une
        //    ligne facturée autrement que ses jumelles est une anomalie).
        $planStats = [];
        foreach ($snap as $s) {
            $p = trim((string)$s['plan_name']) ?: '(forfait non identifié)';
            $planStats[$p]['abos'][] = (float)$s['abo_ht'];
            $planStats[$p]['rows'][] = $s;
            $planStats[$p]['ht']  = ($planStats[$p]['ht']  ?? 0) + (float)$s['total_ht'];
            $planStats[$p]['ko']  = ($planStats[$p]['ko']  ?? 0) + (int)$s['data_ko'];
        }
        foreach ($planStats as $p => &$ps) {
            sort($ps['abos']);
            $ps['n']      = count($ps['abos']);
            $ps['median'] = $ps['abos'][intdiv($ps['n'], 2)];
            $ps['out']    = array_values(array_filter($ps['rows'], fn($r) => abs((float)$r['abo_ht'] - $ps['median']) > 0.01));
            // Volume inclus lisible dans le nom du forfait (« … 5Go »)
            $ps['incl_ko'] = preg_match('/(\d+)\s*(Go|Mo)/i', $p, $mm)
                ? (int)$mm[1] * (strtolower($mm[2]) === 'go' ? 1048576 : 1024) : null;
            $ps['over'] = $ps['incl_ko'] ? count(array_filter($ps['rows'], fn($r) => (int)$r['data_ko'] > $ps['incl_ko'])) : 0;
        }
        unset($ps);
        uasort($planStats, fn($a, $b) => $b['ht'] <=> $a['ht']);

        // 2. Remise marché : taux et prix catalogue lus sur la facture.
        $remGroups = []; $remNone = 0; $catTotal = 0.0; $aboTotal = 0.0; $remKnown = 0;
        foreach ($snap as $s) {
            $aboTotal += (float)$s['abo_ht'];
            if ($s['remise_pct'] === null) { $remNone++; continue; }
            $remKnown++;
            $catTotal += (float)$s['catalog_ht'];
            $k = number_format((float)$s['remise_pct'], 2, ',', ' ') . ' % de ' . $fmtEur($s['catalog_ht']);
            $remGroups[$k]['n']   = ($remGroups[$k]['n'] ?? 0) + 1;
            $remGroups[$k]['abo'] = ($remGroups[$k]['abo'] ?? 0) + (float)$s['abo_ht'];
            $remGroups[$k]['cat'] = ($remGroups[$k]['cat'] ?? 0) + (float)$s['catalog_ht'];
            $remGroups[$k]['pct'] = (float)$s['remise_pct'];
        }
        uasort($remGroups, fn($a, $b) => $b['n'] <=> $a['n']);
        $remExpected = (float)getSetting($pdo, 'inv_alert_remise_pct', 90);

        // 3. Répartition par service : le rapprochement se fait sur le numéro
        //    normalisé, donc en PHP à partir du référentiel déjà chargé.
        $perPhone = $accQuery("SELECT l.phone_number, SUM(l.total_ht) ht, SUM(l.hf_ht) hf
                FROM invoice_lines l WHERE l.month_key IN ($ph) $accWhere
                GROUP BY l.phone_number", $axis)->fetchAll();
        $svcStats = [];
        foreach ($perPhone as $pp) {
            $app = $appLines[$pp['phone_number']] ?? null;
            $key = $app ? (trim((string)$app['service_name']) ?: '(sans service dans SimCity)')
                        : '(ligne inconnue de SimCity)';
            $svcStats[$key]['n']  = ($svcStats[$key]['n']  ?? 0) + 1;
            $svcStats[$key]['ht'] = ($svcStats[$key]['ht'] ?? 0) + (float)$pp['ht'];
            $svcStats[$key]['hf'] = ($svcStats[$key]['hf'] ?? 0) + (float)$pp['hf'];
        }
        uasort($svcStats, fn($a, $b) => $b['ht'] <=> $a['ht']);

        // 4. Terminaux et accessoires facturés (factures 9T) + présence au parc.
        // Bornées à la période comme tout le reste de l'onglet : le mois d'une
        // facture 9T est celui de sa date d'émission (elle n'a pas de période
        // de consommation). Le décompte hors période est affiché à part, pour
        // que le repli ne paraisse pas amputé.
        $stDevAll = $pdo->prepare("SELECT d.label, d.imei, d.qty, d.unit_ht, d.total_ht,
                i.invoice_number, i.invoice_date, i.month_key, i.billing_account,
                (SELECT COUNT(*) FROM devices dv WHERE dv.imei = d.imei) in_parc
            FROM invoice_devices d JOIN invoices i ON i.id = d.invoice_id"
            . ($acct !== '' ? ' WHERE i.billing_account = ?' : '')
            . " ORDER BY i.invoice_date DESC, d.id");
        $stDevAll->execute($acct !== '' ? [$acct] : []);
        $devAll     = $stDevAll->fetchAll();
        $devRows    = array_values(array_filter($devAll,
            fn($d) => $d['month_key'] !== null && $d['month_key'] >= $axisFrom && $d['month_key'] <= $axisTo));
        $devOutside = count($devAll) - count($devRows);
        $devTotal   = array_sum(array_map(fn($d) => (float)$d['total_ht'], $devRows));
        $devNoImei = count(array_filter($devRows, fn($d) => empty($d['imei'])));
        $devOrphan = count(array_filter($devRows, fn($d) => !empty($d['imei']) && !(int)$d['in_parc']));

        // 5. Activité du parc : distribution des lignes dormantes.
        $zeroDist = [];
        foreach ($alertGroups['zero'] as $z) $zeroDist[(int)($z['months'] ?? 0)] = ($zeroDist[(int)($z['months'] ?? 0)] ?? 0) + 1;
        krsort($zeroDist);
    ?>
    <?=$periodPicker('dash', ['top' => $topCrit])?>
    <?php if($acct !== ''): ?>
    <p class="muted" style="margin:-.5rem 0 1rem;font-size:.82rem;"><i class="bi bi-funnel"></i>
      Compteurs, graphiques et top 10 restreints au compte <strong><?=h($acctLabel)?></strong>.</p>
    <?php endif; ?>
    <div class="kpi-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:1rem;margin-bottom:1.5rem;">
      <a href="#inv-hist" class="card" style="padding:1.1rem 1.3rem;text-decoration:none;color:inherit;" title="Voir l'historique mensuel détaillé">
        <div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Lignes mobiles facturées <i class="bi bi-clock-history"></i></div>
        <div style="font-size:1.5rem;font-weight:700;"><?=$fmtEur($periodTotal)?> <span style="font-size:.8rem;color:var(--text2);">HT</span></div>
        <div class="muted"><?=h($periodLabel)?> · <?=$fmtEur($periodTotal / $nbMois)?>/mois en moyenne</div>
        <?php if($devTotal || $adjRows): // ce chiffre porte sur le détail par ligne : le dire plutôt que le laisser croire ?>
        <div class="muted" style="font-size:.75rem;margin-top:.35rem;padding-top:.35rem;border-top:1px dashed var(--border);">
          hors <?php $extra = [];
            if($devTotal) $extra[] = $fmtEur($devTotal) . ' de terminaux';
            // Le net peut être nul (régularisation compensée par son avoir) :
            // annoncer le décompte évite un « hors 0,00 € » incompréhensible.
            if($adjRows)  $extra[] = count($adjRows) . ' régularisation(s) / avoir(s), net ' . $fmtEur($adjNet);
            echo h(implode(' et ', $extra)); ?> — voir plus bas</div>
        <?php endif; ?>
      </a>
      <a href="#inv-hist" class="card" style="padding:1.1rem 1.3rem;text-decoration:none;color:inherit;" title="Voir l'historique mensuel détaillé">
        <div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Hors-forfait <i class="bi bi-clock-history"></i></div>
        <div style="font-size:1.5rem;font-weight:700;color:<?=$periodHF > 0 ? 'var(--warning)' : 'var(--success)'?>;"><?=$fmtEur($periodHF)?></div>
        <div class="muted">dont surtaxés <?=$fmtEur($periodSx)?> · international <?=$fmtEur($periodIntl)?></div>
      </a>
      <div class="card" style="padding:1.1rem 1.3rem;">
        <div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Lignes facturées</div>
        <?php if($cur): ?>
        <div style="font-size:1.5rem;font-weight:700;color:var(--primary);"><?=(int)$cur['n']?></div>
        <div class="muted">en <?=h($fmtMois($curKey))?><?php if($curKey !== $axisTo): ?> <span title="Aucune facture importée pour <?=h($fmtMois($axisTo))?>">(dernier mois facturé)</span><?php endif; ?>
          · <?=$fmtEur((float)$cur['t'] / max(1, (int)$cur['n']))?> HT/ligne</div>
        <?php else: ?>
        <div style="font-size:1.5rem;font-weight:700;color:var(--text3);">—</div>
        <div class="muted">aucune facture importée sur <?=h($periodLabel)?></div>
        <?php endif; ?>
      </div>
      <a href="?page=invoices&tab=alerts&<?=$qsPeriod?>&type=zero" class="card" style="padding:1.1rem 1.3rem;text-decoration:none;color:inherit;" title="Voir les lignes concernées">
        <div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Lignes sans consommation</div>
        <div style="font-size:1.5rem;font-weight:700;color:<?=$nbZero ? 'var(--info)' : 'var(--success)'?>;"><?=$nbZero?></div>
        <div class="muted"><?=$eurZero > 0 ? $fmtEur($eurZero) . ' HT/mois — ' . $fmtEur($eurZero * 12) . '/an' : 'aucune ligne dormante'?></div>
      </a>
      <a href="?page=invoices&tab=alerts&<?=$qsPeriod?>" class="card" style="padding:1.1rem 1.3rem;text-decoration:none;color:inherit;">
        <div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Alertes en cours</div>
        <div style="font-size:1.5rem;font-weight:700;color:<?=$nbAlerts ? 'var(--danger)' : 'var(--success)'?>;"><?=$nbAlerts?></div>
        <div class="muted">sur <?=h($fmtMois($axisTo))?> · voir le détail <i class="bi bi-arrow-right"></i></div>
      </a>
    </div>

    <details class="acc" open>
      <summary><i class="bi bi-graph-up"></i> Évolution du coût et du parc
        <span class="acc-hint"><?=count($axis)?> mois · <?=h($periodLabel)?></span><i class="bi bi-chevron-down acc-chev"></i></summary>
      <div class="acc-body">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;align-items:start;">
          <div>
            <div style="text-align:center;margin-bottom:.75rem;">
              <div style="font-family:var(--font-display);font-size:1.3rem;font-weight:700;color:var(--text-strong);">Évolution sur <?=count($axis)?> mois</div>
              <div style="font-size:.8rem;font-weight:600;color:var(--text2);">du coût mensuel des lignes mobiles (€ HT)</div>
            </div>
            <div style="height:290px;"><canvas id="invMonthly"></canvas></div>
            <?php if($axisGaps): ?>
            <p class="muted" style="text-align:center;font-size:.78rem;margin:.6rem 0 0;"><i class="bi bi-exclamation-triangle" style="color:var(--warning);"></i>
              <?=$axisGaps?> mois sans facture importée sur la période — le tracé est interrompu (aucun mois n'est affiché à 0 €).</p>
            <?php endif; ?>
          </div>
          <div>
            <div style="text-align:center;margin-bottom:.75rem;">
              <div style="font-family:var(--font-display);font-size:1.3rem;font-weight:700;color:var(--text-strong);">Évolution sur <?=count($axis)?> mois</div>
              <div style="font-size:.8rem;font-weight:600;color:var(--text2);">du nombre de lignes mobiles facturées</div>
            </div>
            <div style="height:290px;"><canvas id="invLinesCount"></canvas></div>
            <p class="muted" style="text-align:center;font-size:.78rem;margin:.6rem 0 0;">
              <?php $nbFirst = $axisNb[0] ?? null; $nbLast = $axisNb[count($axisNb)-1] ?? null;
                    $delta = ($nbFirst !== null && $nbLast !== null) ? $nbLast - $nbFirst : null; ?>
              <?php if($delta !== null): ?>
                <?=$nbLast?> lignes facturées en <?=h($fmtMois($axisTo))?> —
                <strong style="color:<?=$delta > 0 ? 'var(--warning)' : ($delta < 0 ? 'var(--success)' : 'inherit')?>;"><?=$delta > 0 ? '+' : ''?><?=$delta?></strong>
                depuis <?=h($fmtMois($axisFrom))?>
                <?php if($delta !== 0): ?>(<?=$fmtEur(abs($delta) * ($nbLast ? (float)$byKey[$axisTo]['t'] / $nbLast : 0))?> HT/mois au prix moyen actuel)<?php endif; ?>
              <?php endif; ?>
            </p>
          </div>
        </div>
      </div>
    </details>

    <details class="acc" open>
      <summary><i class="bi bi-trophy"></i> Top 10 des lignes
        <span class="acc-hint"><?=h($topLabel)?> · cumul sur <?=count($axis)?> mois</span><i class="bi bi-chevron-down acc-chev"></i></summary>
      <div class="acc-body flush">
        <form method="get" style="display:flex;align-items:center;gap:.5rem;margin:0;padding:1rem 1.4rem .4rem;flex-wrap:wrap;">
          <input type="hidden" name="page" value="invoices"><input type="hidden" name="tab" value="dash">
          <input type="hidden" name="from" value="<?=h((string)$axisFrom)?>"><input type="hidden" name="to" value="<?=h((string)$axisTo)?>">
          <?php if($acct !== ''): ?><input type="hidden" name="acct" value="<?=h($acct)?>"><?php endif; ?>
          <label style="margin:0;">Classer par</label>
          <select name="top" onchange="this.form.submit()" style="width:auto;font-size:.85rem;">
            <?php foreach($topDefs as $k => $d): ?><option value="<?=h($k)?>" <?=$k===$topCrit?'selected':''?>><?=h($d[0])?></option><?php endforeach; ?>
          </select>
          <span class="muted" style="font-size:.78rem;">sur <?=h($periodLabel)?></span>
        </form>
        <table class="data-table" style="font-size:.85rem;">
          <thead><tr><th>Ligne</th><th>Utilisateur (SFR)</th><th>Service (SimCity)</th><th style="text-align:right;"><?=h($topCol)?></th><?php if($topCrit !== 'cost'): ?><th style="text-align:right;">Total HT</th><?php endif; ?></tr></thead>
          <tbody>
          <?php if(!$top): ?><tr><td colspan="5" class="empty-cell">Aucune ligne concernée sur la période</td></tr><?php endif; ?>
          <?php foreach($top as $t): $tapp = $appLines[$t['phone_number']] ?? null; ?>
            <tr><td><a href="?page=invoices&tab=conso&<?=$qsPeriod?>&line=<?=h($t['phone_number'])?>" style="font-family:var(--font-mono);white-space:nowrap;"><?=h(formatPhone($t['phone_number']))?></a></td>
                <td><?=h($t['sfr_user'] ?: '—')?></td>
                <td class="muted"><?=$tapp ? h($tapp['service_name'] ?: '—') : '<span class="badge badge-danger" style="font-size:.65rem;">hors SimCity</span>'?></td>
                <td style="font-weight:600;text-align:right;font-family:var(--font-mono);"><?=$topFmt($t['val'])?></td>
                <?php if($topCrit !== 'cost'): ?><td class="muted" style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($t['ht'])?></td><?php endif; ?></tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </details>

    <details class="acc" id="inv-hist" style="scroll-margin-top:1rem;">
      <summary><i class="bi bi-clock-history"></i> Historique mensuel
        <span class="acc-hint"><?=h($periodLabel)?> · <?=count($monthsInPeriod)?> mois facturés</span><i class="bi bi-chevron-down acc-chev"></i></summary>
      <div class="acc-body flush" style="overflow-x:auto;">
      <table class="data-table" style="font-size:.85rem;">
        <thead><tr><th>Mois</th><th style="text-align:right;">Lignes</th><th style="text-align:right;">Abonnements</th>
          <th style="text-align:right;">Consommations</th><th style="text-align:right;">Hors-forfait</th>
          <th style="text-align:right;">dont surtaxés</th><th style="text-align:right;">dont international</th>
          <th style="text-align:right;">Appels</th><th style="text-align:right;">SMS+MMS</th><th style="text-align:right;">Data</th>
          <th style="text-align:right;">Total HT</th><th style="text-align:right;">€/ligne</th></tr></thead>
        <tbody>
        <?php foreach(array_reverse($axis) as $mk): $r = $byKey[$mk] ?? null; ?>
          <tr<?=$mk === $axisTo ? ' style="background:var(--primary-dim);"' : ''?>>
            <td style="font-weight:600;white-space:nowrap;"><?=h($fmtMois($mk))?></td>
            <?php if(!$r): ?>
              <td colspan="11" class="muted" style="font-style:italic;"><i class="bi bi-exclamation-triangle" style="color:var(--warning);"></i> aucune facture importée pour ce mois</td>
            <?php else: ?>
              <td style="text-align:right;"><?=(int)$r['n']?></td>
              <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($r['abo'])?></td>
              <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($r['conso'])?></td>
              <td style="text-align:right;font-family:var(--font-mono);color:<?=(float)$r['hf'] > 0 ? 'var(--warning)' : 'inherit'?>;"><?=(float)$r['hf'] > 0 ? $fmtEur($r['hf']) : '—'?></td>
              <td style="text-align:right;font-family:var(--font-mono);" class="muted"><?=(float)$r['s'] > 0 ? $fmtEur($r['s']) : '—'?></td>
              <td style="text-align:right;font-family:var(--font-mono);" class="muted"><?=(float)$r['i'] > 0 ? $fmtEur($r['i']) : '—'?></td>
              <td style="text-align:right;" class="muted"><?=$fmtDur((int)$r['secs'])?></td>
              <td style="text-align:right;" class="muted"><?=number_format((int)$r['sms'], 0, ',', ' ')?></td>
              <td style="text-align:right;" class="muted"><?=$fmtData((int)$r['ko'])?></td>
              <td style="text-align:right;font-weight:700;font-family:var(--font-mono);"><?=$fmtEur($r['t'])?></td>
              <td style="text-align:right;font-family:var(--font-mono);" class="muted"><?=$fmtEur((float)$r['t'] / max(1, (int)$r['n']))?></td>
            <?php endif; ?>
          </tr>
        <?php endforeach; ?>
        </tbody>
        <tfoot><tr style="border-top:2px solid var(--border);font-weight:700;">
          <td>Total <?=count($monthsInPeriod)?> mois</td>
          <td style="text-align:right;"><?=$lineMonths?><br><span class="muted" style="font-weight:400;font-size:.72rem;">ligne·mois</span></td>
          <td colspan="2"></td>
          <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($periodHF)?></td>
          <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($periodSx)?></td>
          <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($periodIntl)?></td>
          <td></td>
          <td style="text-align:right;"><?=number_format($periodSms, 0, ',', ' ')?></td>
          <td style="text-align:right;"><?=$fmtData((int)$periodKo)?></td>
          <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($periodTotal)?></td>
          <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($lineMonths ? $periodTotal / $lineMonths : 0)?></td>
        </tr></tfoot>
      </table>
      </div>
    </details>

    <details class="acc">
      <summary><i class="bi bi-globe2"></i> Répartition par forfait
        <span class="acc-hint"><?=count($planStats)?> forfaits en <?=h($fmtMois($curKey))?><?php
          $nbOut = array_sum(array_map(fn($p) => count($p['out']), $planStats));
          if($nbOut): ?> · <?=$nbOut?> ligne(s) hors prix médian<?php endif; ?></span><i class="bi bi-chevron-down acc-chev"></i></summary>
      <div class="acc-body flush" style="overflow-x:auto;">
        <table class="data-table" style="font-size:.85rem;">
          <thead><tr><th>Forfait</th><th style="text-align:right;">Lignes</th><th style="text-align:right;">Abo médian</th>
            <th style="text-align:right;">Total HT du mois</th><th style="text-align:right;">Data</th>
            <th style="text-align:right;">Dépassement data</th><th>Prix hors médiane</th></tr></thead>
          <tbody>
          <?php foreach($planStats as $p => $ps): ?>
          <tr>
            <td><?=h($p)?><?php if($ps['incl_ko']): ?><br><span class="muted" style="font-size:.73rem;"><?=$fmtData($ps['incl_ko'])?> inclus</span><?php endif; ?></td>
            <td style="text-align:right;font-weight:600;"><?=$ps['n']?></td>
            <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($ps['median'])?></td>
            <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($ps['ht'])?></td>
            <td style="text-align:right;" class="muted"><?=$fmtData((int)$ps['ko'])?></td>
            <td style="text-align:right;"><?=$ps['over'] ? '<span class="badge badge-warning" style="font-size:.68rem;">' . $ps['over'] . ' ligne(s)</span>' : '<span class="muted">—</span>'?></td>
            <td>
              <?php if(!$ps['out']): ?><span class="muted">—</span><?php else: ?>
                <?php foreach(array_slice($ps['out'], 0, 4) as $o): ?>
                <a href="?page=invoices&tab=conso&<?=$qsPeriod?>&line=<?=h($o['phone_number'])?>" style="font-family:var(--font-mono);font-size:.8rem;white-space:nowrap;"><?=h(formatPhone($o['phone_number']))?></a>
                <span class="badge badge-warning" style="font-size:.66rem;"><?=$fmtEur($o['abo_ht'])?></span><br>
                <?php endforeach; ?>
                <?php if(count($ps['out']) > 4): ?><span class="muted" style="font-size:.75rem;">+ <?=count($ps['out']) - 4?> autres</span><?php endif; ?>
              <?php endif; ?>
            </td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        <p class="muted" style="padding:.8rem 1.4rem 0;font-size:.79rem;"><i class="bi bi-lightbulb"></i>
          Une ligne facturée à un autre prix que ses jumelles sur le même forfait est une anomalie de facturation à faire corriger.
          « Dépassement data » compare la consommation au volume lisible dans le nom du forfait.</p>
      </div>
    </details>

    <details class="acc">
      <summary><i class="bi bi-percent"></i> Remise marché
        <span class="acc-hint"><?php if($remKnown): ?><?=count($remGroups)?> taux appliqués · <?=$fmtEur($catTotal - $aboTotal)?> d'économie/mois<?php else: ?>donnée non encore extraite<?php endif; ?></span><i class="bi bi-chevron-down acc-chev"></i></summary>
      <div class="acc-body">
        <?php if(!$remKnown): ?>
          <p class="muted" style="margin:0;"><i class="bi bi-info-circle"></i>
            Le taux de remise et le prix catalogue sont écrits en clair dans chaque bloc de la facture, mais ils n'ont pas encore été extraits
            pour les factures déjà importées. Lancez <a href="?page=invoices&tab=import">Import des factures → Ré-analyser toutes les factures</a>
            pour les récupérer sans rien re-téléverser.</p>
        <?php else: ?>
          <div class="kpi-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:1.25rem;">
            <div><div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Prix catalogue</div>
                 <div style="font-size:1.35rem;font-weight:700;"><?=$fmtEur($catTotal)?></div><div class="muted">sans remise, pour <?=$remKnown?> lignes</div></div>
            <div><div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Facturé</div>
                 <div style="font-size:1.35rem;font-weight:700;"><?=$fmtEur($aboTotal)?></div><div class="muted">abonnements du mois</div></div>
            <div><div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Économie du marché</div>
                 <div style="font-size:1.35rem;font-weight:700;color:var(--success);"><?=$fmtEur($catTotal - $aboTotal)?></div>
                 <div class="muted"><?=$fmtEur(($catTotal - $aboTotal) * 12)?> sur 12 mois</div></div>
          </div>
          <table class="data-table" style="font-size:.85rem;">
            <thead><tr><th>Remise appliquée</th><th style="text-align:right;">Lignes</th><th style="text-align:right;">Catalogue</th>
              <th style="text-align:right;">Facturé</th><th style="text-align:right;">Économie</th><th>Conformité</th></tr></thead>
            <tbody>
            <?php foreach($remGroups as $k => $g): ?>
            <tr>
              <td style="font-family:var(--font-mono);"><?=h($k)?></td>
              <td style="text-align:right;font-weight:600;"><?=$g['n']?></td>
              <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($g['cat'])?></td>
              <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($g['abo'])?></td>
              <td style="text-align:right;font-family:var(--font-mono);color:var(--success);"><?=$fmtEur($g['cat'] - $g['abo'])?></td>
              <td><?=$g['pct'] + 0.001 >= $remExpected
                    ? '<span class="badge badge-success" style="font-size:.68rem;"><i class="bi bi-check-lg"></i> ≥ ' . rtrim(rtrim(number_format($remExpected, 2, ',', ' '), '0'), ',') . ' %</span>'
                    : '<span class="badge badge-danger" style="font-size:.68rem;"><i class="bi bi-exclamation-triangle"></i> sous le taux attendu</span>'?></td>
            </tr>
            <?php endforeach; ?>
            <?php if($remNone): ?>
            <tr><td colspan="2"><span class="badge badge-warning" style="font-size:.68rem;">Aucune remise lisible</span></td>
                <td colspan="4" class="muted"><?=$remNone?> ligne(s) sans ligne « Remise sur abonnement » dans la facture — abonnement déjà net, ou remise non appliquée.</td></tr>
            <?php endif; ?>
            </tbody>
          </table>
        <?php endif; ?>
      </div>
    </details>

    <details class="acc">
      <summary><i class="bi bi-building"></i> Répartition par service
        <span class="acc-hint"><?=count($svcStats)?> regroupements · <?=h($periodLabel)?></span><i class="bi bi-chevron-down acc-chev"></i></summary>
      <div class="acc-body flush">
        <table class="data-table" style="font-size:.85rem;">
          <thead><tr><th>Service (référentiel SimCity)</th><th style="text-align:right;">Lignes</th>
            <th style="text-align:right;">Total HT sur la période</th><th style="text-align:right;">Hors-forfait</th>
            <th style="text-align:right;">€ HT / ligne / mois</th><th style="text-align:right;">Part</th></tr></thead>
          <tbody>
          <?php foreach($svcStats as $sv => $d): $unknown = str_starts_with($sv, '(');
                // Chaque regroupement mène aux consommations filtrées : le
                // service via svc=, les regroupements « (…) » via leur
                // signalement équivalent.
                $svHref = '?page=invoices&tab=conso&' . $qsPeriod . '&'
                        . ($sv === '(ligne inconnue de SimCity)' ? 'flag=unknown'
                        : ($sv === '(sans service dans SimCity)' ? 'flag=nosvc'
                        : 'svc=' . urlencode($sv))); ?>
          <tr>
            <td<?=$unknown ? ' class="muted"' : ''?>><a href="<?=h($svHref)?>" style="color:inherit;" title="Voir les consommations de ce regroupement"><?=h($sv)?></a></td>
            <td style="text-align:right;font-weight:600;"><?=$d['n']?></td>
            <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($d['ht'])?></td>
            <td style="text-align:right;font-family:var(--font-mono);color:<?=$d['hf'] > 0 ? 'var(--warning)' : 'inherit'?>;"><?=$d['hf'] > 0 ? $fmtEur($d['hf']) : '—'?></td>
            <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($d['ht'] / max(1, $d['n']) / $nbMois)?></td>
            <td style="text-align:right;"><?=$periodTotal > 0 ? number_format($d['ht'] / $periodTotal * 100, 1, ',', ' ') . ' %' : '—'?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        <p class="muted" style="padding:.8rem 1.4rem 0;font-size:.79rem;"><i class="bi bi-info-circle"></i>
          Le service vient du référentiel SimCity (ligne → agent → service) : une ligne facturée mais inconnue du référentiel,
          ou sans service renseigné, tombe dans les regroupements entre parenthèses. C'est le tableau à joindre au dialogue de gestion
          — voir l'onglet Rapprochement pour réduire les lignes non rattachées.</p>
      </div>
    </details>

    <details class="acc">
      <summary><i class="bi bi-phone"></i> Terminaux et accessoires facturés
        <span class="acc-hint"><?php if($devRows): ?><?=count($devRows)?> lignes d'achat · <?=$fmtEur($devTotal)?> HT sur <?=h($periodLabel)?><?php if($devOrphan): ?> · <?=$devOrphan?> IMEI absent(s) du parc<?php endif; ?><?php elseif($devOutside): ?>aucun achat sur la période<?php else: ?>aucune facture 9T importée<?php endif; ?></span><i class="bi bi-chevron-down acc-chev"></i></summary>
      <div class="acc-body flush">
        <?php if(!$devRows): ?>
          <p class="muted" style="padding:1.1rem 1.4rem;margin:0;"><i class="bi bi-info-circle"></i>
            <?php if($devOutside): ?>
            Aucun achat de terminal facturé sur <strong><?=h($periodLabel)?></strong> —
            <?=$devOutside?> ligne(s) d'achat existent en dehors de cette période. Élargissez les bornes pour les voir.
            <?php else: ?>
            Les factures d'achat de terminaux (numéro <code>9T…</code>) contiennent le libellé, la quantité, le prix et l'IMEI de chaque matériel.
            Déposez-les dans l'onglet Import : ce tableau les rapprochera automatiquement du parc matériel par IMEI.
            <?php endif; ?></p>
        <?php else: ?>
        <table class="data-table" style="font-size:.85rem;">
          <thead><tr><th>Matériel</th><th>IMEI</th><th style="text-align:right;">Qté</th><th style="text-align:right;">PU HT</th>
            <th style="text-align:right;">Total HT</th><th>Facture</th><th>Présent au parc</th></tr></thead>
          <tbody>
          <?php foreach($devRows as $d): ?>
          <tr>
            <td><?=h($d['label'])?></td>
            <td style="font-family:var(--font-mono);font-size:.8rem;"><?=h($d['imei'] ?: '—')?></td>
            <td style="text-align:right;"><?=(int)$d['qty']?></td>
            <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($d['unit_ht'])?></td>
            <td style="text-align:right;font-family:var(--font-mono);font-weight:600;"><?=$fmtEur($d['total_ht'])?></td>
            <td class="muted" style="font-size:.78rem;"><?=h($d['invoice_number'])?><br><?=$d['invoice_date'] ? date('d/m/Y', strtotime($d['invoice_date'])) : ''?></td>
            <td><?php if(empty($d['imei'])): ?><span class="muted">IMEI non facturé</span>
                <?php elseif((int)$d['in_parc']): ?><span class="badge badge-success" style="font-size:.68rem;"><i class="bi bi-check-lg"></i> au parc</span>
                <?php else: ?><a href="?page=devices&q=<?=urlencode($d['imei'])?>" class="badge badge-danger" style="font-size:.68rem;text-decoration:none;"><i class="bi bi-exclamation-triangle"></i> absent du parc</a><?php endif; ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        <p class="muted" style="padding:.8rem 1.4rem 0;font-size:.79rem;"><i class="bi bi-lightbulb"></i>
          Un IMEI facturé mais absent du parc, c'est un matériel payé et jamais enregistré dans SimCity.
          <?php if($devNoImei): ?><?=$devNoImei?> ligne(s) d'achat sans IMEI (accessoires, prestations) ne sont pas rapprochables.<?php endif; ?>
          <?php if($devOutside): ?><?=$devOutside?> ligne(s) d'achat hors de la période retenue ne sont pas listées ici.<?php endif; ?></p>
        <?php endif; ?>
      </div>
    </details>

    <!-- Régularisations (9AF) et avoirs (9AA) : sans détail par ligne, donc
         invisibles de tous les compteurs bâtis sur invoice_lines. -->
    <details class="acc">
      <summary><i class="bi bi-arrow-left-right"></i> Régularisations et avoirs
        <span class="acc-hint"><?php if($adjRows): ?><?=count($adjRows)?> facture(s) · <?=$fmtEur($adjNet)?> HT net depuis <?=h($fmtMois($axisFrom))?><?php else: ?>aucune depuis <?=h($fmtMois($axisFrom))?><?php endif; ?></span><i class="bi bi-chevron-down acc-chev"></i></summary>
      <div class="acc-body flush">
        <?php if(!$adjRows): ?>
          <p class="muted" style="padding:1.1rem 1.4rem;margin:0;"><i class="bi bi-info-circle"></i>
            Aucune facture de régularisation (<code>9AF…</code>) ni avoir (<code>9AA…</code>) depuis <strong><?=h($fmtMois($axisFrom))?></strong>.
            Ces documents n'ont pas de détail par ligne : ils ne peuvent pas être ventilés par numéro, seulement suivis à part.</p>
        <?php else: ?>
        <table class="data-table" style="font-size:.85rem;">
          <thead><tr><th>N° de facture</th><th>Type</th><th>Compte</th><th>Date</th><th>Mois</th><th style="text-align:right;">Montant HT</th><th></th></tr></thead>
          <tbody>
          <?php foreach($adjRows as $aj): $isCredit = $aj['invoice_type'] === 'credit'; ?>
          <tr>
            <td style="font-family:var(--font-mono);font-size:.82rem;"><?=h($aj['invoice_number'])?></td>
            <td><span class="badge <?=$isCredit ? 'badge-danger' : 'badge-warning'?>" style="font-size:.68rem;"><?=$isCredit ? 'Avoir' : 'Régularisation'?></span></td>
            <td class="muted"><?=h($aj['billing_account'] ?: '—')?></td>
            <td><?=$aj['invoice_date'] ? date('d/m/Y', strtotime($aj['invoice_date'])) : '—'?></td>
            <td class="muted"><?=h($fmtMois($aj['month_key']))?></td>
            <td style="text-align:right;font-family:var(--font-mono);font-weight:600;color:<?=(float)$aj['total_ht'] < 0 ? 'var(--success)' : 'var(--warning)'?>;"><?=$fmtEur($aj['total_ht'])?></td>
            <td class="actions"><a class="btn-icon" title="Voir la facture dans l'onglet Import" href="?page=invoices&tab=import<?=$acct !== '' ? '&acct=' . urlencode($acct) : ''?>" style="text-decoration:none;"><i class="bi bi-box-arrow-up-right"></i></a></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
          <tfoot><tr style="border-top:2px solid var(--border);font-weight:700;">
            <td colspan="5">Net depuis <?=h($fmtMois($axisFrom))?> — <?=$fmtEur($adjManual)?> de régularisations, <?=$fmtEur($adjCredit)?> d'avoirs</td>
            <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur($adjNet)?></td><td></td>
          </tr></tfoot>
        </table>
        <p class="muted" style="padding:.8rem 1.4rem 0;font-size:.79rem;"><i class="bi bi-lightbulb"></i>
          Ces montants ne sont <strong>pas</strong> compris dans les compteurs ci-dessus : ceux-ci sont construits à partir du
          détail par ligne des factures mensuelles, que les régularisations et les avoirs n'ont pas.
          Un net proche de zéro signifie qu'une régularisation a bien été compensée par son avoir.</p>
        <?php endif; ?>
      </div>
    </details>

    <details class="acc">
      <summary><i class="bi bi-moon-stars"></i> Activité du parc
        <span class="acc-hint"><?=$nbZero?> ligne(s) sans consommation · <?=$fmtEur($eurZero)?> HT/mois</span><i class="bi bi-chevron-down acc-chev"></i></summary>
      <div class="acc-body">
        <?php if(!$zeroDist): ?>
          <p class="muted" style="margin:0;">Toutes les lignes facturées en <?=h($fmtMois($curKey))?> ont consommé au moins une fois sur la période de référence.</p>
        <?php else: ?>
        <?php
          // Lignes groupées par ancienneté, pour le déroulé au clic sur la tranche.
          $zeroByMonths = [];
          foreach ($alertGroups['zero'] as $z) $zeroByMonths[(int)($z['months'] ?? 0)][] = $z;
        ?>
        <table class="data-table" style="font-size:.85rem;">
          <thead><tr><th>Ancienneté du silence</th><th style="text-align:right;">Lignes</th><th>Lecture</th></tr></thead>
          <tbody>
          <?php foreach($zeroDist as $mois => $n): ?>
          <tr onclick="const c=this.querySelector('.zb-chev');c.classList.toggle('bi-chevron-right');c.classList.toggle('bi-chevron-down');document.querySelectorAll('.zero-det-<?=$mois?>').forEach(r=>r.style.display=r.style.display==='none'?'':'none')"
              style="cursor:pointer;" title="Afficher / masquer les lignes concernées">
            <td><i class="bi bi-chevron-right zb-chev" style="font-size:.7rem;color:var(--text-muted);"></i>
              <strong><?=$mois?> mois</strong> consécutifs sans appel, SMS ni data</td>
            <td style="text-align:right;font-weight:600;"><?=$n?></td>
            <td class="muted"><?=$mois >= 4 ? 'Résiliation à envisager' : ($mois >= 2 ? 'Suspension ou résiliation à étudier' : 'À surveiller')?></td>
          </tr>
          <?php foreach(($zeroByMonths[$mois] ?? []) as $z): ?>
          <tr class="zero-det-<?=$mois?>" style="display:none;">
            <td style="padding-left:1.9rem;">
              <a href="?page=invoices&tab=conso&<?=$qsPeriod?>&line=<?=h($z['phone'])?>" style="font-family:var(--font-mono);white-space:nowrap;" title="Historique de la ligne" onclick="event.stopPropagation()"><?=h(formatPhone($z['phone']))?></a>
              <?php if($z['who']): ?> <span class="muted"><?=h($z['who'])?></span><?php endif; ?>
              <?php if($z['plan']): ?> <span class="muted" style="font-size:.76rem;">· <?=h($z['plan'])?></span><?php endif; ?>
            </td>
            <td style="text-align:right;font-family:var(--font-mono);"><?=$fmtEur((float)$z['impact'])?></td>
            <td><?php if(!empty($appLines[$z['phone']])): ?><a class="muted" style="font-size:.78rem;" href="?page=lines&tab=active&q=<?=urlencode(formatPhone($z['phone']))?>" onclick="event.stopPropagation()">voir la fiche →</a><?php endif; ?></td>
          </tr>
          <?php endforeach; ?>
          <?php endforeach; ?>
          </tbody>
        </table>
        <p class="muted" style="padding:.8rem 0 0;font-size:.79rem;"><i class="bi bi-lightbulb"></i>
          Ces lignes sont payées chaque mois sans être utilisées : <strong><?=$fmtEur($eurZero)?> HT/mois</strong>, soit <strong><?=$fmtEur($eurZero * 12)?> par an</strong>.
          Certaines sont légitimes (astreinte, alarme, ligne de secours) — <a href="?page=invoices&tab=alerts&<?=$qsPeriod?>&type=zero">voir le détail ligne par ligne</a>.</p>
        <?php endif; ?>
      </div>
    </details>

    <script src="vendor/chart.umd.min.js"></script>
    <script>
    (function(){
      // Couleurs prises sur le thème courant (clair/sombre) plutôt qu'en dur.
      const css     = getComputedStyle(document.documentElement);
      const cssVar  = (n, d) => (css.getPropertyValue(n) || '').trim() || d;
      const primary = '<?=uiPrimaryColor($pdo) ?: '#4f46e5'?>';
      const axisCol = cssVar('--text2', '#64748b');
      const gridCol = cssVar('--border', '#e2e8f0');
      const strong  = cssVar('--text-strong', '#0f172a');
      const labels  = <?=json_encode($axisLabels)?>;
      const nb      = <?=json_encode($axisNb)?>;
      const eur     = v => Math.round(v).toLocaleString('fr-FR') + ' €';
      const lgn     = v => Math.round(v).toLocaleString('fr-FR') + (Math.abs(v) > 1 ? ' lignes' : ' ligne');

      // Courbe d'évolution mensuelle — présentation commune aux deux
      // graphiques : aire remplie, mois courant en gras, trous conservés.
      const evol = (id, data, fmt, tip) => {
        const el = document.getElementById(id); if(!el) return;
        const last = data.length - 1;
        new Chart(el, {type:'line',
          data:{labels,
                datasets:[{data, borderColor:primary, backgroundColor:primary+'1f', fill:true,
                           tension:.3, borderWidth:2, pointRadius:3.5, pointBackgroundColor:primary,
                           pointBorderWidth:0, spanGaps:false}]},
          options:{responsive:true,maintainAspectRatio:false,
            plugins:{legend:{display:false},
                     tooltip:{displayColors:false, callbacks:{label:tip}}},
            scales:{x:{grid:{display:false}, border:{display:false},
                       ticks:{color: c => c.index === last ? strong : axisCol,
                              font:  c => ({size:11, weight: c.index === last ? '700' : '400'})}},
                    y:{beginAtZero:true, border:{display:false}, grid:{color:gridCol},
                       ticks:{color:axisCol, font:{size:11}, precision:0, callback:v => fmt(v)}}}}});
      };
      evol('invMonthly', <?=json_encode($axisData)?>, eur,
           c => eur(c.parsed.y) + ' HT' + (nb[c.dataIndex] ? ' · ' + nb[c.dataIndex] + ' lignes' : ''));
      evol('invLinesCount', nb, lgn, c => lgn(c.parsed.y) + ' facturée' + (c.parsed.y > 1 ? 's' : ''));

      // Un canvas replié a une taille nulle : on redimensionne à l'ouverture.
      document.querySelectorAll('details.acc').forEach(d => d.addEventListener('toggle', () => {
        if (!d.open) return;
        d.querySelectorAll('canvas').forEach(c => { const ch = Chart.getChart(c); if (ch) ch.resize(); });
      }));
    })();
    </script>
    <?php endif; ?>

    <?php if($tab === 'import'):
        $stInv = $pdo->prepare("SELECT * FROM invoices" . ($acct !== '' ? ' WHERE billing_account = ?' : '')
                             . " ORDER BY invoice_date DESC, invoice_number DESC");
        $stInv->execute($acct !== '' ? [$acct] : []);
        $invoices = $stInv->fetchAll();
        $typeBadge = ['lines'=>['Mensuelle — détail lignes','badge-success'], 'devices'=>['Terminaux','badge-info'],
                      'manual'=>['Régularisation','badge-warning'], 'credit'=>['Avoir','badge-danger'], 'other'=>['Autre','badge-muted']];
        // Contrôle de cohérence : la somme du détail par ligne doit retomber
        // sur le total HT de la facture (au centime près).
        $lineSums = $pdo->query("SELECT invoice_id, SUM(total_ht) s FROM invoice_lines GROUP BY invoice_id")->fetchAll(PDO::FETCH_KEY_PAIR);
    ?>
    <div class="card" style="margin-bottom:1.5rem;">
      <div class="card-header"><i class="bi bi-cloud-upload"></i> Importer des factures PDF</div>
      <?php if(empty($_SESSION['is_admin'])): ?>
      <p class="muted" style="padding:1.5rem;margin:0;"><i class="bi bi-lock"></i>
        L'import des factures est réservé aux super-administrateurs : une facture mensuelle verse en base la liste
        nominative complète du parc et de ses consommations. Les onglets d'analyse restent consultables.</p>
      <?php else: ?>
      <form method="post" enctype="multipart/form-data" style="padding:1.5rem;">
        <input type="hidden" name="<?=CSRF_TOKEN_NAME?>" value="<?=h($CSRF_TOKEN)?>">
        <input type="hidden" name="_entity" value="invoice">
        <input type="hidden" name="_action" value="upload">
        <p style="color:var(--text2);font-size:.88rem;margin-bottom:1rem;line-height:1.6;">
          Déposez une ou plusieurs factures PDF de l'opérateur (multi-sélection possible). Types reconnus automatiquement :
          <span class="badge badge-success">9A… mensuelle</span> <span class="badge badge-info">9T… terminaux</span>
          <span class="badge badge-warning">9AF… régularisation</span> <span class="badge badge-danger">9AA… avoir</span>.
          Les factures déjà importées (même n°) sont ignorées — l'import est rejouable sans doublons.
        </p>
        <p style="font-size:.85rem;margin:-.4rem 0 1rem;">
          <a href="https://www.sfrbusiness.fr/espace-client/portail/#/facturation-et-paiement/societe/multiple"
             target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:6px;">
            <i class="bi bi-box-arrow-up-right"></i> Télécharger les factures sur l'espace client SFR Business</a>
          <span class="muted"> — Facturation et paiement → sélectionner la période, puis déposer les PDF ici.</span>
        </p>
        <?php if($alertGroups['missing']): ?>
        <p style="font-size:.85rem;margin:0 0 1rem;padding:.6rem .9rem;border-left:3px solid var(--warning);background:var(--bg3);border-radius:var(--radius-sm);">
          <i class="bi bi-file-earmark-x" style="color:var(--warning);"></i>
          <strong><?=count($alertGroups['missing'])?> facture(s) manquante(s)</strong> sur la période analysée :
          <?php $miss = array_slice($alertGroups['missing'], 0, 6);
                echo h(implode(' · ', array_map(fn($m) => preg_replace('/^Aucune facture importée pour /', '', $m['detail']) === $m['detail']
                    ? $m['detail'] : trim(explode('—', $m['detail'])[0]) . ' (' . $m['who'] . ')', $miss))); ?>
          <?php if(count($alertGroups['missing']) > 6): ?> et <?=count($alertGroups['missing']) - 6?> autre(s)<?php endif; ?>.
          <a href="?page=invoices&tab=alerts&<?=$qsPeriod?>&type=missing">Voir la liste complète</a>
        </p>
        <?php endif; ?>
        <div style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap;">
          <input type="file" name="file_data[]" accept=".pdf,application/pdf" multiple required
            style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.6rem;color:var(--text);flex:1;min-width:280px;">
          <button type="submit" class="btn-primary" style="display:inline-flex;align-items:center;gap:6px;"><i class="bi bi-upload"></i> Importer</button>
        </div>
      </form>
      <?php if(!empty($_SESSION['is_admin']) && $invoices): ?>
      <form method="post" style="padding:0 1.5rem 1.25rem;border-top:1px solid var(--border);"
            onsubmit="return confirm('Ré-analyser toutes les factures depuis les PDF archivés avec le parseur courant ? Le détail par ligne est reconstruit (les totaux peuvent évoluer après une mise à jour du parseur).')">
        <input type="hidden" name="<?=CSRF_TOKEN_NAME?>" value="<?=h($CSRF_TOKEN)?>">
        <input type="hidden" name="_entity" value="invoice"><input type="hidden" name="_action" value="reparse">
        <p class="muted" style="font-size:.8rem;margin:.9rem 0 .6rem;">Après une mise à jour de l'application, le bouton ci-dessous relit les PDF archivés avec la dernière version du parseur — sans re-téléverser.</p>
        <button type="submit" class="btn-secondary" style="font-size:.82rem;"><i class="bi bi-arrow-clockwise"></i> Ré-analyser toutes les factures</button>
      </form>
      <?php endif; ?>
      <?php endif; /* fin du garde super-admin sur l'import */ ?>
    </div>

    <?php if(!empty($_SESSION['is_admin'])): ?>
    <p class="muted" style="margin:-.5rem 0 1.5rem;font-size:.83rem;"><i class="bi bi-arrow-right-circle"></i>
      Les factures disent ce qui est <strong>payé</strong>. Pour contrôler ce que l'opérateur a <strong>en parc</strong>
      (titulaires, forfaits, statuts, terminaux et IMEI), utilisez
      <a href="?page=refs&tab=settings&sub=maintenance">Référentiels et Paramètres → Maintenance → Import depuis SFR</a>.</p>
    <?php endif; ?>

    <?php if(!empty($_SESSION['invoice_import_report'])):
        $rep = $_SESSION['invoice_import_report'];
        unset($_SESSION['invoice_import_report']);   // affiché une seule fois
        $repMeta = ['ok' => ['Importée', 'badge-success', 'bi-check-circle'],
                    'duplicate' => ['Déjà importée — ignorée', 'badge-warning', 'bi-copy'],
                    'error' => ['Erreur', 'badge-danger', 'bi-x-circle']];
    ?>
    <div class="card" style="margin-bottom:1.5rem;">
      <div class="card-header"><i class="bi bi-clipboard-check"></i> Compte rendu du dernier dépôt — <?=count($rep)?> fichier(s)</div>
      <table class="data-table" style="font-size:.85rem;">
        <thead><tr><th>Fichier déposé</th><th>Résultat</th><th>N° de facture</th><th>Mois</th><th>Détail</th></tr></thead>
        <tbody>
        <?php foreach($rep as $rp): [$rlbl, $rcls, $rico] = $repMeta[$rp['status'] ?? 'error'] ?? $repMeta['error']; ?>
        <tr>
          <td style="font-size:.8rem;"><?=h($rp['file'] ?? '—')?></td>
          <td><span class="badge <?=$rcls?>" style="font-size:.68rem;"><i class="bi <?=$rico?>"></i> <?=$rlbl?></span></td>
          <td style="font-family:var(--font-mono);font-size:.8rem;"><?=h($rp['invoice_number'] ?? '—')?></td>
          <td><?=h($fmtMois($rp['month_key'] ?? ($rp['existing']['month_key'] ?? null)))?></td>
          <td class="muted" style="font-size:.8rem;">
            <?php if(($rp['status'] ?? '') === 'ok'): ?>
              <?=(int)($rp['nb_lines'] ?? 0)?> ligne(s)<?php if(!empty($rp['nb_devices'])): ?>, <?=(int)$rp['nb_devices']?> matériel(s)<?php endif; ?>
              <?php if(isset($rp['total_ttc'])): ?> · <?=$fmtEur($rp['total_ttc'])?> TTC<?php endif; ?>
              <?php if(!empty($rp['message'])): ?><br><span style="color:var(--warning);"><i class="bi bi-exclamation-triangle"></i> <?=h($rp['message'])?></span><?php endif; ?>
            <?php elseif(($rp['status'] ?? '') === 'duplicate'): ?>
              déjà en base<?php if(!empty($rp['existing']['imported_at'])): ?> depuis le <?=date('d/m/Y', strtotime($rp['existing']['imported_at']))?>
              <?php if(!empty($rp['existing']['imported_by'])): ?>(<?=h($rp['existing']['imported_by'])?>)<?php endif; ?><?php endif; ?>
            <?php else: ?>
              <?=h($rp['message'] ?? 'erreur')?>
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <p class="muted" style="padding:.75rem 1.4rem 1rem;margin:0;font-size:.79rem;"><i class="bi bi-info-circle"></i>
        Le contrôle des doublons porte sur le numéro de facture : redéposer un dossier complet est sans risque, seules les factures nouvelles sont ajoutées.</p>
    </div>
    <?php endif; ?>

    <?php if(count($accounts) > 1): ?>
    <form method="get" style="display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem;">
      <input type="hidden" name="page" value="invoices"><input type="hidden" name="tab" value="import">
      <label style="margin:0;">Compte de facturation</label>
      <select name="acct" onchange="this.form.submit()" style="width:auto;">
        <option value="">Tous les comptes (<?=array_sum(array_column($accountRows, 'nb'))?> factures)</option>
        <?php foreach($accountRows as $ar): ?>
        <option value="<?=h($ar['acc'])?>" <?=$ar['acc']===$acct?'selected':''?>><?=h($ar['acc'] . ($ar['label'] ? " — {$ar['label']}" : ''))?> (<?=(int)$ar['nb']?> factures)</option>
        <?php endforeach; ?>
      </select>
    </form>
    <?php endif; ?>
    <div class="search-bar-wrap">
      <div class="search-bar"><span class="search-bar-icon"><i class="bi bi-search"></i></span><input type="text" placeholder="Filtrer par n°, compte, mois..." oninput="tableSearch(this,'tbody-inv','count-inv')"></div>
      <div class="search-count" id="count-inv"></div>
    </div>
    <div class="card" style="overflow-x:auto;">
      <table class="data-table">
        <thead><tr><th>N° de facture</th><th>Type</th><th>Compte</th><th>Date</th><th>Mois conso</th><th>Total HT</th><th>Total TTC</th><th>Lignes</th><th>Contrôle</th><th>Importée</th><th>Actions</th></tr></thead>
        <tbody id="tbody-inv">
        <?php if(!$invoices): ?><tr><td colspan="11" class="empty-cell">Aucune facture importée</td></tr><?php endif; ?>
        <?php foreach($invoices as $inv): [$tl,$tc] = $typeBadge[$inv['invoice_type']] ?? $typeBadge['other']; ?>
        <tr>
          <td style="font-family:var(--font-mono);font-size:.85rem;"><?=h($inv['invoice_number'])?></td>
          <td><span class="badge <?=$tc?>"><?=$tl?></span></td>
          <td class="muted"><?=h($inv['billing_account'] ?: '—')?></td>
          <td><?=$inv['invoice_date'] ? date('d/m/Y', strtotime($inv['invoice_date'])) : '—'?></td>
          <td><?=$inv['invoice_type']==='lines' ? h($fmtMois($inv['month_key'])) : '—'?></td>
          <td style="font-weight:600;"><?=$inv['total_ht'] !== null ? $fmtEur($inv['total_ht']) : '—'?></td>
          <td><?=$inv['total_ttc'] !== null ? $fmtEur($inv['total_ttc']) : '—'?></td>
          <td><?=$inv['invoice_type']==='lines' ? (int)$inv['nb_lines'] : '—'?></td>
          <td>
            <?php if($inv['invoice_type'] === 'lines' && $inv['total_ht'] !== null):
                $diff = round((float)($lineSums[$inv['id']] ?? 0) - (float)$inv['total_ht'], 2); ?>
              <?php if(abs($diff) < 0.02): ?>
                <span class="badge badge-success" title="La somme du détail par ligne égale le total de la facture"><i class="bi bi-check-lg"></i> détail = total</span>
              <?php else: ?>
                <span class="badge badge-warning" title="Somme du détail par ligne : <?=h($fmtEur($lineSums[$inv['id']] ?? 0))?>"><i class="bi bi-exclamation-triangle"></i> écart <?=h($fmtEur($diff))?></span>
              <?php endif; ?>
            <?php else: ?>—<?php endif; ?>
          </td>
          <td class="muted" style="font-size:.78rem;"><?=date('d/m/Y', strtotime($inv['imported_at']))?><br><?=h($inv['imported_by'] ?: '')?></td>
          <td class="actions">
            <?php if($inv['pdf_path']): ?><a class="btn-icon" title="Ouvrir le PDF archivé (accès authentifié)" href="?page=invoice_pdf&id=<?=(int)$inv['id']?>" target="_blank" style="text-decoration:none;"><i class="bi bi-filetype-pdf"></i></a><?php endif; ?>
            <?php if(!empty($_SESSION['is_admin'])): ?>
            <form method="post" style="display:inline" onsubmit="return confirm('Supprimer cette facture et tout son détail par ligne ?')">
              <input type="hidden" name="<?=CSRF_TOKEN_NAME?>" value="<?=h($CSRF_TOKEN)?>">
              <input type="hidden" name="_entity" value="invoice"><input type="hidden" name="_action" value="delete">
              <input type="hidden" name="_id" value="<?=$inv['id']?>">
              <button type="submit" class="btn-icon btn-del" title="Supprimer"><i class="bi bi-trash3"></i></button>
            </form>
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    <?php endif; ?>

    <?php if($tab === 'reconcile' && $months):
        // Rapprochement du mois sélectionné : facture ↔ référentiel.
        $factLines = $accQuery("SELECT l.* FROM invoice_lines l
                WHERE l.month_key = ? $accWhere ORDER BY l.phone_number", [$selMonth])->fetchAll();
        $factPhones = [];
        $rows = [];
        // Similarité de noms : règle unique de l'application (invoice_lib.php),
        // partagée avec le contrôle de l'état de parc SFR. Le libellé SFR peut
        // contenir du texte en plus : si le nom et le prénom du référentiel
        // s'y retrouvent, c'est une concordance.
        $nameMatch = fn(string $sfr, string $ln, string $fn): bool =>
            simcity_name_matches($sfr, trim($ln . ' ' . $fn)) || simcity_name_found_in($sfr, $ln, $fn);
        foreach ($factLines as $fl) {
            $phone = $fl['phone_number'];
            $factPhones[$phone] = true;
            $app = $appLines[$phone] ?? null;
            $isGeneric = (bool)preg_match('/^(Autr|AUTRE)/i', trim((string)$fl['sfr_user']));
            if (!$app) {
                $status = 'unknown_app';
            } elseif ($app['archived']) {
                $status = 'archived_app';
            } elseif ($isGeneric || trim($app['ln'] . $app['fn']) === '') {
                // Ligne de service côté SFR ou sans agent côté SimCity : on ne
                // peut comparer aucun nom nominal — signalé neutre.
                $status = ($isGeneric && trim($app['ln'] . $app['fn']) === '') ? 'ok' : 'neutral';
            } else {
                $status = $nameMatch((string)$fl['sfr_user'], (string)$app['ln'], (string)$app['fn']) ? 'ok' : 'diff';
            }
            $rows[] = ['phone'=>$phone, 'sfr'=>$fl['sfr_user'], 'plan'=>$fl['plan_name'], 'ht'=>$fl['total_ht'],
                       'app'=>$app, 'status'=>$status];
        }
        // Lignes SimCity actives absentes de la facture du mois. Sont exclues
        // celles qui n'ont normalement pas de facture : résiliées, en stock,
        // suspendues, et les SIM vierges (numéro non encore activé).
        // Quand un compte de facturation est sélectionné, seules les lignes
        // rattachées à ce compte dans le référentiel sont comparables.
        $missingHidden = 0;
        foreach ($appLines as $phone => $app) {
            if (isset($factPhones[$phone]) || $app['archived']) continue;
            if (in_array($app['status'], ['Resiliated', 'Stock', 'Suspended'], true)) continue;
            if (!empty($app['sim_vierge'])) continue;
            if ($acct !== '' && $app['acct'] !== $acct) { $missingHidden++; continue; }
            $rows[] = ['phone'=>$phone, 'sfr'=>null, 'plan'=>null, 'ht'=>null, 'app'=>$app, 'status'=>'missing_inv'];
        }
        $statusMeta = [
            'ok'          => ['OK — noms concordants',              'badge-success', 'bi-check-circle'],
            'neutral'     => ['Ligne de service / sans agent',      'badge-muted',   'bi-dash-circle'],
            'diff'        => ['Nom différent SFR ↔ SimCity',        'badge-warning', 'bi-exclamation-triangle'],
            'unknown_app' => ['Facturée mais inconnue de SimCity',  'badge-danger',  'bi-question-circle'],
            'archived_app'=> ['Facturée mais archivée dans SimCity','badge-danger',  'bi-archive'],
            'missing_inv' => ['Dans SimCity mais absente de la facture', 'badge-info', 'bi-eye-slash'],
        ];
        $counts = array_fill_keys(array_keys($statusMeta), 0);
        foreach ($rows as $r) $counts[$r['status']]++;
        $filter = $_GET['status'] ?? '';
    ?>
    <?=$periodPicker('reconcile', $filter !== '' ? ['status' => $filter] : [])?>
    <p class="muted" style="margin:-.5rem 0 1rem;font-size:.82rem;">Rapprochement de la facture de <strong><?=h($fmtMois($selMonth))?></strong>
      (mois d'arrivée de la période), compte <strong><?=h($acctLabel)?></strong>, avec le référentiel SimCity.
      <?php if($missingHidden): ?><br><i class="bi bi-info-circle"></i> <?=$missingHidden?> ligne(s) SimCity ne sont pas rattachées à ce compte de facturation dans le référentiel : elles ne sont pas comparables et restent masquées.<?php endif; ?></p>
    <div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap;margin-bottom:1rem;">
      <div style="display:flex;gap:.5rem;flex-wrap:wrap;">
        <a href="?page=invoices&tab=reconcile&<?=$qsPeriod?>" class="badge <?=$filter===''?'badge-info':'badge-muted'?>" style="text-decoration:none;">Tout (<?=count($rows)?>)</a>
        <?php foreach($statusMeta as $k => [$lbl, $cls]): if(!$counts[$k]) continue; ?>
        <a href="?page=invoices&tab=reconcile&<?=$qsPeriod?>&status=<?=$k?>" class="badge <?=$filter===$k?$cls:'badge-muted'?>" style="text-decoration:none;"><?=$lbl?> (<?=$counts[$k]?>)</a>
        <?php endforeach; ?>
      </div>
    </div>
    <div class="search-bar-wrap">
      <div class="search-bar"><span class="search-bar-icon"><i class="bi bi-search"></i></span><input type="text" placeholder="Filtrer par numéro, nom..." oninput="tableSearch(this,'tbody-rec','count-rec')"></div>
      <div class="search-count" id="count-rec"></div>
    </div>
    <div class="card" style="overflow-x:auto;">
      <table class="data-table">
        <thead><tr><th>Ligne</th><th>Nom sur la facture (SFR)</th><th>Utilisateur SimCity</th><th>Service</th><th>Forfait facturé</th><th>HT mois</th><th>Statut</th><th>Actions</th></tr></thead>
        <tbody id="tbody-rec">
        <?php $shown = 0; foreach($rows as $r): if($filter !== '' && $r['status'] !== $filter) continue; $shown++;
            [$lbl, $cls, $ico] = $statusMeta[$r['status']]; $app = $r['app']; ?>
        <tr>
          <td style="font-family:var(--font-mono);white-space:nowrap;"><a href="?page=invoices&tab=conso&line=<?=h($r['phone'])?>"><?=h(formatPhone($r['phone']))?></a></td>
          <td><?=h($r['sfr'] ?: '—')?></td>
          <td><?=$app ? h(trim($app['ln'].' '.$app['fn']) ?: '—') : '—'?></td>
          <td class="muted"><?=$app ? h($app['service_name'] ?: '—') : '—'?></td>
          <td class="muted"><?=h($r['plan'] ?: '—')?></td>
          <td><?=$r['ht'] !== null ? $fmtEur($r['ht']) : '—'?></td>
          <td><span class="badge <?=$cls?>"><i class="bi <?=$ico?>"></i> <?=$lbl?></span></td>
          <td class="actions">
            <?php if($app): ?><a class="btn-icon" title="Voir la ligne dans SimCity" href="?page=lines&tab=active&q=<?=urlencode(formatPhone($r['phone']))?>" style="text-decoration:none;"><i class="bi bi-telephone"></i></a><?php endif; ?>
            <?php if($r['status'] === 'unknown_app'): /* Ligne facturée absente du parc : la créer sans ressaisir le numéro */ ?>
            <a class="btn-icon" title="Ajouter cette ligne dans SimCity" style="text-decoration:none;color:var(--success);"
               href="?page=lines&tab=active&open=modal-add-line&phone=<?=urlencode($r['phone'])?>"><i class="bi bi-plus-circle"></i></a>
            <?php endif; ?>
            <?php if($app && $app['agent_id']): ?><button class="btn-icon" title="Fiche utilisateur" onclick="viewAgent(<?=$app['agent_id']?>, '<?=h(addslashes($app['fn'].' '.$app['ln']))?>')"><i class="bi bi-person"></i></button><?php endif; ?>
          </td>
        </tr>
        <?php endforeach; if(!$shown): ?><tr><td colspan="8" class="empty-cell">Aucune ligne pour ce filtre</td></tr><?php endif; ?>
        </tbody>
      </table>
    </div>
    <p class="muted" style="margin-top:.75rem;font-size:.8rem;"><i class="bi bi-info-circle"></i>
      « Nom différent » : mettez à jour la fiche SimCity, ou faites corriger le nom chez SFR (espace client / commercial) pour retrouver un rapprochement propre.
      « Facturée mais inconnue » : ligne payée qui n'est pas dans votre parc — à vérifier en priorité (résiliation oubliée ?).
      Le bouton <i class="bi bi-plus-circle" style="color:var(--success);"></i> ouvre la création de la ligne dans SimCity, numéro déjà rempli.<br>
      <i class="bi bi-arrow-right-circle"></i> Ce rapprochement porte sur ce qui est <strong>facturé</strong>. Pour comparer avec l'état de parc
      de l'opérateur (forfaits, statuts, terminaux, IMEI), voir
      <a href="?page=refs&tab=settings&sub=maintenance">Référentiels et Paramètres → Maintenance → Import depuis SFR</a>.</p>
    <?php endif; ?>

    <?php if($tab === 'conso' && $months):
        // Règle unique de l'application : le numéro reçu en paramètre peut venir
        // du référentiel (« +33 6… », espaces, points) — il doit être canonisé
        // comme partout ailleurs, sinon la ligne paraît sans facture.
        $detailPhone = simcity_phone_canon((string)($_GET['line'] ?? ''));
        if ($detailPhone !== ''):
            $st = $pdo->prepare("SELECT * FROM invoice_lines WHERE phone_number=? ORDER BY month_key");
            $st->execute([$detailPhone]);
            $hist = $st->fetchAll();
            $app = $appLines[$detailPhone] ?? null;
    ?>
      <p style="margin-bottom:1rem;"><a href="?page=invoices&tab=conso&<?=$qsPeriod?>" class="btn-secondary" style="text-decoration:none;font-size:.82rem;padding:.4rem .9rem;"><i class="bi bi-arrow-left"></i> Toutes les lignes</a></p>
      <?php if(!$hist): ?>
        <div class="card" style="padding:2rem;text-align:center;color:var(--text2);">Aucune donnée de facturation pour <?=h(formatPhone($detailPhone))?>.</div>
      <?php else: $last = end($hist); ?>
      <div class="card" style="margin-bottom:1.5rem;padding:1.25rem 1.5rem;display:flex;gap:2rem;flex-wrap:wrap;align-items:center;">
        <div><div style="font-family:var(--font-mono);font-size:1.35rem;font-weight:700;color:var(--primary);"><?=h(formatPhone($detailPhone))?></div>
             <div class="muted"><?=h($last['sfr_user'] ?: '—')?> <span style="opacity:.6;">(nom SFR)</span></div></div>
        <?php if($app): ?>
        <div><div style="font-weight:600;"><?=h(trim($app['ln'].' '.$app['fn']) ?: 'Sans agent')?></div>
             <div class="muted"><i class="bi bi-building"></i> <?=h($app['service_name'] ?: 'Aucun service')?> · statut <?=h($app['status'])?></div></div>
        <?php else: ?>
        <div><span class="badge badge-danger"><i class="bi bi-question-circle"></i> Inconnue de SimCity</span></div>
        <?php endif; ?>
        <div style="margin-left:auto;"><div class="muted">Forfait (dernier mois)</div><div style="font-weight:600;"><?=h($last['plan_name'] ?: '—')?></div></div>
      </div>
      <div class="card" style="margin-bottom:1.5rem;">
        <div class="card-header"><i class="bi bi-bar-chart-line"></i> Évolution mensuelle</div>
        <div style="padding:1rem;height:280px;"><canvas id="invLine"></canvas></div>
      </div>
      <div class="card" style="overflow-x:auto;">
        <table class="data-table">
          <thead><tr><th>Mois</th><th>Forfait</th><th>Appels</th><th>Durée</th><th>SMS</th><th>MMS</th><th>Data</th><th>Surtaxés</th><th>International</th><th>Hors-forfait</th><th>Abo HT</th><th>Total HT</th></tr></thead>
          <tbody>
          <?php foreach(array_reverse($hist) as $hrow): ?>
            <tr>
              <td style="font-weight:600;"><?=h($fmtMois($hrow['month_key']))?></td>
              <td class="muted" style="font-size:.8rem;"><?=h($hrow['plan_name'] ?: '—')?></td>
              <td><?=(int)$hrow['calls_count']?></td>
              <td><?=$fmtDur((int)$hrow['calls_seconds'])?></td>
              <td><?=(int)$hrow['sms_count'] ?: '—'?></td>
              <td><?=(int)$hrow['mms_count'] ?: '—'?></td>
              <td><?=$fmtData((int)$hrow['data_ko'])?></td>
              <td style="color:<?=(float)$hrow['surtaxe_ht']>0?'var(--danger)':'inherit'?>;"><?=(float)$hrow['surtaxe_ht']>0 ? $fmtEur($hrow['surtaxe_ht']).' ('.$hrow['surtaxe_count'].')' : '—'?></td>
              <td style="color:<?=(float)$hrow['intl_ht']>0?'var(--danger)':'inherit'?>;"><?=(float)$hrow['intl_ht']>0 ? $fmtEur($hrow['intl_ht']).' ('.$hrow['intl_count'].')' : ((int)$hrow['intl_count'] ? $hrow['intl_count'].' app.' : '—')?></td>
              <td style="color:<?=(float)$hrow['hf_ht']>0?'var(--warning)':'inherit'?>;font-weight:600;"><?=(float)$hrow['hf_ht']>0 ? $fmtEur($hrow['hf_ht']) : '—'?></td>
              <td><?=$fmtEur($hrow['abo_ht'])?></td>
              <td style="font-weight:700;"><?=$fmtEur($hrow['total_ht'])?></td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <script src="vendor/chart.umd.min.js"></script>
      <script>
      (function(){
        const el = document.getElementById('invLine'); if(!el) return;
        new Chart(el, {
          data:{labels:<?=json_encode(array_map($fmtMois, array_column($hist,'month_key')))?>,
            datasets:[
              {type:'bar', label:'Data (Go)', yAxisID:'y', data:<?=json_encode(array_map(fn($r)=>round($r['data_ko']/1048576,2), $hist))?>, backgroundColor:'rgba(79,70,229,.55)', borderRadius:4},
              {type:'bar', label:'Appels (h)', yAxisID:'y', data:<?=json_encode(array_map(fn($r)=>round($r['calls_seconds']/3600,2), $hist))?>, backgroundColor:'rgba(8,145,178,.55)', borderRadius:4},
              {type:'line', label:'Coût total € HT', yAxisID:'y2', data:<?=json_encode(array_map(fn($r)=>round((float)$r['total_ht'],2), $hist))?>, borderColor:'#f59e0b', backgroundColor:'#f59e0b', tension:.25}
            ]},
          options:{responsive:true,maintainAspectRatio:false,
            scales:{x:{ticks:{color:'#94a3b8'},grid:{display:false}},
                    y:{beginAtZero:true,position:'left',ticks:{color:'#94a3b8'},grid:{color:'rgba(148,163,184,.15)'}},
                    y2:{beginAtZero:true,position:'right',ticks:{color:'#f59e0b'},grid:{display:false}}},
            plugins:{legend:{labels:{color:'#94a3b8'}}}}});
      })();
      </script>
      <?php endif; ?>
    <?php else:
        // ── Consommations cumulées sur la période, une ligne par numéro ──
        // Filtres, tri et pagination sont faits en SQL sur une table dérivée :
        // les totaux du pied de tableau portent donc sur TOUTE la sélection
        // filtrée, pas seulement sur la page affichée.
        $ph = implode(',', array_fill(0, count($axis), '?'));
        // Le service vient du référentiel : rapprochement sur le numéro
        // canonique (règle unique de l'application, +33 compris).
        $norm = sprintf(SIMCITY_SQL_PHONE_CANON, 'ml.phone_number');
        $derived = "SELECT l.phone_number, COUNT(*) nbm,
                SUM(l.calls_count) calls_count, SUM(l.calls_seconds) calls_seconds,
                SUM(l.sms_count) sms_count, SUM(l.mms_count) mms_count, SUM(l.data_ko) data_ko,
                SUM(l.surtaxe_ht) surtaxe_ht, SUM(l.surtaxe_count) surtaxe_count,
                SUM(l.intl_ht) intl_ht, SUM(l.intl_count) intl_count,
                SUM(l.hf_ht) hf_ht, SUM(l.abo_ht) abo_ht, SUM(l.total_ht) total_ht,
                MAX(l.catalog_ht) catalog_ht, MAX(l.remise_pct) remise_pct,
                (SELECT x.sfr_user  FROM invoice_lines x WHERE x.phone_number = l.phone_number AND x.month_key <= ? ORDER BY x.month_key DESC LIMIT 1) sfr_user,
                (SELECT y.plan_name FROM invoice_lines y WHERE y.phone_number = l.phone_number AND y.month_key <= ? ORDER BY y.month_key DESC LIMIT 1) plan_name,
                (SELECT IFNULL(s.name,'') FROM mobile_lines ml LEFT JOIN agents a2 ON ml.agent_id=a2.id
                    LEFT JOIN services s ON COALESCE(ml.service_id, a2.service_id)=s.id
                    WHERE $norm = l.phone_number AND ml.archived=0 LIMIT 1) service_name,
                (SELECT COUNT(*) FROM mobile_lines ml WHERE $norm = l.phone_number AND ml.archived=0) in_app
            FROM invoice_lines l WHERE l.month_key IN ($ph) $accWhere
            GROUP BY l.phone_number";
        $baseArgs = array_merge([$axisTo, $axisTo], $axis, $accArgs);

        // Filtres avancés
        $fq    = trim((string)($_GET['q'] ?? ''));
        $fplan = (string)($_GET['plan'] ?? '');
        $fsvc  = (string)($_GET['svc'] ?? '');
        $fflag = (string)($_GET['flag'] ?? '');
        $flagDefs = [
            'hf'      => 'Hors-forfait > 0',
            'intl'    => 'International > 0',
            'surtaxe' => 'Surtaxés > 0',
            'zero'    => 'Aucune consommation',
            'unknown' => 'Inconnue de SimCity',
            'nosvc'   => 'Sans service renseigné',
        ];
        if (!isset($flagDefs[$fflag])) $fflag = '';
        $where = []; $wArgs = [];
        if ($fq !== '') {
            $where[] = "(t.phone_number LIKE ? OR t.sfr_user LIKE ? OR t.plan_name LIKE ? OR t.service_name LIKE ?)";
            $like = '%' . preg_replace('/\s+/', '%', $fq) . '%';
            array_push($wArgs, $like, $like, $like, $like);
        }
        if ($fplan !== '') { $where[] = "t.plan_name = ?";    $wArgs[] = $fplan; }
        if ($fsvc  !== '') { $where[] = "t.service_name = ?";  $wArgs[] = $fsvc; }
        if ($fflag === 'hf')      $where[] = "t.hf_ht > 0";
        if ($fflag === 'intl')    $where[] = "t.intl_ht > 0";
        if ($fflag === 'surtaxe') $where[] = "t.surtaxe_ht > 0";
        if ($fflag === 'zero')    $where[] = "(t.calls_count + t.sms_count + t.mms_count + t.data_ko + t.intl_count + t.surtaxe_count) = 0";
        if ($fflag === 'unknown') $where[] = "t.in_app = 0";
        if ($fflag === 'nosvc')   $where[] = "t.in_app > 0 AND t.service_name = ''";
        $wSql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

        // Tri (colonnes en liste blanche)
        $sortDefs = ['total' => 't.total_ht', 'phone' => 't.phone_number', 'user' => 't.sfr_user',
                     'svc' => 't.service_name', 'plan' => 't.plan_name', 'hf' => 't.hf_ht',
                     'data' => 't.data_ko', 'sms' => 't.sms_count', 'calls' => 't.calls_seconds',
                     'intl' => 't.intl_ht', 'surtaxe' => 't.surtaxe_ht'];
        $sort = isset($sortDefs[$_GET['sort'] ?? '']) ? $_GET['sort'] : 'total';
        $dir  = (($_GET['dir'] ?? 'desc') === 'asc') ? 'ASC' : 'DESC';

        // Totaux sur toute la sélection filtrée (indépendants de la page)
        $tot = $pdo->prepare("SELECT COUNT(*) n, IFNULL(SUM(t.total_ht),0) ht, IFNULL(SUM(t.abo_ht),0) abo,
                IFNULL(SUM(t.hf_ht),0) hf, IFNULL(SUM(t.surtaxe_ht),0) sx, IFNULL(SUM(t.intl_ht),0) it,
                IFNULL(SUM(t.data_ko),0) ko, IFNULL(SUM(t.sms_count),0) sms, IFNULL(SUM(t.calls_seconds),0) secs,
                IFNULL(SUM(t.calls_count),0) nbc FROM ($derived) t $wSql");
        $tot->execute(array_merge($baseArgs, $wArgs));
        $tot = $tot->fetch();

        // Pagination — « per=all » (0 en interne) affiche toute la sélection d'un coup
        $per  = ($_GET['per'] ?? '') === 'all' ? 0 : (int)($_GET['per'] ?? 50);
        if (!in_array($per, [0, 25, 50, 100, 500], true)) $per = 50;
        $nbRows = (int)$tot['n'];
        $pages  = $per ? max(1, (int)ceil($nbRows / $per)) : 1;
        $pageNo = max(1, min($pages, (int)($_GET['p'] ?? 1)));
        $off    = ($pageNo - 1) * $per;

        $st = $pdo->prepare("SELECT t.* FROM ($derived) t $wSql
                ORDER BY {$sortDefs[$sort]} $dir, t.phone_number" . ($per ? " LIMIT $per OFFSET $off" : ''));
        $st->execute(array_merge($baseArgs, $wArgs));
        $consoRows = $st->fetchAll();

        // Valeurs proposées dans les listes de filtres (sur la période/compte)
        $optSt = $pdo->prepare("SELECT t.plan_name, t.service_name, COUNT(*) n FROM ($derived) t
                GROUP BY t.plan_name, t.service_name");
        $optSt->execute($baseArgs);
        $optPlans = $optSvcs = [];
        foreach ($optSt as $o) {
            if (($o['plan_name'] ?? '') !== '') $optPlans[$o['plan_name']] = ($optPlans[$o['plan_name']] ?? 0) + (int)$o['n'];
            if (($o['service_name'] ?? '') !== '') $optSvcs[$o['service_name']] = ($optSvcs[$o['service_name']] ?? 0) + (int)$o['n'];
        }
        ksort($optPlans); ksort($optSvcs);

        $multi = count($monthsInPeriod) > 1;
        $keepQs = ['page' => 'invoices', 'tab' => 'conso', 'from' => (string)$axisFrom, 'to' => (string)$axisTo]
                + ($acct !== '' ? ['acct' => $acct] : [])
                + ($fq !== '' ? ['q' => $fq] : []) + ($fplan !== '' ? ['plan' => $fplan] : [])
                + ($fsvc !== '' ? ['svc' => $fsvc] : []) + ($fflag !== '' ? ['flag' => $fflag] : [])
                + ['sort' => $sort, 'dir' => strtolower($dir), 'per' => $per ?: 'all'];
        $lnk = fn(array $over = []) => '?' . http_build_query(array_merge($keepQs, $over));
        $sortLnk = fn(string $col) => $lnk(['sort' => $col, 'dir' => ($sort === $col && $dir === 'DESC') ? 'asc' : 'desc', 'p' => 1]);
        $sortIco = fn(string $col) => $sort === $col ? ' <i class="bi bi-caret-' . ($dir === 'DESC' ? 'down' : 'up') . '-fill" style="font-size:.7rem;"></i>' : '';
    ?>
      <?=$periodPicker('conso', array_intersect_key($keepQs, array_flip(['q','plan','svc','flag','sort','dir','per'])))?>

      <form method="get" style="display:flex;align-items:flex-end;gap:.75rem;flex-wrap:wrap;margin-bottom:1rem;">
        <input type="hidden" name="page" value="invoices"><input type="hidden" name="tab" value="conso">
        <input type="hidden" name="from" value="<?=h((string)$axisFrom)?>"><input type="hidden" name="to" value="<?=h((string)$axisTo)?>">
        <?php if($acct !== ''): ?><input type="hidden" name="acct" value="<?=h($acct)?>"><?php endif; ?>
        <input type="hidden" name="sort" value="<?=h($sort)?>"><input type="hidden" name="dir" value="<?=h(strtolower($dir))?>">
        <div class="form-group" style="margin:0;min-width:220px;flex:1;">
          <label style="font-size:.78rem;">Recherche</label>
          <input type="text" name="q" value="<?=h($fq)?>" placeholder="numéro, nom, forfait, service...">
        </div>
        <div class="form-group" style="margin:0;">
          <label style="font-size:.78rem;">Forfait</label>
          <select name="plan" style="width:auto;max-width:250px;">
            <option value="">Tous (<?=array_sum($optPlans)?>)</option>
            <?php foreach($optPlans as $p => $n): ?><option value="<?=h($p)?>" <?=$p===$fplan?'selected':''?>><?=h($p)?> (<?=$n?>)</option><?php endforeach; ?>
          </select>
        </div>
        <div class="form-group" style="margin:0;">
          <label style="font-size:.78rem;">Service</label>
          <select name="svc" style="width:auto;max-width:220px;">
            <option value="">Tous<?=$optSvcs ? ' (' . array_sum($optSvcs) . ')' : ''?></option>
            <?php foreach($optSvcs as $s => $n): ?><option value="<?=h($s)?>" <?=$s===$fsvc?'selected':''?>><?=h($s)?> (<?=$n?>)</option><?php endforeach; ?>
          </select>
        </div>
        <div class="form-group" style="margin:0;">
          <label style="font-size:.78rem;">Signalement</label>
          <select name="flag" style="width:auto;">
            <option value="">Aucun filtre</option>
            <?php foreach($flagDefs as $k => $lbl): ?><option value="<?=h($k)?>" <?=$k===$fflag?'selected':''?>><?=h($lbl)?></option><?php endforeach; ?>
          </select>
        </div>
        <div class="form-group" style="margin:0;">
          <label style="font-size:.78rem;">Par page</label>
          <select name="per" style="width:auto;">
            <?php foreach([25,50,100,500] as $pp): ?><option value="<?=$pp?>" <?=$pp===$per?'selected':''?>><?=$pp?></option><?php endforeach; ?>
            <option value="all" <?=$per===0?'selected':''?>>Tout</option>
          </select>
        </div>
        <button type="submit" class="btn-primary" style="font-size:.85rem;"><i class="bi bi-funnel"></i> Filtrer</button>
        <?php if($fq !== '' || $fplan !== '' || $fsvc !== '' || $fflag !== ''): ?>
        <a href="?page=invoices&tab=conso&<?=$qsPeriod?>" class="btn-secondary" style="font-size:.85rem;text-decoration:none;"><i class="bi bi-x-lg"></i> Effacer</a>
        <?php endif; ?>
      </form>

      <p class="muted" style="margin:-.4rem 0 1rem;font-size:.82rem;">
        <strong><?=$nbRows?></strong> ligne(s) retenue(s)<?=$fq !== '' || $fplan !== '' || $fsvc !== '' || $fflag !== '' ? ' après filtrage' : ''?>
        sur <?=h($periodLabel)?><?=$multi ? ' (cumul de ' . count($monthsInPeriod) . ' mois)' : ''?><?=$acct !== '' ? ', compte ' . h($acctLabel) : ''?> —
        total <strong><?=$fmtEur($tot['ht'])?> HT</strong>. Les totaux du pied de tableau portent sur l'ensemble de la sélection, pas sur la page affichée.
        Cliquez sur un numéro pour son historique détaillé.</p>

      <div class="card" style="overflow-x:auto;">
        <table class="data-table">
          <thead><tr>
            <th><a href="<?=h($sortLnk('phone'))?>">Ligne<?=$sortIco('phone')?></a></th>
            <th><a href="<?=h($sortLnk('user'))?>">Utilisateur (SFR)<?=$sortIco('user')?></a></th>
            <th><a href="<?=h($sortLnk('svc'))?>">Service (SimCity)<?=$sortIco('svc')?></a></th>
            <th><a href="<?=h($sortLnk('plan'))?>">Forfait<?=$sortIco('plan')?></a></th>
            <?php if($multi): ?><th style="text-align:right;">Mois</th><?php endif; ?>
            <th><a href="<?=h($sortLnk('calls'))?>">Appels<?=$sortIco('calls')?></a></th>
            <th style="text-align:right;"><a href="<?=h($sortLnk('sms'))?>">SMS<?=$sortIco('sms')?></a></th>
            <th style="text-align:right;"><a href="<?=h($sortLnk('data'))?>">Data<?=$sortIco('data')?></a></th>
            <th style="text-align:right;"><a href="<?=h($sortLnk('surtaxe'))?>">Surtaxés<?=$sortIco('surtaxe')?></a></th>
            <th style="text-align:right;"><a href="<?=h($sortLnk('intl'))?>">International<?=$sortIco('intl')?></a></th>
            <th style="text-align:right;"><a href="<?=h($sortLnk('hf'))?>">Hors-forfait<?=$sortIco('hf')?></a></th>
            <th style="text-align:right;"><a href="<?=h($sortLnk('total'))?>">Total HT<?=$sortIco('total')?></a></th>
          </tr></thead>
          <tbody id="tbody-conso">
          <?php if(!$consoRows): ?><tr><td colspan="12" class="empty-cell">Aucune ligne ne correspond aux filtres</td></tr><?php endif; ?>
          <?php foreach($consoRows as $c): ?>
          <tr>
            <td style="font-family:var(--font-mono);white-space:nowrap;"><a href="?page=invoices&tab=conso&<?=$qsPeriod?>&line=<?=h($c['phone_number'])?>" title="Historique de la ligne"><?=h(formatPhone($c['phone_number']))?></a></td>
            <td><?=h($c['sfr_user'] ?: '—')?></td>
            <td class="muted"><?=(int)$c['in_app'] ? h($c['service_name'] ?: '—') : '<span class="badge badge-danger" style="font-size:.65rem;">hors SimCity</span>'?></td>
            <td class="muted" style="font-size:.8rem;"><?=h($c['plan_name'] ?: '—')?></td>
            <?php if($multi): ?><td class="muted" style="text-align:right;"><?=(int)$c['nbm']?></td><?php endif; ?>
            <td><?=(int)$c['calls_count']?> <span class="muted">(<?=$fmtDur((int)$c['calls_seconds'])?>)</span></td>
            <td style="text-align:right;"><?=(int)$c['sms_count'] ?: '—'?></td>
            <td style="text-align:right;"><?=$fmtData((int)$c['data_ko'])?></td>
            <td style="text-align:right;color:<?=(float)$c['surtaxe_ht']>0?'var(--danger)':'inherit'?>;"><?=(float)$c['surtaxe_ht']>0 ? $fmtEur($c['surtaxe_ht']) : '—'?></td>
            <td style="text-align:right;color:<?=(float)$c['intl_ht']>0?'var(--danger)':'inherit'?>;"><?=(float)$c['intl_ht']>0 ? $fmtEur($c['intl_ht']) : ((int)$c['intl_count'] ? $c['intl_count'].' app.' : '—')?></td>
            <td style="text-align:right;color:<?=(float)$c['hf_ht']>0?'var(--warning)':'inherit'?>;font-weight:600;"><?=(float)$c['hf_ht']>0 ? $fmtEur($c['hf_ht']) : '—'?></td>
            <td style="text-align:right;font-weight:700;"><?=$fmtEur($c['total_ht'])?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
          <tfoot><tr style="border-top:2px solid var(--border);font-weight:700;">
            <td colspan="<?=$multi ? 5 : 4?>">Total de la sélection — <?=$nbRows?> ligne(s)</td>
            <td><?=number_format((int)$tot['nbc'], 0, ',', ' ')?> <span class="muted" style="font-weight:400;">(<?=$fmtDur((int)$tot['secs'])?>)</span></td>
            <td style="text-align:right;"><?=number_format((int)$tot['sms'], 0, ',', ' ')?></td>
            <td style="text-align:right;"><?=$fmtData((int)$tot['ko'])?></td>
            <td style="text-align:right;"><?=$fmtEur($tot['sx'])?></td>
            <td style="text-align:right;"><?=$fmtEur($tot['it'])?></td>
            <td style="text-align:right;"><?=$fmtEur($tot['hf'])?></td>
            <td style="text-align:right;"><?=$fmtEur($tot['ht'])?></td>
          </tr></tfoot>
        </table>
      </div>

      <?php if($pages > 1): ?>
      <div style="display:flex;align-items:center;gap:.35rem;flex-wrap:wrap;margin-top:1rem;">
        <a href="<?=h($lnk(['p' => max(1, $pageNo - 1)]))?>" class="btn-secondary" style="text-decoration:none;font-size:.82rem;padding:.35rem .7rem;<?=$pageNo <= 1 ? 'pointer-events:none;opacity:.45;' : ''?>"><i class="bi bi-chevron-left"></i></a>
        <?php
          // Fenêtre de pages autour de la page courante, avec les extrémités.
          $show = [1, $pages];
          for ($i = $pageNo - 2; $i <= $pageNo + 2; $i++) if ($i >= 1 && $i <= $pages) $show[] = $i;
          $show = array_values(array_unique($show)); sort($show);
          $prev = 0;
          foreach ($show as $p):
            if ($prev && $p > $prev + 1): ?><span class="muted">…</span><?php endif; $prev = $p; ?>
          <a href="<?=h($lnk(['p' => $p]))?>" class="badge <?=$p === $pageNo ? 'badge-info' : 'badge-muted'?>" style="text-decoration:none;min-width:2rem;text-align:center;"><?=$p?></a>
        <?php endforeach; ?>
        <a href="<?=h($lnk(['p' => min($pages, $pageNo + 1)]))?>" class="btn-secondary" style="text-decoration:none;font-size:.82rem;padding:.35rem .7rem;<?=$pageNo >= $pages ? 'pointer-events:none;opacity:.45;' : ''?>"><i class="bi bi-chevron-right"></i></a>
        <span class="muted" style="margin-left:.5rem;font-size:.82rem;">page <?=$pageNo?> / <?=$pages?> · lignes <?=$off + 1?> à <?=min($nbRows, $off + $per)?> sur <?=$nbRows?></span>
      </div>
      <?php endif; ?>
    <?php endif; endif; ?>

    <?php if($tab === 'alerts' && $months):
        // Un seul tableau, trié par impact en euros : le bruit tombe en bas.
        $groupMeta = [
            'missing' => ['Facture manquante',       'bi-file-earmark-x',  'badge-danger',  'Un mois sans facture pour un compte actif : les compteurs de ce mois sont faux.'],
            'zero'    => ['Ligne sans consommation', 'bi-moon-stars',      'badge-info',    'Économie possible : la ligne est payée mais inutilisée.'],
            'hf'      => ['Hors-forfait',            'bi-cash-coin',       'badge-warning', 'Consommations facturées en plus de l\'abonnement.'],
            'surtaxe' => ['Numéro surtaxé',          'bi-telephone-plus',  'badge-danger',  'Appels vers des numéros à tarification spéciale.'],
            'intl'    => ['International',           'bi-globe-americas',  'badge-danger',  'Appels ou data hors de France / en itinérance.'],
            'remise'  => ['Remise marché',           'bi-percent',         'badge-danger',  'Abonnement au prix catalogue : remise non appliquée ?'],
            'var'     => ['Variation de conso',      'bi-activity',        'badge-muted',   'Écart de volume vs les 3 mois précédents (souvent sans impact financier).'],
            'global'  => ['Montant global',          'bi-graph-up-arrow',  'badge-danger',  'Le total du parc a fortement bougé d\'un mois sur l\'autre.'],
        ];
        // Aplatit tous les groupes en une liste unique triée par impact.
        $flat = [];
        foreach ($alertGroups as $gk => $rows) foreach ($rows as $a) $flat[] = $a + ['type' => $gk];
        usort($flat, fn($x, $y) => [(float)$y['impact'], $y['type']] <=> [(float)$x['impact'], $x['type']]);
        $counts = $impacts = [];
        foreach ($groupMeta as $gk => $_) {
            $counts[$gk]  = count($alertGroups[$gk]);
            $impacts[$gk] = array_sum(array_map(fn($a) => (float)$a['impact'], $alertGroups[$gk]));
        }
        $filter = isset($_GET['type'], $groupMeta[$_GET['type']]) ? $_GET['type'] : '';
        // Enjeu global SANS double comptage : les groupes se recouvrent (un
        // hors-forfait inhabituel compte dans « hors-forfait » ET dans
        // « variation » ; une facture manquante alimente aussi « montant
        // global »). Sommer tous les groupes pouvait approcher le double de
        // l'enjeu réel. On retient donc, par ligne, la plus coûteuse de ses
        // alertes, et on écarte les indicateurs de parc (facture manquante,
        // montant global) qui sont des signaux, pas des économies mensuelles.
        $lineImpact = [];
        foreach ($alertGroups as $gk => $garows) {
            if ($gk === 'missing' || $gk === 'global') continue;
            foreach ($garows as $ga) {
                $gp = (string)($ga['phone'] ?? '');
                if ($gp === '') continue;
                $lineImpact[$gp] = max($lineImpact[$gp] ?? 0.0, (float)$ga['impact']);
            }
        }
        $totalImpact = array_sum($lineImpact);
        $shownImpact = $filter === '' ? $totalImpact : $impacts[$filter];
    ?>
    <?=$periodPicker('alerts', $filter !== '' ? ['type' => $filter] : [])?>
    <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin-bottom:1rem;">
      <p class="muted" style="margin:0;">Alertes sur <strong><?=h($fmtMois($latestMonth))?></strong> (mois d'arrivée de la période), comparé aux 3 mois précédents.</p>
      <?php if(!empty($_SESSION['is_admin'])): ?>
      <button class="btn-secondary" style="font-size:.82rem;" onclick="document.getElementById('inv-thresholds').style.display = document.getElementById('inv-thresholds').style.display==='none'?'block':'none'"><i class="bi bi-sliders"></i> Seuils d'alerte</button>
      <?php endif; ?>
    </div>

    <?php if(!empty($_SESSION['is_admin'])): ?>
    <div class="card" id="inv-thresholds" style="display:none;margin-bottom:1.5rem;">
      <div class="card-header"><i class="bi bi-sliders"></i> Seuils d'alerte</div>
      <form method="post" style="padding:1.25rem 1.5rem;display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;align-items:end;">
        <input type="hidden" name="<?=CSRF_TOKEN_NAME?>" value="<?=h($CSRF_TOKEN)?>">
        <input type="hidden" name="_entity" value="invoice"><input type="hidden" name="_action" value="thresholds">
        <div class="form-group"><label>Variation (%) vs moyenne 3 mois</label><input type="number" step="1" min="0" name="inv_alert_var_pct" value="<?=h($thr['var_pct'])?>"></div>
        <div class="form-group"><label>Impact minimal variation (€ HT)</label><input type="number" step="0.5" min="0" name="inv_alert_var_min_eur" value="<?=h($thr['var_min_eur'])?>"></div>
        <div class="form-group"><label>Mois sans consommation</label><input type="number" step="1" min="1" name="inv_alert_zero_months" value="<?=h($thr['zero_months'])?>"></div>
        <div class="form-group"><label>Hors-forfait (€ HT / mois)</label><input type="number" step="0.5" min="0" name="inv_alert_hf_eur" value="<?=h($thr['hf_eur'])?>"></div>
        <div class="form-group"><label>International (€ HT / mois)</label><input type="number" step="0.5" min="0" name="inv_alert_intl_eur" value="<?=h($thr['intl_eur'])?>"></div>
        <div class="form-group"><label>Surtaxés (€ HT / mois)</label><input type="number" step="0.5" min="0" name="inv_alert_surtaxe_eur" value="<?=h($thr['surtaxe_eur'])?>"></div>
        <div class="form-group"><label>Remise marché attendue (%)</label><input type="number" step="0.01" min="0" max="100" name="inv_alert_remise_pct" value="<?=h($thr['remise_pct'])?>"></div>
        <div><button type="submit" class="btn-primary"><i class="bi bi-check-lg"></i> Enregistrer</button></div>
      </form>
    </div>
    <?php endif; ?>

    <?php if(!$nbAlerts): ?>
    <div class="card" style="padding:2.5rem;text-align:center;">
      <div style="font-size:2.2rem;color:var(--success);margin-bottom:.5rem;"><i class="bi bi-check-circle"></i></div>
      <p style="color:var(--text2);margin:0;">Aucune alerte sur <?=h($fmtMois($latestMonth))?> avec les seuils actuels. Tout est sous contrôle.</p>
    </div>
    <?php else: ?>

    <div class="kpi-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:1rem;margin-bottom:1.25rem;">
      <div class="card" style="padding:1.1rem 1.3rem;">
        <div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Enjeu identifié</div>
        <div style="font-size:1.5rem;font-weight:700;color:var(--warning);"><?=$fmtEur($totalImpact)?> <span style="font-size:.8rem;color:var(--text2);">HT/mois</span></div>
        <div class="muted"><?=$fmtEur($totalImpact * 12)?> sur 12 mois</div>
      </div>
      <div class="card" style="padding:1.1rem 1.3rem;">
        <div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Alertes</div>
        <div style="font-size:1.5rem;font-weight:700;"><?=$nbAlerts?></div>
        <div class="muted">dont <?=$counts['var']?> sans impact financier</div>
      </div>
      <div class="card" style="padding:1.1rem 1.3rem;">
        <div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Premier poste</div>
        <?php
          // Le poste au plus fort impact. Quand aucune alerte ne coûte d'euros
          // (variations de volume seules), il n'y a pas de « premier poste » :
          // max() renvoyait alors 0 et array_keys() désignait le premier groupe
          // du tableau — « Facture manquante · 0 ligne(s) », qui n'existe pas.
          $best = null;
          foreach ($impacts as $gk => $v) if ($v > 0 && ($best === null || $v > $impacts[$best])) $best = $gk;
          if ($best === null) foreach ($counts as $gk => $n) if ($n > 0) { $best = $gk; break; }
        ?>
        <?php if($best !== null && $impacts[$best] > 0): ?>
        <div style="font-size:1.5rem;font-weight:700;color:var(--info);"><?=$fmtEur($impacts[$best])?></div>
        <div class="muted"><?=h($groupMeta[$best][0])?> · <?=$counts[$best]?> ligne(s)</div>
        <?php else: ?>
        <div style="font-size:1.5rem;font-weight:700;color:var(--success);">—</div>
        <div class="muted">aucune alerte chiffrable<?=$best !== null ? ' · ' . h($groupMeta[$best][0]) . ' seulement' : ''?></div>
        <?php endif; ?>
      </div>
    </div>

    <div style="display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem;align-items:center;">
      <a href="?page=invoices&tab=alerts&<?=$qsPeriod?>" class="badge <?=$filter===''?'badge-info':'badge-muted'?>" style="text-decoration:none;">Tout (<?=$nbAlerts?>)</a>
      <?php foreach($groupMeta as $gk => [$glbl, $gico, $gcls, $ghelp]): if(!$counts[$gk]) continue; ?>
      <a href="?page=invoices&tab=alerts&<?=$qsPeriod?>&type=<?=$gk?>" class="badge <?=$filter===$gk?$gcls:'badge-muted'?>"
         style="text-decoration:none;" title="<?=h($ghelp)?>"><i class="bi <?=$gico?>"></i> <?=h($glbl)?> (<?=$counts[$gk]?>)<?php
         if($impacts[$gk] > 0): ?> · <?=$fmtEur($impacts[$gk])?><?php endif; ?></a>
      <?php endforeach; ?>
    </div>

    <?php if($filter !== ''): ?>
    <p class="muted" style="margin:-.4rem 0 1rem;font-size:.82rem;"><i class="bi bi-info-circle"></i> <?=h($groupMeta[$filter][3])?>
      <?php if($shownImpact > 0): ?>Enjeu de ce poste : <strong><?=$fmtEur($shownImpact)?> HT/mois</strong>.<?php endif; ?></p>
    <?php endif; ?>

    <div class="search-bar-wrap">
      <div class="search-bar"><span class="search-bar-icon"><i class="bi bi-search"></i></span><input type="text" placeholder="Filtrer par numéro, nom, type d'alerte..." oninput="tableSearch(this,'tbody-alerts','count-alerts')"></div>
      <div class="search-count" id="count-alerts"></div>
    </div>
    <div class="card" style="overflow-x:auto;">
      <table class="data-table" style="font-size:.86rem;">
        <thead><tr><th style="width:135px;">Ligne</th><th style="width:200px;">Utilisateur</th>
          <th style="width:170px;">Type</th><th>Détail</th><th style="width:110px;text-align:right;">Impact HT</th>
          <th style="width:60px;"></th></tr></thead>
        <tbody id="tbody-alerts">
        <?php $shown = 0; foreach($flat as $a): if($filter !== '' && $a['type'] !== $filter) continue; $shown++;
              [$glbl, $gico, $gcls, ] = $groupMeta[$a['type']]; ?>
          <tr>
            <td style="font-family:var(--font-mono);white-space:nowrap;"><?php if($a['phone']): ?><a href="?page=invoices&tab=conso&<?=$qsPeriod?>&line=<?=h($a['phone'])?>"><?=h(formatPhone($a['phone']))?></a><?php else: ?><span class="muted">tout le parc</span><?php endif; ?></td>
            <td><?=h($a['who'] ?: '—')?><?php if($a['plan']): ?><br><span class="muted" style="font-size:.74rem;"><?=h($a['plan'])?></span><?php endif; ?></td>
            <td><span class="badge <?=$gcls?>" style="font-size:.7rem;"><i class="bi <?=$gico?>"></i> <?=h($glbl)?></span></td>
            <td><?=h($a['detail'])?></td>
            <td style="text-align:right;font-family:var(--font-mono);font-weight:<?=(float)$a['impact'] > 0 ? '700' : '400'?>;color:<?=(float)$a['impact'] > 0 ? 'inherit' : 'var(--text3)'?>;">
              <?=(float)$a['impact'] > 0 ? $fmtEur($a['impact']) : '—'?></td>
            <td class="actions">
              <?php $app = $a['phone'] ? ($appLines[$a['phone']] ?? null) : null; ?>
              <?php if($app): ?><a class="btn-icon" title="Voir la ligne dans SimCity" href="?page=lines&tab=active&q=<?=urlencode(formatPhone($a['phone']))?>" style="text-decoration:none;"><i class="bi bi-telephone"></i></a><?php endif; ?>
            </td>
          </tr>
        <?php endforeach; if(!$shown): ?><tr><td colspan="6" class="empty-cell">Aucune alerte pour ce filtre</td></tr><?php endif; ?>
        </tbody>
      </table>
    </div>
    <p class="muted" style="margin-top:.75rem;font-size:.8rem;"><i class="bi bi-lightbulb"></i>
      Trié par impact décroissant : les lignes à « — » ne coûtent rien de plus ce mois-ci (variation de volume comprise dans le forfait).
      Les seuils monétaires filtrent ce qui est affiché — un seuil supérieur à la dépense réelle du parc rend un poste muet.</p>
    <?php endif; ?>
    <?php endif; ?>
    <?php
}

// ==================================================================
// VUE : REFERENTIELS ET UTILISATEURS
// ==================================================================
elseif ($page === 'refs') {
    $tab = $_GET['tab'] ?? 'agents';
    $tabs = ['agents'=>'<i class="bi bi-people"></i> Utilisateurs', 'services'=>'<i class="bi bi-building"></i> Services', 'models'=>'<i class="bi bi-list-ul"></i> Modèles', 'plans'=>'<i class="bi bi-globe2"></i> Forfaits', 'operators'=>'<i class="bi bi-broadcast"></i> Opérateurs', 'billing'=>'<i class="bi bi-cash-coin"></i> Facturation', 'admins'=>'<i class="bi bi-shield-lock"></i> Comptes Admin', 'settings'=>'<i class="bi bi-gear"></i> Paramètres'];
    
    if ($tab === 'agents') {
        // Sous-onglet : agents actifs (défaut) ou partis (archivés)
        $agentArchived = ($_GET['arch'] ?? '') === '1' ? 1 : 0;
        $agCounts = $pdo->query("SELECT SUM(archived=0) AS actifs, SUM(archived=1) AS partis FROM agents")->fetch();
        $q = $pdo->prepare("SELECT a.*, s.name as service_name FROM agents a LEFT JOIN services s ON a.service_id=s.id WHERE a.archived=? ORDER BY a.last_name, a.first_name");
        $q->execute([$agentArchived]);
        $data = $q->fetchAll();
        $cols = ['Nom'=>'last_name', 'Prénom'=>'first_name', 'Fonction'=>'fonction', 'Email'=>'email', 'Service'=>'service_name']; $ent = 'agent';
    } elseif ($tab === 'services') {
        $data = $pdo->query("SELECT s.*,
                (SELECT COUNT(*) FROM mobile_lines l WHERE l.service_id=s.id AND l.archived=0) AS nb_lines,
                (SELECT COUNT(*) FROM devices d WHERE d.service_id=s.id AND d.archived=0)      AS nb_devices
            FROM services s ORDER BY s.name")->fetchAll();
        $cols = ['Nom'=>'name', 'Direction'=>'direction', 'Lignes'=>'nb_lines', 'Matériels'=>'nb_devices', 'Visa Chef de service'=>'chef_name', 'Visa D.G.A.'=>'dga_name', 'Notes'=>'notes']; $ent = 'service';
    } elseif ($tab === 'models') {
        $data = $pdo->query("SELECT * FROM models ORDER BY brand, name")->fetchAll();
        $cols = ['Marque'=>'brand', 'Modèle'=>'name', 'Catégorie'=>'category']; $ent = 'model';
    } elseif ($tab === 'plans') {
        $data = $pdo->query("SELECT p.*, IFNULL(o.name,'—') as operator_name FROM plan_types p LEFT JOIN operators o ON p.operator_id=o.id ORDER BY o.name, p.name")->fetchAll();
        $cols = ['Opérateur'=>'operator_name', 'Nom du forfait'=>'name', 'Data'=>'data_limit', 'Notes'=>'notes']; $ent = 'plan';
        $operators = $pdo->query("SELECT id, name FROM operators ORDER BY name")->fetchAll();
    } elseif ($tab === 'operators') {
        $data = $pdo->query("SELECT * FROM operators ORDER BY name")->fetchAll();
        $cols = ['Opérateur'=>'name', 'Site web'=>'website', 'Notes'=>'notes']; $ent = 'operator';
    } elseif ($tab === 'billing') {
        $data = $pdo->query("SELECT * FROM billing_accounts ORDER BY name")->fetchAll();
        $cols = ['N° de Compte'=>'account_number', 'Nom / Entité'=>'name', 'Notes'=>'notes']; $ent = 'billing';
    } elseif ($tab === 'admins') {
        $data = $pdo->query("SELECT id, username, active, IFNULL(first_name,'') as first_name, IFNULL(last_name,'') as last_name, IFNULL(email,'') as email, IFNULL(auth_source,'local') as auth_source, DATE_FORMAT(created_at, '%d/%m/%Y %H:%i') as created_at FROM users ORDER BY active DESC, last_name, first_name, username")->fetchAll();
        $cols = ['Identifiant'=>'username', 'Nom'=>'last_name', 'Prénom'=>'first_name', 'Email'=>'email', 'Créé le'=>'created_at']; $ent = 'admin';
        // Visa DSI de chaque compte (une signature par admin)
        $sigMap = $pdo->query("SELECT id, signature_data FROM users WHERE signature_data IS NOT NULL AND signature_data != ''")->fetchAll(PDO::FETCH_KEY_PAIR);
    } elseif ($tab === 'settings') {
        $allSettings = $pdo->query("SELECT * FROM settings ORDER BY id")->fetchAll();
        $ent = 'settings';
    }
    ?>
    <?php
    // Le bouton d'ajout est rendu plus bas, à droite de la barre de recherche.
    $addLabels = [
      'agents'    => 'Ajouter un(e) utilisateur(trice)',
      'services'  => 'Ajouter un service',
      'models'    => 'Ajouter un modèle',
      'plans'     => 'Ajouter un forfait',
      'operators' => 'Ajouter un opérateur',
      'billing'   => 'Ajouter un compte de facturation',
      'admins'    => 'Ajouter un compte admin',
    ];
    ?>

    <?php if($tab !== 'agents'): // « Utilisateurs » a son propre menu à gauche : pas de bandeau d'onglets sur cette page ?>
    <div style="display:flex; gap:10px; margin-bottom:1rem; border-bottom:2px solid var(--border); flex-wrap:wrap;">
        <?php foreach($tabs as $k => $label): if($k === 'agents') continue; // masqué du bandeau (accessible via le menu de gauche) ?>
        <a href="?page=refs&tab=<?=$k?>" class="tab-btn <?=$tab===$k?'active':''?>"><?=$label?></a>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <?php if($tab === 'admins'): ?>
    <!-- ── Statut LDAP / Active Directory ─────────────────────── -->
    <div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap;background:<?=ldap_auth_enabled()?'rgba(5,150,105,.06)':'var(--bg3)'?>;border:1px solid <?=ldap_auth_enabled()?'rgba(5,150,105,.3)':'var(--border)'?>;border-radius:var(--radius-sm);padding:.75rem 1rem;margin-bottom:1rem;font-size:.85rem;">
      <span><i class="bi bi-globe2"></i> <strong>Authentification Active Directory :</strong>
        <?php if(ldap_auth_enabled()): ?>
          <span style="color:var(--success);font-weight:600;">activée</span>
          <span class="muted">— serveur : <code style="font-family:var(--font-mono);font-size:.8rem;"><?=h(ldap_cfg('ldap_server'))?></code><?=ldap_cfg('ldap_required_group')!==''?' · groupe requis : <code style="font-family:var(--font-mono);font-size:.8rem;">'.h(ldap_cfg('ldap_required_group')).'</code>':' · <strong style="color:var(--warning);">⚠️ aucun groupe requis</strong>'?></span>
        <?php elseif(ldap_cfg('ldap_enabled') && !extension_loaded('ldap')): ?>
          <span style="color:var(--danger);font-weight:600;">extension PHP « ldap » manquante</span>
        <?php else: ?>
          <span class="muted">désactivée</span>
        <?php endif; ?>
      </span>
      <?php if(!empty($_SESSION['is_admin'])): ?>
      <a href="?page=refs&tab=settings" class="btn-secondary" style="font-size:.8rem;padding:.35rem .8rem;margin-left:auto;text-decoration:none;"><i class="bi bi-gear"></i> Configurer</a>
      <?php endif; ?>
    </div>
    <?php endif; ?>

    <?php if($tab === 'settings'):
        $currentLogo = getSetting($pdo, 'pdf_logo_path', '');
        // Sous-menu des paramètres (évite une page unique surchargée).
        $subMenu = [
            'general'  => '<i class="bi bi-sliders"></i> Général',
            'email'    => '<i class="bi bi-envelope"></i> Envoi d\'e-mails',
            'requests' => '<i class="bi bi-inbox"></i> Demandes de téléphone',
            'security' => '<i class="bi bi-shield-lock"></i> Sécurité (AD/LDAP)',
        ];
        if(!empty($_SESSION['is_admin'])) $subMenu['maintenance'] = '<i class="bi bi-hdd"></i> Maintenance';
        $settingsSub = $_GET['sub'] ?? 'general';
        if(!isset($subMenu[$settingsSub])) $settingsSub = 'general';
    ?>
    <!-- ── ONGLET PARAMÈTRES ───────────────────────────────────── -->
    <!-- Sous-menu : chaque section regroupe des réglages proches. -->
    <div style="display:flex; gap:10px; margin-bottom:1.5rem; border-bottom:2px solid var(--border); flex-wrap:wrap;">
      <?php foreach($subMenu as $sk => $slabel): ?>
      <a href="?page=refs&tab=settings&sub=<?=$sk?>" class="tab-btn <?=$settingsSub===$sk?'active':''?>"><?=$slabel?></a>
      <?php endforeach; ?>
    </div>

    <?php if($settingsSub === 'general'): ?>
    <!-- Colonnes CSS : les cartes se répartissent verticalement et remplissent
         l'espace sans laisser de « trous » (responsive : 1 colonne si étroit). -->
    <div style="column-width:460px;column-gap:1.5rem;">

      <!-- Bloc logo -->
      <div class="card">
        <div class="card-header"><i class="bi bi-image"></i> Logo des bons de remise PDF</div>
        <form method="post" enctype="multipart/form-data" style="padding:1.5rem;">
          <input type="hidden" name="_entity" value="settings">
          <input type="hidden" name="_action" value="save">
          <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
            Le logo apparaîtra en haut à gauche de chaque bon de remise imprimé.<br>
            <strong>Formats acceptés :</strong> PNG, JPG, GIF, WEBP — <strong>Taille max : 1 Mo</strong>.<br>
            Il sera affiché avec une hauteur maximale de 60 px sur le document.
          </p>
          <?php if($currentLogo && file_exists($currentLogo)): ?>
          <div style="display:flex;align-items:center;gap:1.5rem;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:1rem;margin-bottom:1.25rem;">
            <img src="<?=h($currentLogo)?>" alt="Logo actuel" style="max-height:70px;max-width:200px;object-fit:contain;border-radius:4px;">
            <div>
              <div style="font-weight:600;color:var(--text);margin-bottom:.5rem;">Logo actuel</div>
              <label style="display:flex;align-items:center;gap:.5rem;cursor:pointer;color:var(--danger);font-size:.85rem;">
                <input type="checkbox" name="delete_logo" value="1" style="accent-color:var(--danger);width:14px;height:14px;">
                Supprimer ce logo
              </label>
            </div>
          </div>
          <?php else: ?>
          <div style="background:var(--bg3);border:1px dashed var(--border);border-radius:var(--radius-sm);padding:1rem;margin-bottom:1.25rem;text-align:center;color:var(--text3);font-size:.88rem;">
            Aucun logo configuré
          </div>
          <?php endif; ?>
          <div class="form-group form-full">
            <label><?=$currentLogo && file_exists($currentLogo) ? 'Remplacer le logo' : 'Choisir un logo'?></label>
            <input type="file" name="pdf_logo" accept="image/png,image/jpeg,image/gif,image/webp"
              style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.6rem;color:var(--text);width:100%;">
          </div>
          <div style="padding-top:1rem;border-top:1px solid var(--border);margin-top:.5rem;">
            <button type="submit" class="btn-primary"><i class="bi bi-save"></i> Enregistrer</button>
          </div>
        </form>
      </div>

      <!-- Bloc URL du site -->
      <?php $currentSiteUrl = getSetting($pdo, 'site_url', ''); ?>
      <div class="card">
        <div class="card-header"><i class="bi bi-link-45deg"></i> URL publique du site</div>
        <form method="post" style="padding:1.5rem;">
          <input type="hidden" name="_entity" value="settings">
          <input type="hidden" name="_action" value="save">
          <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
            L'URL de base utilisée pour générer les liens des <strong>QR codes de signature</strong>.<br>
            Laissez vide pour utiliser la détection automatique.<br>
            <strong>Exemple :</strong> <code style="font-family:var(--font-mono);font-size:.82rem;">https://simcity.monentreprise.fr</code>
          </p>
          <div class="form-group form-full">
            <label>URL du site</label>
            <input type="url" name="site_url" value="<?=h($currentSiteUrl)?>"
              placeholder="https://simcity.monentreprise.fr"
              style="font-family:var(--font-mono);font-size:.88rem;">
          </div>
          <?php if($currentSiteUrl): ?>
          <p style="font-size:.82rem;color:var(--success);margin-top:.5rem;">
            ✅ URL active — les QR codes pointent vers : <code style="font-family:var(--font-mono);"><?=h($currentSiteUrl)?>/index.php</code>
          </p>
          <?php else: ?>
          <p style="font-size:.82rem;color:var(--text3);margin-top:.5rem;">
            ⚙️ Détection automatique active (basée sur le serveur HTTP).
          </p>
          <?php endif; ?>
          <div style="padding-top:1rem;border-top:1px solid var(--border);margin-top:1rem;">
            <button type="submit" class="btn-primary"><i class="bi bi-save"></i> Enregistrer</button>
          </div>
        </form>
      </div>

      <!-- Bloc couleur du site -->
      <div class="card">
        <div class="card-header"><i class="bi bi-palette"></i> Couleur du site</div>
        <form method="post" style="padding:1.5rem;">
          <input type="hidden" name="_entity" value="settings">
          <input type="hidden" name="_action" value="save">
          <input type="hidden" name="ui_color_form" value="1">
          <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
            Couleur principale de l'interface (boutons, onglets, liens, logo embarqué).
            Elle s'applique aussi aux thèmes sombre (déclinaison éclaircie) et aux pages publiques.
          </p>
          <?php $uiColor = uiPrimaryColor($pdo); ?>
          <div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap;">
            <label style="display:flex;align-items:center;gap:.5rem;font-size:.86rem;font-weight:400;text-transform:none;letter-spacing:normal;cursor:pointer;margin:0;">
              <input type="checkbox" name="ui_primary_color_enabled" value="1" <?=$uiColor!==''?'checked':''?> style="width:15px;height:15px;accent-color:var(--primary);">
              Couleur personnalisée
            </label>
            <input type="color" name="ui_primary_color" value="<?=h($uiColor !== '' ? $uiColor : '#4f46e5')?>" style="width:46px;height:30px;padding:1px;border:1px solid var(--border);border-radius:4px;cursor:pointer;">
            <span style="font-size:.78rem;color:var(--text3);">Décochée : palette d'origine (indigo). Choisissez une couleur foncée, le texte posé dessus est blanc.</span>
          </div>
          <div style="padding-top:1rem;border-top:1px solid var(--border);margin-top:1.25rem;">
            <button type="submit" class="btn-primary"><i class="bi bi-save"></i> Enregistrer</button>
          </div>
        </form>
      </div>

      <!-- Bloc seuils -->
      <div class="card">
        <div class="card-header"><i class="bi bi-bell"></i> Seuils d'alerte Stock</div>
        <form method="post" style="padding:1.5rem;">
          <input type="hidden" name="_entity" value="settings">
          <input type="hidden" name="_action" value="save">
          <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.5rem;line-height:1.6;">
            Quand le stock descend <strong>en-dessous ou à égalité</strong> du seuil configuré, une alerte s'affiche sur le tableau de bord.
          </p>
          <?php foreach($allSettings as $s):
              if(!in_array($s['setting_key'], ['sim_stock_alert', 'device_stock_alert'])) continue; ?>
          <div class="form-group form-full" style="margin-bottom:1.25rem;">
            <label><?=h($s['label'])?></label>
            <div style="display:flex;align-items:center;gap:1rem;">
              <input type="number" name="<?=h($s['setting_key'])?>" value="<?=h($s['setting_value'])?>" min="0" max="999" style="max-width:120px;">
              <span style="color:var(--text3);font-size:.82rem;">unité(s)</span>
            </div>
          </div>
          <?php endforeach; ?>
          <div style="padding-top:1rem;border-top:1px solid var(--border);margin-top:.5rem;">
            <button type="submit" class="btn-primary"><i class="bi bi-save"></i> Enregistrer les seuils</button>
          </div>
        </form>
      </div>

    </div><!-- fin section « Général » -->
    <?php endif; ?>

    <?php
    // ── Secret encore stocké en base : proposition d'effacement ──
    // Une variable d'environnement prime sur la table mais ne la vide pas.
    // Tant que la valeur y reste, elle part dans chaque sauvegarde SQL.
    // Ce bloc n'apparaît que s'il y a effectivement quelque chose à effacer.
    $secretPurgeBox = function($pdo, string $key, string $envVar, string $label) use ($CSRF_TOKEN) {
        if (empty($_SESSION['is_admin'])) return '';
        if (trim((string)getSetting($pdo, $key, '')) === '') return '';
        $fromEnv = getenv($envVar) !== false && getenv($envVar) !== '';
        $col = $fromEnv ? 'var(--warning)' : 'var(--text2)';
        ob_start(); ?>
        <div style="margin:0 1.5rem 1.5rem;padding:.85rem 1rem;border-left:3px solid <?=$col?>;background:var(--bg3);border-radius:var(--radius-sm);font-size:.84rem;">
          <strong style="color:<?=$col?>;"><i class="bi bi-shield-exclamation"></i>
            <?=$fromEnv ? 'Valeur en double' : 'Secret stocké en base'?></strong>
          <p style="margin:.4rem 0 .7rem;color:var(--text2);line-height:1.55;">
            <?php if($fromEnv): ?>
              Le <?=h($label)?> est fourni par la variable d'environnement <code><?=h($envVar)?></code>, qui prime — mais une
              valeur reste enregistrée dans la base. Elle n'est plus utilisée, et elle continue de partir dans chaque
              sauvegarde SQL. Autant l'effacer.
            <?php else: ?>
              Le <?=h($label)?> est enregistré dans la table <code>settings</code>, en clair : il figure donc dans chaque
              sauvegarde SQL. Pour l'éviter, fournissez-le par la variable d'environnement <code><?=h($envVar)?></code>
              (elle prime sur la base et verrouille le champ), puis effacez la valeur stockée ici.
            <?php endif; ?>
          </p>
          <form method="post" style="margin:0;"
                onsubmit="return confirm('Effacer le <?=h($label)?> enregistré en base ?<?=$fromEnv ? '' : '\n\nL\'envoi se fera sans authentification tant qu\'aucune variable d\'environnement ne le fournit.'?>')">
            <input type="hidden" name="<?=CSRF_TOKEN_NAME?>" value="<?=h($CSRF_TOKEN)?>">
            <input type="hidden" name="_entity" value="secret_purge">
            <input type="hidden" name="_action" value="run">
            <input type="hidden" name="setting_key" value="<?=h($key)?>">
            <button type="submit" class="btn-secondary" style="font-size:.82rem;"><i class="bi bi-eraser"></i> Effacer la valeur stockée</button>
          </form>
        </div>
        <?php return ob_get_clean();
    };
    ?>

    <?php if($settingsSub === 'email'): ?>
    <div style="column-width:460px;column-gap:1.5rem;">

      <!-- Bloc SMTP -->
      <div class="card">
        <div class="card-header"><i class="bi bi-envelope"></i> Envoi d'e-mails (liens de signature)</div>
        <form method="post" style="padding:1.5rem;">
          <input type="hidden" name="_entity" value="settings">
          <input type="hidden" name="_action" value="save">
          <?php
            // Champ verrouillé si imposé par variable d'environnement (Docker)
            $mk  = fn($k) => smtp_env_locked($k) ? 'disabled title="Imposé par la variable d\'environnement '.h(SMTP_ENV_KEYS[$k]).' — modifiable uniquement côté serveur"' : '';
            $mkN = fn($k) => smtp_env_locked($k) ? ' <span style="font-weight:400;text-transform:none;color:var(--warning);">🔒 env</span>' : '';
          ?>
          <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
            Permet d'envoyer le lien de signature d'un bon directement à l'agent (bouton 📧).<br>
            Laissez le serveur vide pour désactiver l'envoi d'e-mails. Marqué 🔒 env : valeur imposée par l'environnement (variables <code>MAIL_*</code>, comme Sentinelle).
          </p>
          <div class="form-grid">
            <div class="form-group"><label>Serveur SMTP<?=$mkN('smtp_host')?></label><input type="text" name="smtp_host" value="<?=h(smtpSetting($pdo,'smtp_host',''))?>" placeholder="smtp.monentreprise.fr" <?=$mk('smtp_host')?>></div>
            <div class="form-group"><label>Port<?=$mkN('smtp_port')?></label><input type="number" name="smtp_port" value="<?=h(smtpSetting($pdo,'smtp_port','587'))?>" min="1" max="65535" <?=$mk('smtp_port')?>></div>
            <div class="form-group"><label>Chiffrement<?=$mkN('smtp_secure')?></label>
              <?php $smtpSec = smtpSetting($pdo,'smtp_secure','tls'); ?>
              <select name="smtp_secure" <?=$mk('smtp_secure')?>>
                <option value="tls" <?=$smtpSec==='tls'?'selected':''?>>STARTTLS (port 587)</option>
                <option value="ssl" <?=$smtpSec==='ssl'?'selected':''?>>SSL/TLS (port 465)</option>
                <option value="none" <?=$smtpSec==='none'?'selected':''?>>Aucun (interne uniquement)</option>
              </select>
            </div>
            <div class="form-group"><label>Identifiant<?=$mkN('smtp_user')?></label><input type="text" name="smtp_user" value="<?=h(smtpSetting($pdo,'smtp_user',''))?>" autocomplete="off" placeholder="Vide si serveur sans authentification" <?=$mk('smtp_user')?>></div>
            <div class="form-group"><label>Mot de passe <span style="font-weight:400;text-transform:none;">(vide = inchangé)</span><?=$mkN('smtp_pass')?></label><input type="password" name="smtp_pass" value="" autocomplete="new-password" <?=$mk('smtp_pass')?>></div>
            <div class="form-group"><label>Adresse expéditrice<?=$mkN('smtp_from')?></label><input type="email" name="smtp_from" value="<?=h(smtpSetting($pdo,'smtp_from',''))?>" placeholder="dsi@monentreprise.fr" <?=$mk('smtp_from')?>></div>
            <div class="form-group form-full"><label>Nom de l'expéditeur<?=$mkN('smtp_from_name')?></label><input type="text" name="smtp_from_name" value="<?=h(smtpSetting($pdo,'smtp_from_name','SimCity — DSI'))?>" <?=$mk('smtp_from_name')?>></div>
          </div>
          <div style="padding-top:1rem;border-top:1px solid var(--border);margin-top:1rem;">
            <button type="submit" class="btn-primary"><i class="bi bi-save"></i> Enregistrer</button>
          </div>
        </form>
        <?=$secretPurgeBox($pdo, 'smtp_pass', 'MAIL_PASSWORD', 'mot de passe SMTP')?>
        <?php
          // Adresse de test pré-remplie avec l'e-mail de l'administrateur connecté
          $smtpTestTo = '';
          if(!empty($_SESSION['user_id'])) {
              $qte = $pdo->prepare("SELECT email FROM users WHERE id=?");
              $qte->execute([(int)$_SESSION['user_id']]);
              $smtpTestTo = (string)$qte->fetchColumn();
          }
        ?>
        <form method="post" style="padding:0 1.5rem 1.5rem;">
          <input type="hidden" name="_entity" value="smtp_test">
          <input type="hidden" name="_action" value="test">
          <label style="display:block;font-size:.78rem;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.03em;margin-bottom:.4rem;">Tester l'envoi</label>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:.4rem .9rem;margin-bottom:.85rem;">
            <?php foreach (mailTemplates() as $tk => $tpl): ?>
            <label style="display:flex;align-items:center;gap:.45rem;font-size:.84rem;font-weight:400;text-transform:none;letter-spacing:normal;color:var(--text);cursor:pointer;margin:0;">
              <input type="checkbox" name="tpl[]" value="<?=h($tk)?>" <?=$tk==='test'?'checked':''?> style="width:14px;height:14px;accent-color:var(--primary);flex-shrink:0;">
              <span><?=h($tpl['label'])?></span>
            </label>
            <?php endforeach; ?>
          </div>
          <div style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:center;">
            <input type="email" name="test_email" placeholder="destinataire@exemple.fr" required value="<?=h($smtpTestTo)?>" style="flex:1;min-width:220px;">
            <button type="submit" class="btn-secondary">📧 Envoyer les e-mails cochés</button>
          </div>
          <small style="color:var(--text3);">Utilise la configuration <strong>enregistrée</strong> (enregistrez d'abord vos modifications). Chaque e-mail part avec des données fictives, sujet préfixé [DÉMO].</small>
        </form>
      </div>

      <!-- Personnalisation des gabarits d'e-mails -->
      <div class="card" style="break-inside:avoid;">
        <div class="card-header"><i class="bi bi-envelope-paper"></i> Personnalisation des e-mails</div>
        <form method="post" style="padding:1.25rem 1.5rem 1.5rem;">
          <input type="hidden" name="<?=CSRF_TOKEN_NAME?>" value="<?=h($CSRF_TOKEN)?>">
          <input type="hidden" name="_entity" value="mail_tpl">
          <input type="hidden" name="_action" value="save">
          <p style="color:var(--text2);font-size:.85rem;line-height:1.6;margin-bottom:1rem;">
            Sujet, titre et corps (HTML) de chaque e-mail. Effacer un champ (ou le laisser identique au défaut) reprend le gabarit standard.
            Les variables <code style="font-family:var(--font-mono);">{xxx}</code> sont remplacées à l'envoi.
          </p>
          <?php [$mbC1, $mbC2, $mbGrad] = mailBannerColors($pdo); ?>
          <div style="display:flex;flex-wrap:wrap;gap:1rem 1.5rem;align-items:center;padding:.75rem .9rem;border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:1rem;">
            <span style="font-size:.84rem;font-weight:600;">Bandeau :</span>
            <label style="display:flex;align-items:center;gap:.45rem;font-size:.84rem;font-weight:400;text-transform:none;letter-spacing:normal;cursor:pointer;margin:0;">
              Couleur <input type="color" name="banner_color" id="mail-banner-c1" value="<?=h($mbC1)?>" style="width:38px;height:26px;padding:1px;border:1px solid var(--border);border-radius:4px;cursor:pointer;">
            </label>
            <label style="display:flex;align-items:center;gap:.45rem;font-size:.84rem;font-weight:400;text-transform:none;letter-spacing:normal;cursor:pointer;margin:0;">
              <input type="checkbox" name="banner_gradient" id="mail-banner-grad" value="1" <?=$mbGrad?'checked':''?> style="width:14px;height:14px;accent-color:var(--primary);">
              Dégradé vers <input type="color" name="banner_color2" id="mail-banner-c2" value="<?=h($mbC2)?>" style="width:38px;height:26px;padding:1px;border:1px solid var(--border);border-radius:4px;cursor:pointer;">
            </label>
            <span style="font-size:.76rem;color:var(--text3);">Choisissez des couleurs foncées : le texte du bandeau est blanc. S'applique aussi aux boutons (1re couleur).</span>
          </div>
          <?php foreach (mailTemplates() as $tk => $tpl):
              $ovS = trim(getSetting($pdo, "mail_tpl_{$tk}_subject", ''));
              $ovT = trim(getSetting($pdo, "mail_tpl_{$tk}_title", ''));
              $ovB = trim(getSetting($pdo, "mail_tpl_{$tk}_body", ''));
              $customized = $ovS !== '' || $ovT !== '' || $ovB !== '';
              $enabled = mailTplEnabled($pdo, $tk);
          ?>
          <details style="border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:.6rem;<?=$enabled?'':'opacity:.65;'?>" data-tpl="<?=h($tk)?>">
            <summary style="cursor:pointer;padding:.65rem .9rem;font-size:.88rem;font-weight:600;">
              <?=h($tpl['label'])?><?=$customized ? ' <span class="badge badge-info" style="font-size:.68rem;">personnalisé</span>' : ''?><?=$enabled ? '' : ' <span class="badge badge-danger" style="font-size:.68rem;">désactivé</span>'?>
            </summary>
            <div style="padding:.35rem .9rem .9rem;">
              <?php if ($tk !== 'test'): ?>
              <label style="display:flex;align-items:center;gap:.45rem;font-size:.84rem;font-weight:400;text-transform:none;letter-spacing:normal;cursor:pointer;margin:0 0 .75rem;">
                <input type="checkbox" name="tpl_enabled[<?=h($tk)?>]" value="1" <?=$enabled?'checked':''?> style="width:14px;height:14px;accent-color:var(--primary);">
                <span>Envoi activé — décochez pour que cet e-mail ne parte plus jamais.</span>
              </label>
              <?php endif; ?>
              <div class="form-group form-full"><label>Sujet</label>
                <input type="text" name="tpl_subject[<?=h($tk)?>]" value="<?=h($ovS !== '' ? $ovS : $tpl['subject'])?>"></div>
              <div class="form-group form-full"><label>Titre (bandeau du message)</label>
                <input type="text" name="tpl_title[<?=h($tk)?>]" value="<?=h($ovT !== '' ? $ovT : $tpl['title'])?>"></div>
              <div class="form-group form-full"><label>Corps (HTML)</label>
                <textarea name="tpl_body[<?=h($tk)?>]" rows="6" style="font-family:var(--font-mono);font-size:.78rem;"><?=h($ovB !== '' ? $ovB : $tpl['body'])?></textarea></div>
              <div style="text-align:right;margin-bottom:.5rem;">
                <button type="button" class="btn-secondary btn-sm" onclick="mailTplPreview('<?=h($tk)?>')"><i class="bi bi-eye"></i> Aperçu</button>
              </div>
              <?php if ($tpl['vars']): ?>
              <div style="font-size:.76rem;color:var(--text3);line-height:1.7;">
                <strong>Variables :</strong>
                <?php foreach ($tpl['vars'] as $vk => $vd): ?>
                  <code style="font-family:var(--font-mono);">{<?=h($vk)?>}</code> <?=h($vd)?> ·
                <?php endforeach; ?>
              </div>
              <?php endif; ?>
            </div>
          </details>
          <?php endforeach; ?>
          <div style="margin-top:1rem;text-align:right;">
            <button type="submit" class="btn-primary">💾 Enregistrer les gabarits</button>
          </div>
        </form>
      </div>

      <!-- Modale d'aperçu d'un gabarit d'e-mail -->
      <div class="modal-overlay" id="modal-mail-preview">
        <div class="modal" style="max-width:700px;width:95%;">
          <div class="modal-header">
            <h3><i class="bi bi-envelope-open"></i> Aperçu — <span id="mail-preview-label"></span></h3>
            <button type="button" class="modal-close" onclick="closeModal('modal-mail-preview')"><i class="bi bi-x-lg"></i></button>
          </div>
          <div style="padding:1rem 1.5rem 1.5rem;">
            <div style="font-size:.85rem;margin-bottom:.75rem;"><strong>Sujet :</strong> <span id="mail-preview-subject" style="color:var(--text2);"></span></div>
            <iframe id="mail-preview-frame" sandbox="" style="width:100%;height:60vh;border:1px solid var(--border);border-radius:var(--radius-sm);background:#eef1f6;"></iframe>
          </div>
        </div>
      </div>
      <script>
      // Aperçu : envoie les valeurs COURANTES du formulaire (non enregistrées)
      // à ajax_mail_preview, et affiche le rendu dans une iframe sandboxée.
      const MAIL_TPL_LABELS = <?= json_encode(array_map(fn($t) => $t['label'], mailTemplates())) ?>;
      const MAIL_TPL_VARS   = <?= json_encode(array_map(fn($t) => $t['vars'], mailTemplates())) ?>;
      function mailTplPreview(tk){
        const det  = document.querySelector('details[data-tpl="'+tk+'"]');
        const form = det.closest('form');
        const fd = new FormData();
        fd.append('tpl', tk);
        fd.append('subject', form.querySelector('[name="tpl_subject['+tk+']"]').value);
        fd.append('title',   form.querySelector('[name="tpl_title['+tk+']"]').value);
        fd.append('body',    form.querySelector('[name="tpl_body['+tk+']"]').value);
        fd.append('banner_color',    document.getElementById('mail-banner-c1').value);
        fd.append('banner_color2',   document.getElementById('mail-banner-c2').value);
        fd.append('banner_gradient', document.getElementById('mail-banner-grad').checked ? '1' : '0');
        fetch('index.php?ajax_mail_preview=1', { method:'POST', body:fd })
          .then(r => r.json())
          .then(j => {
            if(!j || j.error){ alert((j&&j.error)||'Aperçu indisponible.'); return; }
            document.getElementById('mail-preview-label').textContent = MAIL_TPL_LABELS[tk] || tk;
            document.getElementById('mail-preview-subject').textContent = j.subject;
            // L'iframe est recréée à chaque aperçu : la réaffectation de
            // srcdoc sur une iframe sandboxée déjà rendue reste blanche
            // sur certains navigateurs.
            const old = document.getElementById('mail-preview-frame');
            const fresh = old.cloneNode(false);
            fresh.srcdoc = j.html;
            old.replaceWith(fresh);
            openModal('modal-mail-preview');
          })
          .catch(() => alert('Erreur réseau pendant l\'aperçu.'));
      }

      // ── Mini-éditeur WYSIWYG des corps de gabarits ──────────────
      // Le <textarea> reste la source soumise ; une zone contenteditable
      // synchronisée offre gras/italique/souligné, taille, couleur, lien
      // et liste. Bouton </> : bascule visuel <-> code HTML. Le HTML
      // produit (balises simples + styles inline) reste compatible e-mail.
      document.querySelectorAll('textarea[name^="tpl_body"]').forEach(ta => {
        const wrap = document.createElement('div');
        wrap.style.cssText = 'border:1px solid var(--border);border-radius:var(--radius-sm);overflow:hidden;';
        const bar = document.createElement('div');
        bar.style.cssText = 'display:flex;gap:2px;flex-wrap:wrap;align-items:center;padding:4px 6px;border-bottom:1px solid var(--border);background:var(--bg3);';
        const ed = document.createElement('div');
        ed.contentEditable = 'true';
        ed.style.cssText = 'min-height:130px;max-height:320px;overflow-y:auto;padding:.7rem .85rem;background:#fff;color:#374151;font-size:.9rem;line-height:1.6;outline:none;';
        ed.innerHTML = ta.value;
        const sync = () => { ta.value = ed.innerHTML; };
        ed.addEventListener('input', sync);
        ed.addEventListener('blur', sync);
        // Position du curseur mémorisée : l'insertion de variable retombe au
        // bon endroit même après un clic dans la barre d'outils.
        let savedRange = null;
        const saveRange = () => { const s = getSelection(); if(s.rangeCount && ed.contains(s.anchorNode)) savedRange = s.getRangeAt(0).cloneRange(); };
        ed.addEventListener('keyup', saveRange); ed.addEventListener('mouseup', saveRange); ed.addEventListener('blur', saveRange);
        const cmd = (c, v) => { document.execCommand('styleWithCSS', false, true); document.execCommand(c, false, v || null); ed.focus(); sync(); };
        const mkBtn = (html, title, fn) => {
          const b = document.createElement('button');
          b.type = 'button'; b.innerHTML = html; b.title = title;
          b.style.cssText = 'border:none;background:none;cursor:pointer;padding:.3rem .5rem;border-radius:4px;font-size:.85rem;color:var(--text);min-width:28px;';
          b.addEventListener('mouseenter', () => b.style.background = 'var(--border)');
          b.addEventListener('mouseleave', () => b.style.background = 'none');
          b.addEventListener('mousedown', e => e.preventDefault()); // garde la sélection
          b.addEventListener('click', fn);
          bar.appendChild(b); return b;
        };
        mkBtn('<strong>G</strong>', 'Gras', () => cmd('bold'));
        mkBtn('<em>I</em>', 'Italique', () => cmd('italic'));
        mkBtn('<u>S</u>', 'Souligné', () => cmd('underline'));
        const size = document.createElement('select');
        size.style.cssText = 'font-size:.78rem;padding:.2rem;border:1px solid var(--border);border-radius:4px;background:#fff;color:var(--text);width:auto;';
        size.innerHTML = '<option value="">Taille</option><option value="1">Petit</option><option value="3">Normal</option><option value="5">Grand</option><option value="6">Très grand</option>';
        size.addEventListener('mousedown', e => e.stopPropagation());
        size.addEventListener('change', () => { if(size.value){ cmd('fontSize', size.value); size.value = ''; } });
        bar.appendChild(size);
        const color = document.createElement('input');
        color.type = 'color'; color.value = '#374151'; color.title = 'Couleur du texte';
        color.style.cssText = 'width:26px;height:24px;padding:0;border:1px solid var(--border);border-radius:4px;cursor:pointer;background:none;';
        color.addEventListener('input', () => cmd('foreColor', color.value));
        bar.appendChild(color);
        mkBtn('<i class="bi bi-link-45deg"></i>', 'Insérer un lien', () => {
          const u = prompt('URL du lien :', 'https://'); if(u) cmd('createLink', u);
        });
        mkBtn('<i class="bi bi-list-ul"></i>', 'Liste à puces', () => cmd('insertUnorderedList'));
        mkBtn('<i class="bi bi-eraser"></i>', 'Effacer la mise en forme', () => cmd('removeFormat'));
        // Insertion des variables du gabarit, avec leur explication.
        const tplKey = (ta.name.match(/tpl_body\[(.+)\]/) || [])[1];
        const tplVars = MAIL_TPL_VARS[tplKey] || {};
        if(Object.keys(tplVars).length){
          const vsel = document.createElement('select');
          vsel.style.cssText = 'font-size:.78rem;padding:.2rem;border:1px solid var(--border);border-radius:4px;background:#fff;color:var(--primary);width:auto;max-width:220px;font-weight:600;';
          vsel.title = 'Insérer une variable — remplacée automatiquement à l\'envoi';
          vsel.innerHTML = '<option value="">{ } Variable…</option>'
            + Object.entries(tplVars).map(([k, d]) => '<option value="{'+k+'}">{'+k+'} — '+d.replace(/</g,'&lt;')+'</option>').join('');
          vsel.addEventListener('mousedown', e => e.stopPropagation());
          vsel.addEventListener('change', () => {
            if(!vsel.value) return;
            if(ta.style.display !== 'none'){
              // Mode code HTML : insertion à la position du curseur du textarea
              const p = ta.selectionStart ?? ta.value.length;
              ta.value = ta.value.slice(0, p) + vsel.value + ta.value.slice(ta.selectionEnd ?? p);
              ta.focus(); ta.selectionStart = ta.selectionEnd = p + vsel.value.length;
            } else {
              ed.focus();
              if(savedRange){ const s = getSelection(); s.removeAllRanges(); s.addRange(savedRange); }
              document.execCommand('insertText', false, vsel.value); sync(); saveRange();
            }
            vsel.value = '';
          });
          bar.appendChild(vsel);
        }
        const spacer = document.createElement('span'); spacer.style.flex = '1'; bar.appendChild(spacer);
        const tgl = mkBtn('<i class="bi bi-code-slash"></i>', 'Basculer visuel / code HTML', () => {
          const showingHtml = ta.style.display !== 'none';
          if(showingHtml){ ed.innerHTML = ta.value; ta.style.display = 'none'; ed.style.display = 'block'; }
          else { sync(); ed.style.display = 'none'; ta.style.display = 'block'; }
        });
        tgl.style.color = 'var(--primary)';
        wrap.appendChild(bar);
        wrap.appendChild(ed);
        ta.parentNode.insertBefore(wrap, ta);
        wrap.appendChild(ta);
        ta.style.display = 'none';
        ta.style.border = 'none';
        ta.style.borderTop = '1px solid var(--border)';
        ta.style.borderRadius = '0';
      });
      </script>

    </div><!-- fin section « Envoi d'e-mails » -->
    <?php endif; ?>

    <?php if($settingsSub === 'requests'): ?>
    <div style="column-width:460px;column-gap:1.5rem;">

      <!-- Bloc demandes de téléphone -->
      <div class="card">
        <div class="card-header"><i class="bi bi-inbox"></i> Demandes de téléphone (formulaire public & circuit)</div>
        <form method="post" style="padding:1.5rem;">
          <input type="hidden" name="_entity" value="settings">
          <input type="hidden" name="_action" value="save">
          <input type="hidden" name="request_form" value="1">
          <p style="color:var(--text2);font-size:.88rem;margin-bottom:1rem;line-height:1.6;">
            Les demandes d'attribution / renouvellement arrivent par un <strong>formulaire public</strong> (sans compte),
            puis suivent un circuit de visas par <strong>liens e-mail personnels</strong>. Les valideurs variables
            (chef de service, D.G.A. de secteur) se paramètrent sur chaque <a href="?page=refs&tab=services" style="color:var(--primary);">service</a>.
          </p>
          <div style="display:flex;align-items:center;gap:.6rem;background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:.6rem .9rem;margin-bottom:1.25rem;font-size:.8rem;">
            🔗 <code style="font-family:var(--font-mono);font-size:.75rem;word-break:break-all;flex:1;"><?=h(baseUrl($pdo) . '?page=demande')?></code>
            <button type="button" class="btn-secondary" style="font-size:.75rem;padding:.3rem .7rem;" onclick="copySignLink(this, '<?=h(baseUrl($pdo) . '?page=demande')?>')">📋 Copier</button>
          </div>
          <div class="form-grid">
            <div class="form-group"><label>E-mail notifié à chaque nouvelle demande</label><input type="email" name="request_notify_email" value="<?=h(getSetting($pdo,'request_notify_email',''))?>" placeholder="dsi@collectivite.fr"></div>
            <div class="form-group"><label>Relance des valideurs après (jours)</label><input type="number" name="request_reminder_days" value="<?=(int)getSetting($pdo,'request_reminder_days',5)?>" min="1" max="60" style="max-width:120px;"></div>
            <div class="form-group"><label>Visa D.S.I. — nom par défaut</label><input type="text" name="request_dsi_name" value="<?=h(getSetting($pdo,'request_dsi_name',''))?>" placeholder="M. PARFAIT"></div>
            <div class="form-group"><label>Visa D.S.I. — e-mail par défaut</label><input type="email" name="request_dsi_email" value="<?=h(getSetting($pdo,'request_dsi_email',''))?>" placeholder="dsi@collectivite.fr"></div>
            <div class="form-group"><label>Visa D.G.S. — nom par défaut</label><input type="text" name="request_dgs_name" value="<?=h(getSetting($pdo,'request_dgs_name',''))?>" placeholder="M. ROL"></div>
            <div class="form-group"><label>Visa D.G.S. — e-mail par défaut</label><input type="email" name="request_dgs_email" value="<?=h(getSetting($pdo,'request_dgs_email',''))?>" placeholder="dgs@collectivite.fr"></div>
          </div>
          <div style="padding-top:1rem;border-top:1px solid var(--border);margin-top:1rem;">
            <button type="submit" class="btn-primary"><i class="bi bi-save"></i> Enregistrer</button>
          </div>
        </form>
      </div>

      <!-- Bloc personnalisation du formulaire public -->
      <div class="card">
        <div class="card-header"><i class="bi bi-pencil-square"></i> Personnalisation du formulaire de demande</div>
        <form method="post" style="padding:1.5rem;">
          <input type="hidden" name="_entity" value="settings">
          <input type="hidden" name="_action" value="save">
          <input type="hidden" name="request_form_texts" value="1">
          <p style="color:var(--text2);font-size:.88rem;margin-bottom:1rem;line-height:1.6;">
            Adaptez les textes affichés sur le <a href="<?=h(baseUrl($pdo) . '?page=demande')?>" target="_blank" style="color:var(--primary);">formulaire public</a>.
            Le <strong>logo</strong> affiché en tête est celui configuré ci-dessus (bloc « Logo des bons de remise PDF ») ; à défaut, le logo de l'application est utilisé.
          </p>
          <div class="form-grid">
            <div class="form-group form-full"><label>Titre du formulaire</label><input type="text" name="request_form_title" value="<?=h(getSetting($pdo,'request_form_title','Demande de téléphone portable'))?>" placeholder="Demande de téléphone portable"></div>
            <div class="form-group form-full"><label>Texte d'introduction</label><textarea name="request_form_intro" rows="2" placeholder="Quelques mots sous le titre"><?=h(getSetting($pdo,'request_form_intro',''))?></textarea></div>
            <div class="form-group form-full"><label>Libellé du champ « Motivation »</label><input type="text" name="request_form_motivation_label" value="<?=h(getSetting($pdo,'request_form_motivation_label',''))?>"></div>
            <div class="form-group"><label>Motifs de remplacement <span style="font-weight:400;text-transform:none;">(un par ligne)</span></label><textarea name="request_form_motifs" rows="5" placeholder="Panne&#10;Casse&#10;Perte&#10;Vol&#10;Obsolescence"><?=h(getSetting($pdo,'request_form_motifs',"Panne\nCasse\nPerte\nVol\nObsolescence"))?></textarea></div>
            <div class="form-group"><label>Nota (bas du formulaire) <span style="font-weight:400;text-transform:none;">(vide = masqué)</span></label><textarea name="request_form_nota" rows="5" placeholder="Mention légale affichée en bas du formulaire"><?=h(getSetting($pdo,'request_form_nota',''))?></textarea></div>
            <div class="form-group form-full"><label>Message de confirmation <span style="font-weight:400;text-transform:none;">(après envoi)</span></label><textarea name="request_form_success" rows="2"><?=h(getSetting($pdo,'request_form_success',''))?></textarea></div>
          </div>
          <div style="display:flex;gap:.75rem;align-items:center;padding-top:1rem;border-top:1px solid var(--border);margin-top:1rem;">
            <button type="submit" class="btn-primary"><i class="bi bi-save"></i> Enregistrer</button>
            <a href="<?=h(baseUrl($pdo) . '?page=demande')?>" target="_blank" class="btn-secondary" style="text-decoration:none;"><i class="bi bi-eye"></i> Prévisualiser</a>
          </div>
        </form>
      </div>

      <!-- Bloc circuits de validation enregistrés -->
      <?php $reqCircuits = $pdo->query("SELECT * FROM request_circuits ORDER BY name")->fetchAll(); ?>
      <div class="card">
        <div class="card-header"><i class="bi bi-diagram-3"></i> Circuits de validation enregistrés</div>
        <div style="padding:1.5rem;">
          <p style="color:var(--text2);font-size:.88rem;margin-bottom:1rem;line-height:1.6;">
            Enregistrez ici vos circuits types (étapes + valideurs) : ils sont ensuite <strong>proposés à la
            qualification</strong> de chaque demande pour pré-remplir le circuit en un clic — qui reste
            ajustable au cas par cas. Modifier ou supprimer un circuit ne touche pas les demandes déjà lancées.
          </p>

          <?php if ($reqCircuits): ?>
          <table class="data-table" style="font-size:.85rem;margin-bottom:1.25rem;">
            <thead><tr><th>Nom</th><th>Étapes</th><th style="width:90px;">Actions</th></tr></thead>
            <tbody>
            <?php foreach ($reqCircuits as $c): $cSteps = json_decode($c['steps'] ?: '[]', true) ?: []; ?>
            <tr>
              <td><strong><?=h($c['name'])?></strong></td>
              <td class="muted" style="font-size:.8rem;"><?=h(implode(' → ', array_column($cSteps, 'label')) ?: '—')?></td>
              <td style="white-space:nowrap;">
                <button type="button" class="btn-icon" title="Modifier ce circuit" style="color:var(--primary);"
                  onclick='circuitPresetEdit(<?=json_encode(['id' => (int)$c['id'], 'name' => $c['name'], 'steps' => $cSteps], JSON_UNESCAPED_UNICODE | JSON_HEX_APOS | JSON_HEX_TAG)?>)'><i class="bi bi-pencil"></i></button>
                <form method="post" style="display:inline;" onsubmit="return confirm('Supprimer le circuit « <?=h(addslashes($c['name']))?> » ? Les demandes déjà lancées ne sont pas modifiées.')">
                  <?=csrf_field()?>
                  <input type="hidden" name="_entity" value="req_circuit">
                  <input type="hidden" name="_action" value="delete">
                  <input type="hidden" name="_id" value="<?=(int)$c['id']?>">
                  <button type="submit" class="btn-icon btn-del" title="Supprimer"><i class="bi bi-trash"></i></button>
                </form>
              </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
          <?php else: ?>
          <div style="background:var(--bg3);border:1px dashed var(--border);border-radius:var(--radius-sm);padding:1rem;margin-bottom:1.25rem;text-align:center;color:var(--text3);font-size:.88rem;">
            Aucun circuit enregistré pour l'instant — créez le premier ci-dessous.
          </div>
          <?php endif; ?>

          <form method="post" id="circuit-preset-form">
            <?=csrf_field()?>
            <input type="hidden" name="_entity" value="req_circuit">
            <input type="hidden" name="_action" value="save">
            <input type="hidden" name="_id" id="cp-id" value="">
            <div class="form-group form-full" style="margin-bottom:.75rem;">
              <label id="cp-form-title">Nouveau circuit</label>
              <input type="text" name="circuit_name" id="cp-name" placeholder="ex : Circuit standard, Direction générale…" required>
            </div>
            <table class="data-table" id="preset-table" style="font-size:.85rem;">
              <thead><tr><th style="width:30px;"></th><th>Visa (libellé)</th><th>Valideur</th><th>E-mail</th><th style="width:40px;"></th></tr></thead>
              <tbody></tbody>
            </table>
            <div style="display:flex;gap:.75rem;margin-top:1rem;flex-wrap:wrap;align-items:center;">
              <button type="button" class="btn-secondary" onclick="presetAddRow()">➕ Ajouter une étape</button>
              <button type="submit" class="btn-primary"><i class="bi bi-save"></i> <span id="cp-submit-label">Enregistrer le circuit</span></button>
              <button type="button" class="btn-secondary" id="cp-cancel" style="display:none;" onclick="circuitPresetReset()">Annuler la modification</button>
            </div>
          </form>
          <script>
          function presetAddRow(step) {
            const tb = document.querySelector('#preset-table tbody');
            const tr = document.createElement('tr');
            tr.innerHTML = '<td class="drag-cell" title="Glisser pour réordonner"><i class="bi bi-grip-vertical"></i></td>'
              + '<td><input type="text" name="step_label[]" placeholder="ex : Direction du service"></td>'
              + '<td style="position:relative;"><input type="text" class="circuit-name" name="step_name[]" placeholder="Prénom Nom" autocomplete="off"><div class="adp-box circuit-suggest"></div></td>'
              + '<td><input type="email" class="circuit-email" name="step_email[]" placeholder="valideur@collectivite.fr"></td>'
              + '<td><button type="button" class="btn-icon btn-del" title="Retirer cette étape" onclick="this.closest(\'tr\').remove()"><i class="bi bi-x-lg"></i></button></td>';
            if (step) {
              tr.querySelector('[name="step_label[]"]').value = step.label || '';
              tr.querySelector('[name="step_name[]"]').value  = step.name  || '';
              tr.querySelector('[name="step_email[]"]').value = step.email || '';
            }
            tb.appendChild(tr);
          }
          function circuitPresetEdit(c) {
            document.getElementById('cp-id').value = c.id;
            document.getElementById('cp-name').value = c.name || '';
            document.getElementById('cp-form-title').textContent = 'Modifier le circuit « ' + (c.name || '') + ' »';
            document.getElementById('cp-submit-label').textContent = 'Mettre à jour le circuit';
            document.getElementById('cp-cancel').style.display = '';
            document.querySelector('#preset-table tbody').innerHTML = '';
            (c.steps || []).forEach(s => presetAddRow(s));
            if (!(c.steps || []).length) presetAddRow();
            document.getElementById('circuit-preset-form').scrollIntoView({behavior: 'smooth', block: 'center'});
          }
          function circuitPresetReset() {
            document.getElementById('cp-id').value = '';
            document.getElementById('cp-name').value = '';
            document.getElementById('cp-form-title').textContent = 'Nouveau circuit';
            document.getElementById('cp-submit-label').textContent = 'Enregistrer le circuit';
            document.getElementById('cp-cancel').style.display = 'none';
            document.querySelector('#preset-table tbody').innerHTML = '';
            presetAddRow();
          }
          presetAddRow();
          // ── Autocomplétion annuaire (AD + référentiel) sur le champ Valideur ──
          // Même pattern que la fiche demande : délégation sur la table.
          (function(){
            const table = document.getElementById('preset-table');
            if (!table) return;
            const esc = s => { const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; };
            table.addEventListener('input', e => {
              const inp = e.target;
              if (!inp.classList || !inp.classList.contains('circuit-name')) return;
              const box = inp.parentElement.querySelector('.circuit-suggest');
              const q = inp.value.trim();
              clearTimeout(inp._t);
              if (q.length < 2) { box.style.display='none'; box.innerHTML=''; return; }
              inp._t = setTimeout(async () => {
                try {
                  const r = await fetch('index.php?ajax_request_lookup=1&q='+encodeURIComponent(q));
                  const items = await r.json();
                  if (!Array.isArray(items) || !items.length) { box.style.display='none'; box.innerHTML=''; return; }
                  box.innerHTML = items.map((p,i) =>
                    '<div class="adp-item" data-i="'+i+'"><strong>'+esc(p.name)+'</strong>'
                    + (p.source==='ad' ? ' <span style="color:var(--info);font-size:.7rem;">AD</span>' : '')
                    + '<br><span class="muted" style="font-size:.75rem;">'+esc([p.fonction,p.email].filter(Boolean).join(' · '))+'</span></div>').join('');
                  box.style.display='block';
                  const emailInp = inp.closest('tr').querySelector('.circuit-email');
                  [...box.querySelectorAll('.adp-item')].forEach(el => el.addEventListener('mousedown', ev => {
                    ev.preventDefault(); const p = items[+el.dataset.i];
                    inp.value = p.name || '';
                    if (emailInp && p.email) emailInp.value = p.email;
                    box.style.display='none'; box.innerHTML='';
                  }));
                } catch(err) { box.style.display='none'; }
              }, 250);
            });
            table.addEventListener('focusout', e => {
              if (e.target.classList && e.target.classList.contains('circuit-name')) {
                const box = e.target.parentElement.querySelector('.circuit-suggest');
                setTimeout(() => { if (box) { box.style.display='none'; } }, 150);
              }
            });
          })();
          </script>
        </div>
      </div>

    </div><!-- fin section « Demandes de téléphone » -->
    <?php endif; ?>

    <?php if($settingsSub === 'security'): ?>
    <div style="column-width:460px;column-gap:1.5rem;">

      <!-- Bloc LDAP / Active Directory -->
      <div class="card">
        <div class="card-header"><i class="bi bi-globe2"></i> Authentification Active Directory (LDAP)</div>
        <?php if(empty($_SESSION['is_admin'])): ?>
        <p style="padding:1.5rem;color:var(--text2);font-size:.88rem;">Configuration réservée aux super-administrateurs.</p>
        <?php else: ?>
        <?php
          // Champ verrouillé si imposé par variable d'environnement (Docker)
          $lk  = fn($k) => ldap_env_locked($k) ? 'disabled title="Imposé par la variable d\'environnement '.h(LDAP_KEYS[$k]).' — modifiable uniquement côté serveur"' : '';
          $lkN = fn($k) => ldap_env_locked($k) ? ' <span style="font-weight:400;text-transform:none;color:var(--warning);">🔒 env</span>' : '';
        ?>
        <form method="post" style="padding:1.5rem;">
          <input type="hidden" name="_entity" value="settings">
          <input type="hidden" name="_action" value="save">
          <input type="hidden" name="ldap_form" value="1">
          <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
            Les administrateurs se connectent avec leur <strong>compte Active Directory</strong>, en complément des comptes locaux
            (mot de passe local testé d'abord, puis bind LDAP). Un utilisateur AD valide et inconnu est <strong>provisionné automatiquement</strong>
            (jamais super-admin). Marqué 🔒 env : valeur imposée par l'environnement (Docker).
          </p>
          <?php if(!extension_loaded('ldap')): ?>
          <div style="background:var(--danger-dim);color:var(--danger);border-radius:var(--radius-sm);padding:.75rem 1rem;margin-bottom:1.25rem;font-size:.85rem;">
            ⚠️ Extension PHP <strong>« ldap »</strong> non chargée — l'authentification AD restera inactive (php.ini : <code>extension=ldap</code>, puis redémarrez le serveur web).
          </div>
          <?php endif; ?>
          <div class="form-grid">
            <div class="form-group form-full">
              <label style="display:flex;align-items:center;gap:.6rem;cursor:pointer;text-transform:none;font-size:.88rem;">
                <input type="checkbox" name="ldap_enabled" value="1" <?=ldap_cfg('ldap_enabled')?'checked':''?> <?=$lk('ldap_enabled')?> style="width:15px;height:15px;accent-color:var(--primary);">
                <span><strong>Activer l'authentification Active Directory</strong><?=$lkN('ldap_enabled')?></span>
              </label>
            </div>
            <div class="form-group"><label>Serveur LDAP<?=$lkN('ldap_server')?></label><input type="text" name="ldap_server" value="<?=h(ldap_cfg('ldap_server'))?>" placeholder="dc.chatillon.lan ou ldaps://dc.chatillon.lan" <?=$lk('ldap_server')?>></div>
            <?php
              // Port affiché : la valeur enregistrée, ou le port standard déduit
              // de LDAPS. Le champ n'est ainsi jamais à « 0 », qui n'évoque rien.
              $ldapPortShown = (int)ldap_cfg('ldap_port') ?: (ldap_cfg('ldap_use_ssl') ? 636 : 389);
            ?>
            <div class="form-group"><label>Port<?=$lkN('ldap_port')?></label><input type="number" id="ldap-port" name="ldap_port" value="<?=$ldapPortShown?>" min="0" max="65535" <?=$lk('ldap_port')?>><small style="color:var(--text3);font-size:.75rem;">389 en clair, 636 en LDAPS. Suit automatiquement la case ci-dessous, sauf port personnalisé (3269…).</small></div>
            <div class="form-group">
              <label style="display:flex;align-items:center;gap:.6rem;cursor:pointer;text-transform:none;font-size:.85rem;">
                <input type="checkbox" id="ldap-use-ssl" name="ldap_use_ssl" value="1" <?=ldap_cfg('ldap_use_ssl')?'checked':''?> <?=$lk('ldap_use_ssl')?> style="width:15px;height:15px;accent-color:var(--primary);">
                <span>LDAPS — connexion chiffrée (TLS)<?=$lkN('ldap_use_ssl')?></span>
              </label>
            </div>
            <script>
            // Le port suit la case LDAPS : 636 coché, 389 décoché. On ne touche
            // pas à un port saisi à la main (3269 pour le catalogue global, etc.).
            (function(){
              var ssl = document.getElementById('ldap-use-ssl'), port = document.getElementById('ldap-port');
              if (!ssl || !port || port.readOnly || port.disabled) return;
              ssl.addEventListener('change', function(){
                var v = port.value.trim();
                if (v === '' || v === '0' || v === '389' || v === '636') port.value = ssl.checked ? 636 : 389;
              });
            })();
            </script>
            <div class="form-group">
              <label style="display:flex;align-items:center;gap:.6rem;cursor:pointer;text-transform:none;font-size:.85rem;">
                <input type="checkbox" name="ldap_validate_cert" value="1" <?=ldap_cfg('ldap_validate_cert')?'checked':''?> <?=$lk('ldap_validate_cert')?> style="width:15px;height:15px;accent-color:var(--primary);">
                <span>Valider le certificat serveur <small style="color:var(--text3);">(décocher si CA interne/auto-signée)</small><?=$lkN('ldap_validate_cert')?></span>
              </label>
            </div>
            <div class="form-group"><label>Domaine AD (bind UPN)<?=$lkN('ldap_domain')?></label><input type="text" name="ldap_domain" value="<?=h(ldap_cfg('ldap_domain'))?>" placeholder="chatillon.lan → utilisateur@chatillon.lan" <?=$lk('ldap_domain')?>></div>
            <div class="form-group"><label>Base DN<?=$lkN('ldap_base_dn')?></label><input type="text" name="ldap_base_dn" value="<?=h(ldap_cfg('ldap_base_dn'))?>" placeholder="DC=chatillon,DC=lan" <?=$lk('ldap_base_dn')?>></div>
            <div class="form-group form-full"><label>Groupe AD requis <span style="font-weight:400;text-transform:none;color:var(--warning);">— fortement conseillé</span><?=$lkN('ldap_required_group')?></label>
              <input type="text" name="ldap_required_group" value="<?=h(ldap_cfg('ldap_required_group'))?>" placeholder="GG-SimCity-Admins ou CN=GG-SimCity-Admins,OU=Groupes,DC=chatillon,DC=lan" <?=$lk('ldap_required_group')?>>
              <small style="color:var(--text3);font-size:.75rem;">Sans groupe, <strong>tout compte AD valide</strong> accède à l'application. Les groupes imbriqués sont pris en compte.</small>
            </div>
            <div class="form-group form-full"><label>Fichier CA (PEM) <span style="font-weight:400;text-transform:none;">(optionnel, chemin serveur)</span><?=$lkN('ldap_ca_cert')?></label><input type="text" name="ldap_ca_cert" value="<?=h(ldap_cfg('ldap_ca_cert'))?>" placeholder="/etc/ssl/certs/ca-interne.pem" <?=$lk('ldap_ca_cert')?>><small style="color:var(--text3);font-size:.75rem;">Chemin vu <strong>par le serveur</strong> — dans le conteneur Docker, pas sur votre poste. Inutile si la validation du certificat est décochée.</small></div>
            <div class="form-group"><label>Compte de service <span style="font-weight:400;text-transform:none;">(bouton Tester)</span><?=$lkN('ldap_bind_user')?></label><input type="text" name="ldap_bind_user" value="<?=h(ldap_cfg('ldap_bind_user'))?>" autocomplete="off" placeholder="svc-simcity@chatillon.lan" <?=$lk('ldap_bind_user')?>></div>
            <div class="form-group"><label>Mot de passe <span style="font-weight:400;text-transform:none;">(vide = inchangé)</span><?=$lkN('ldap_bind_password')?></label><input type="password" name="ldap_bind_password" value="" autocomplete="new-password" <?=$lk('ldap_bind_password')?>></div>
          </div>
          <div style="display:flex;gap:.75rem;align-items:center;padding-top:1rem;border-top:1px solid var(--border);margin-top:1rem;">
            <button type="submit" class="btn-primary"><i class="bi bi-save"></i> Enregistrer</button>
          </div>
        </form>
        <form method="post" style="padding:0 1.5rem 1.5rem;">
          <input type="hidden" name="_entity" value="ldap_test">
          <input type="hidden" name="_action" value="test">
          <button type="submit" class="btn-secondary">🔌 Tester la connexion</button>
          <small style="color:var(--text3);margin-left:.75rem;">Teste la configuration <strong>enregistrée</strong> (enregistrez d'abord vos modifications).</small>
        </form>
        <?=$secretPurgeBox($pdo, 'ldap_bind_password', 'LDAP_BIND_PASSWORD', 'mot de passe du compte de service AD')?>
        <?php endif; ?>
      </div>

    </div><!-- fin section « Sécurité » -->
    <?php endif; ?>

    <?php if($settingsSub === 'maintenance' && !empty($_SESSION['is_admin'])):
        $backups   = simcity_list_backups();
        $retention = defined('BACKUP_RETENTION') ? BACKUP_RETENTION : 7;
        $fmtSize = function($b) { return $b >= 1048576 ? round($b/1048576,1).' Mo' : round($b/1024).' Ko'; };
        $autoOn    = defined('BACKUP_AUTO') && BACKUP_AUTO;
        $autoLast  = getSetting($pdo, 'last_auto_backup', '');
        $autoHours = defined('BACKUP_AUTO_INTERVAL') ? round(((int)BACKUP_AUTO_INTERVAL)/3600) : 24;
    ?>
    <!-- Bloc sauvegarde / restauration — super-admin uniquement -->
    <div class="card">
      <div class="card-header"><i class="bi bi-hdd"></i> Sauvegardes de la base de données</div>
      <div style="padding:1.5rem;">
        <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
          Sauvegarde complète (structure + données : lignes, matériels, agents, bons signés, signatures, historique…).
          Les fichiers créés sur le serveur sont conservés en <strong><?=$retention?> exemplaires glissants</strong>
          dans le dossier <code style="font-size:.8rem;"><?=h(BACKUP_DIR)?></code> (protégé du web).
        </p>

        <!-- Statut de la sauvegarde automatique intégrée -->
        <div style="display:flex;align-items:center;gap:.6rem;background:<?=$autoOn?'rgba(16,185,129,.08)':'rgba(148,163,184,.08)'?>;border:1px solid <?=$autoOn?'rgba(16,185,129,.25)':'var(--border)'?>;border-radius:8px;padding:.75rem 1rem;margin-bottom:1.25rem;font-size:.85rem;">
          <span style="font-size:1.2rem;"><?=$autoOn?'🟢':'⚪'?></span>
          <div>
            <strong style="color:<?=$autoOn?'var(--success)':'var(--text2)'?>;">Sauvegarde automatique <?=$autoOn?'activée':'désactivée'?></strong>
            <span style="color:var(--text3);">— déclenchée par le trafic, toutes les <?=$autoHours?> h (sans cron, idéal en conteneur).</span><br>
            <span style="color:var(--text3);font-size:.8rem;">Dernière sauvegarde automatique : <strong><?= $autoLast ? h(date('d/m/Y H:i', strtotime($autoLast))) : 'aucune pour l\'instant' ?></strong>
            <?php if(!$autoOn): ?> — activez <code>BACKUP_AUTO</code> dans <code>config.php</code>.<?php endif; ?></span>
          </div>
        </div>

        <div style="display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:1.5rem;">
          <form method="post" style="display:inline;margin:0;padding:0;">
            <input type="hidden" name="_entity" value="backup">
            <input type="hidden" name="_action" value="run">
            <button type="submit" class="btn-primary" style="display:inline-flex;align-items:center;gap:6px;"><i class="bi bi-hdd-fill"></i> Sauvegarder maintenant (serveur)</button>
          </form>
          <a href="?page=backup_sql" class="btn-secondary" style="text-decoration:none;display:inline-flex;align-items:center;gap:6px;">⬇️ Télécharger un .sql</a>
        </div>

        <!-- Liste des sauvegardes stockées -->
        <h4 style="font-size:.9rem;color:var(--text2);margin-bottom:.75rem;"><i class="bi bi-folder2-open"></i> Sauvegardes présentes sur le serveur</h4>
        <?php if(!$backups): ?>
          <div class="muted" style="font-size:.85rem;margin-bottom:1rem;">Aucune sauvegarde sur le serveur pour l'instant. Cliquez sur « Sauvegarder maintenant » ou planifiez le cron (voir ci-dessous).</div>
        <?php else: ?>
          <div style="overflow-x:auto;margin-bottom:1rem;">
          <table class="data-table" style="font-size:.85rem;">
            <thead><tr><th>Fichier</th><th>Date</th><th>Taille</th><th>Actions</th></tr></thead>
            <tbody>
            <?php foreach($backups as $bk): ?>
              <tr>
                <td><code style="font-size:.78rem;"><?=h($bk['name'])?></code></td>
                <td><?=date('d/m/Y H:i', $bk['mtime'])?></td>
                <td><?=$fmtSize($bk['size'])?></td>
                <td class="actions" style="white-space:nowrap;">
                  <a href="?page=backup_download&f=<?=urlencode($bk['name'])?>" class="btn-icon" title="Télécharger" style="text-decoration:none;">⬇️</a>
                  <form method="post" style="display:inline;margin:0;" onsubmit="return confirm('Restaurer cette sauvegarde ? La base actuelle sera écrasée (une sauvegarde de sécurité est créée avant).')">
                    <input type="hidden" name="_entity" value="backup">
                    <input type="hidden" name="_action" value="restore">
                    <input type="hidden" name="file" value="<?=h($bk['name'])?>">
                    <input type="hidden" name="confirm_word" value="RESTAURER">
                    <button type="submit" class="btn-icon" title="Restaurer cette sauvegarde" style="color:var(--warning);"><i class="bi bi-arrow-counterclockwise"></i></button>
                  </form>
                  <form method="post" style="display:inline;margin:0;" onsubmit="return confirm('Supprimer définitivement cette sauvegarde ?')">
                    <input type="hidden" name="_entity" value="backup">
                    <input type="hidden" name="_action" value="delete">
                    <input type="hidden" name="file" value="<?=h($bk['name'])?>">
                    <button type="submit" class="btn-icon btn-del" title="Supprimer"><i class="bi bi-trash3"></i></button>
                  </form>
                </td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
          </div>
        <?php endif; ?>

        <!-- Restauration depuis un fichier uploadé -->
        <details style="margin-bottom:1rem;background:rgba(245,158,11,.05);border:1px solid rgba(245,158,11,.25);border-radius:8px;padding:.75rem 1rem;">
          <summary style="cursor:pointer;font-size:.85rem;color:var(--warning);font-weight:600;">♻️ Restaurer depuis un fichier .sql externe</summary>
          <form method="post" enctype="multipart/form-data" style="padding:.75rem 0 0;margin:0;"
                onsubmit="return confirm('Restaurer depuis ce fichier ? La base actuelle sera écrasée (une sauvegarde de sécurité est créée avant).')">
            <input type="hidden" name="_entity" value="backup">
            <input type="hidden" name="_action" value="restore">
            <p class="muted" style="font-size:.8rem;margin-bottom:.6rem;">Envoyez un fichier <code>.sql</code> généré par SimCity. Tapez <strong>RESTAURER</strong> pour confirmer.</p>
            <div style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:center;">
              <input type="file" name="sql_file" accept=".sql" required style="flex:1;min-width:200px;">
              <input type="text" name="confirm_word" placeholder="RESTAURER" autocomplete="off" required style="max-width:150px;font-family:var(--font-mono);">
              <button type="submit" class="btn-secondary" style="color:var(--warning);border-color:rgba(245,158,11,.4);">♻️ Restaurer</button>
            </div>
          </form>
        </details>

        <!-- Aide planification -->
        <details style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:.75rem 1rem;">
          <summary style="cursor:pointer;font-size:.85rem;color:var(--text2);font-weight:600;">⏰ Planification (autres méthodes)</summary>
          <div style="font-size:.82rem;color:var(--text2);line-height:1.7;margin-top:.6rem;">
            La <strong>sauvegarde automatique intégrée</strong> (ci-dessus) suffit dans la plupart des cas —
            aucune configuration serveur requise. Elle ne se déclenche toutefois que s'il y a du trafic ;
            si l'application peut rester plusieurs jours sans visite, ajoutez l'une de ces méthodes :
            <div style="margin:.5rem 0;"><strong>Endpoint HTTP + planificateur externe</strong> (adapté aux conteneurs) :<br>
              définissez la variable d'environnement <code>BACKUP_TOKEN</code> puis appelez chaque nuit :<br>
              <code style="display:block;background:var(--card2);padding:.5rem;border-radius:6px;font-size:.78rem;margin-top:.25rem;word-break:break-all;">curl -fsS "https://votre-site/backup.php?token=VOTRE_JETON"</code>
              <span class="muted" style="font-size:.78rem;">(depuis un cron de l'hôte, un conteneur planificateur, une GitHub Action, un service de « cron en ligne »…)</span>
            </div>
            <div style="margin:.5rem 0;"><strong>Depuis l'hôte Docker :</strong><br>
              <code style="display:block;background:var(--card2);padding:.5rem;border-radius:6px;font-size:.78rem;margin-top:.25rem;word-break:break-all;">0 2 * * * docker exec &lt;conteneur&gt; php /var/www/html/backup.php</code>
            </div>
            <span class="muted" style="font-size:.78rem;">💡 Restauration en ligne de commande : <code>mysql -u &lt;user&gt; -p <?=h(DB_NAME)?> &lt; fichier.sql</code></span>
          </div>
        </details>
      </div>
    </div>

    <?php
    // ── Rapport de comparaison, commun aux deux sources d'import ──
    // CSV d'inventaire et export de parc SFR passent par le même moteur
    // (simcity_parc_compare) et donc par le même rapport : mêmes écarts,
    // mêmes règles, un seul écran à comprendre.
    $parcControlReport = function(array $cmp, string $srcLabel, string $param, string $anchor) {
        $c = $cmp['counts'];
        $issueMeta = [
            'unknown'     => ['Ligne inconnue de SimCity',         'badge-danger',  'bi-question-circle'],
            'name'        => ['Titulaire différent',               'badge-warning', 'bi-person-exclamation'],
            'plan'        => ['Forfait différent',                 'badge-warning', 'bi-globe2'],
            'status'      => ['Statut différent',                  'badge-warning', 'bi-toggle-off'],
            'billing'     => ['Compte de facturation différent',   'badge-info',    'bi-cash-coin'],
            'iccid'       => ['Carte SIM différente',              'badge-info',    'bi-sim'],
            'imei'        => ['IMEI différent du matériel associé', 'badge-warning', 'bi-phone'],
            'codes'       => ['Codes SIM à compléter ou corriger',  'badge-info',    'bi-key'],
            'device_swap' => ['Terminal utilisé ≠ terminal acheté', 'badge-muted',   'bi-arrow-left-right'],
            'imei_absent' => ['IMEI utilisé absent du parc',        'badge-danger',  'bi-exclamation-triangle'],
        ];
        $fltr = isset($_GET[$param], $issueMeta[$_GET[$param]]) ? $_GET[$param] : '';
        $flagged = array_values(array_filter($cmp['rows'], fn($r) => $r['issues']));
        usort($flagged, fn($x, $y) => count($y['issues']) <=> count($x['issues']));
        $base = "?page=refs&tab=settings&sub=maintenance";
        ob_start(); ?>
        <div class="kpi-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:1rem;margin-bottom:1.25rem;">
          <div><div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Lignes dans le fichier</div>
               <div style="font-size:1.5rem;font-weight:700;color:var(--primary);"><?=$c['total']?></div>
               <div class="muted"><?=h($srcLabel)?></div></div>
          <div><div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Concordantes</div>
               <div style="font-size:1.5rem;font-weight:700;color:var(--success);"><?=$c['ok']?></div>
               <div class="muted">aucun écart détecté</div></div>
          <div><div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Inconnues de SimCity</div>
               <div style="font-size:1.5rem;font-weight:700;color:<?=$c['unknown']?'var(--danger)':'var(--success)'?>;"><?=$c['unknown']?></div>
               <div class="muted">seraient des créations</div></div>
          <div><div style="font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;">Absentes du fichier</div>
               <div style="font-size:1.5rem;font-weight:700;color:<?=$c['missing']?'var(--warning)':'var(--success)'?>;"><?=$c['missing']?></div>
               <div class="muted">actives dans SimCity</div></div>
        </div>

        <div style="display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem;">
          <a href="<?=$base?>#<?=h($anchor)?>" class="badge <?=$fltr===''?'badge-info':'badge-muted'?>" style="text-decoration:none;">Tous les écarts (<?=count($flagged)?>)</a>
          <?php foreach($issueMeta as $k => [$lbl, $cls, $ico]): if(empty($c[$k])) continue; ?>
          <a href="<?=$base?>&<?=h($param)?>=<?=$k?>#<?=h($anchor)?>" class="badge <?=$fltr===$k?$cls:'badge-muted'?>" style="text-decoration:none;"><i class="bi <?=$ico?>"></i> <?=$lbl?> (<?=$c[$k]?>)</a>
          <?php endforeach; ?>
        </div>

        <div style="max-height:420px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:1.5rem;">
          <table class="data-table" style="font-size:.83rem;">
            <thead><tr><th>Ligne</th><th>Dans le fichier</th><th>Dans SimCity</th><th>Écarts constatés</th></tr></thead>
            <tbody>
            <?php $shownP = 0; foreach($flagged as $r): if($fltr !== '' && !in_array($fltr, $r['issues'], true)) continue;
                  if(++$shownP > 400) break; $rec = $r['rec']; $a = $r['app']; ?>
            <tr>
              <td style="font-family:var(--font-mono);white-space:nowrap;"><?=h(formatPhone($rec['phone']))?></td>
              <td style="font-size:.8rem;">
                <?=h(trim($rec['last_name'] . ' ' . $rec['first_name']) ?: '—')?><br>
                <span class="muted"><?=h($rec['plan'] ?: '—')?><?=$rec['status'] !== '' ? ' · ' . h($rec['status']) : ''?><?=$rec['billing_acct'] !== '' ? ' · ' . h($rec['billing_acct']) : ''?></span><br>
                <span class="muted"><?=h($rec['device_used'] ?: 'terminal non renseigné')?></span>
              </td>
              <td style="font-size:.8rem;">
                <?php if(!$a): ?><span class="badge badge-danger" style="font-size:.66rem;">absente du référentiel</span>
                <?php else: ?>
                  <?=h(trim($a['ln'] . ' ' . $a['fn']) ?: 'sans utilisateur')?><br>
                  <span class="muted"><?=h($a['plan_name'] ?: '—')?> · <?=h($a['status'])?><?=$a['acct'] !== '' ? ' · ' . h($a['acct']) : ' · sans compte'?></span><br>
                  <span class="muted"><?=h(trim($a['brand'] . ' ' . $a['model']) ?: 'aucun matériel associé')?></span>
                <?php endif; ?>
              </td>
              <td>
                <?php foreach($r['issues'] as $is): [$lbl, $cls, $ico] = $issueMeta[$is]; ?>
                <span class="badge <?=$cls?>" style="font-size:.66rem;"><i class="bi <?=$ico?>"></i> <?=$lbl?></span>
                <?php endforeach; ?>
              </td>
            </tr>
            <?php endforeach; if(!$shownP): ?><tr><td colspan="4" class="empty-cell">Aucun écart pour ce filtre</td></tr><?php endif; ?>
            <?php if($shownP > 400): ?><tr><td colspan="4" class="muted">Affichage limité aux 400 premiers écarts.</td></tr><?php endif; ?>
            </tbody>
          </table>
        </div>

        <?php if($cmp['missing']): ?>
        <h4 style="font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:var(--warning);margin-bottom:.5rem;">
          <i class="bi bi-eye-slash"></i> Dans SimCity mais absentes du fichier (<?=count($cmp['missing'])?>)</h4>
        <p class="muted" style="font-size:.82rem;margin-bottom:.6rem;">Lignes actives au référentiel qui ne figurent pas dans le fichier déposé — à vérifier (résiliation non enregistrée, ou fichier partiel).</p>
        <div style="max-height:200px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:1.5rem;">
          <table class="data-table" style="font-size:.83rem;">
            <thead><tr><th>Ligne</th><th>Utilisateur</th><th>Statut SimCity</th></tr></thead>
            <tbody>
            <?php foreach($cmp['missing'] as $m): ?>
            <tr><td style="font-family:var(--font-mono);white-space:nowrap;"><?=h(formatPhone(preg_replace('/\D/', '', (string)$m['phone_number'])))?></td>
                <td><?=h(trim($m['ln'] . ' ' . $m['fn']) ?: '—')?></td>
                <td><?=h($m['status'])?></td></tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
        <?php endif; ?>
        <?php return ob_get_clean();
    };

    // ── Étape de contrôle avant importation ──────────────────────
    // Un CSV analysé attend confirmation : on liste les utilisateurs du
    // fichier, rapprochés du référentiel ou à créer, avec possibilité
    // d'associer manuellement chaque non-correspondance à un agent existant,
    // et on affiche le même rapport de comparaison que l'export SFR.
    $pendImp = $_SESSION['import_pending'] ?? null;
    if ($pendImp && !is_file($pendImp['file'])) { unset($_SESSION['import_pending']); $pendImp = null; }
    $impScan = null; $impCmp = null;
    if ($pendImp) {
        try { $impScan = simcity_import_scan_users($pdo, $pendImp['file']); }
        catch (Throwable $e) { $impScan = ['matched'=>[], 'unmatched'=>[]]; }
        // La comparaison n'a de sens que sans purge : après purge, tout est créé.
        if (empty($pendImp['purge'])) {
            try { $impCmp = simcity_parc_compare($pdo, simcity_import_csv_records($pendImp['file'])); }
            catch (Throwable $e) { $impCmp = null; }
        }
    }
    ?>
    <?php if($pendImp): ?>
    <div class="card" style="margin-top:1.5rem;border:1px solid var(--primary);" id="import-review">
      <div class="card-header"><i class="bi bi-person-check"></i> Contrôle avant importation — <?=h($pendImp['name'])?></div>
      <form method="post" style="padding:1.5rem;">
        <input type="hidden" name="<?=CSRF_TOKEN_NAME?>" value="<?=h($CSRF_TOKEN)?>">
        <input type="hidden" name="_entity" value="import">
        <input type="hidden" name="_action" value="run">
        <input type="hidden" name="pend_sha1" value="<?=h($pendImp['sha1'] ?? '')?>">

        <?php if(!empty($pendImp['purge'])): ?>
        <p style="background:var(--danger-dim);border:1px solid var(--danger);border-radius:var(--radius-sm);padding:.75rem 1rem;font-size:.85rem;margin-bottom:1.25rem;">
          <strong style="color:var(--danger);"><i class="bi bi-exclamation-triangle-fill"></i> Purge activée :</strong>
          la base sera vidée avant l'import — les <?=count($impScan['matched'])+count($impScan['unmatched'])?> utilisateur(s)
          du fichier seront tous créés (aucun rapprochement possible).
        </p>
        <?php else: ?>

        <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
          <strong><?=count($impScan['matched'])?></strong> utilisateur(s) du fichier correspondent déjà au référentiel,
          <strong><?=count($impScan['unmatched'])?></strong> sans correspondance.
          Pour un import propre, associez les non-correspondances à un utilisateur existant (recherche ci-dessous)
          ou laissez vide pour les créer.
        </p>

        <?php if($impCmp): ?>
        <h4 style="font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:var(--text2);margin-bottom:.6rem;">
          <i class="bi bi-clipboard-check"></i> Comparaison des lignes avec le référentiel</h4>
        <p class="muted" style="font-size:.82rem;margin-bottom:.9rem;">
          Même contrôle que l'export SFR : ce que le CSV apporte, ce que SimCity contient déjà, et les écarts entre les deux.
          L'import ne crée que ce qui manque (les doublons de numéro et d'IMEI sont ignorés) — ce tableau vous dit d'avance
          ce qui sera créé et sur quoi les deux sources divergent.
        </p>
        <?=$parcControlReport($impCmp, 'fichier CSV déposé', 'cissue', 'import-review')?>
        <?php endif; ?>

        <?php if($impScan['unmatched']): ?>
        <h4 style="font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:var(--warning);margin-bottom:.5rem;"><i class="bi bi-person-plus"></i> Sans correspondance (<?=count($impScan['unmatched'])?>)</h4>
        <div style="max-height:340px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:1.25rem;">
          <table class="data-table" style="font-size:.85rem;">
            <thead><tr><th>Utilisateur du fichier</th><th>Service (CSV)</th><th>Lignes CSV</th><th>Associer à un utilisateur existant</th><th>Résultat</th></tr></thead>
            <tbody>
            <?php foreach($impScan['unmatched'] as $u): ?>
              <tr class="imp-map">
                <td><strong><?=h($u['nom'].' '.$u['prenom'])?></strong></td>
                <td class="muted"><?=h($u['service'] ?: '—')?></td>
                <td><?=(int)$u['nb']?></td>
                <td style="min-width:240px;">
                  <div style="position:relative;">
                    <input type="text" class="imp-map-search" placeholder="🔎 Rechercher (vide = créer)" autocomplete="off" style="font-size:.83rem;padding:.4rem .6rem;">
                    <input type="hidden" name="agent_map[<?=h($u['key'])?>]" value="">
                    <div class="adp-box"></div>
                  </div>
                </td>
                <td><span class="imp-map-state badge badge-warning">sera créé</span></td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
        <?php endif; ?>

        <?php if($impScan['matched']): ?>
        <h4 style="font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:var(--success);margin-bottom:.5rem;"><i class="bi bi-check-circle"></i> Correspondances trouvées (<?=count($impScan['matched'])?>)</h4>
        <div style="max-height:260px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:1.25rem;">
          <table class="data-table" style="font-size:.85rem;">
            <thead><tr><th>Utilisateur du fichier</th><th>Service (CSV)</th><th>Lignes CSV</th><th>Utilisateur du référentiel</th></tr></thead>
            <tbody>
            <?php foreach($impScan['matched'] as $u): ?>
              <tr>
                <td><strong><?=h($u['nom'].' '.$u['prenom'])?></strong></td>
                <td class="muted"><?=h($u['service'] ?: '—')?></td>
                <td><?=(int)$u['nb']?></td>
                <td><span class="badge badge-success"><i class="bi bi-link-45deg"></i> <?=h($u['agent']['last_name'].' '.$u['agent']['first_name'])?></span>
                    <span class="muted" style="font-size:.75rem;"><?=h(implode(' · ', array_filter([$u['agent']['service_name'], $u['agent']['email']])))?></span></td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
        <?php endif; ?>
        <?php endif; ?>

        <div style="padding-top:1rem;border-top:1px solid var(--border);display:flex;gap:.75rem;align-items:center;">
          <button type="submit" class="btn-primary" style="display:inline-flex;align-items:center;gap:6px;"><i class="bi bi-check-lg"></i> Confirmer l'importation</button>
          <button type="submit" class="btn-secondary" formnovalidate
            onclick="this.form.querySelector('[name=_action]').value='cancel'">Annuler</button>
        </div>
      </form>
      <script>
      // Autocomplétion des rapprochements : recherche dans le référentiel
      // (même endpoint que les sélecteurs de lignes / matériels).
      document.querySelectorAll('#import-review .imp-map').forEach(tr => {
        const inp = tr.querySelector('.imp-map-search'), hid = tr.querySelector('input[type=hidden]'),
              box = tr.querySelector('.adp-box'), badge = tr.querySelector('.imp-map-state');
        const esc = s => { const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; };
        const hide = () => { box.style.display='none'; box.innerHTML=''; };
        const mark = () => {
          if(hid.value){ badge.textContent='→ rapproché'; badge.className='imp-map-state badge badge-success'; }
          else { badge.textContent='sera créé'; badge.className='imp-map-state badge badge-warning'; }
        };
        let timer=null;
        inp.addEventListener('input', () => {
          hid.value=''; mark();
          const q = inp.value.trim(); clearTimeout(timer);
          if(q.length < 2){ hide(); return; }
          timer = setTimeout(async () => {
            try {
              const r = await fetch('index.php?ajax_agent_search=1&q='+encodeURIComponent(q));
              const items = await r.json();
              box.innerHTML = (Array.isArray(items) && items.length ? items.map((a,i) =>
                '<div class="adp-item" data-i="'+i+'"><strong>'+esc(a.name)+'</strong>'
                + '<br><span class="muted" style="font-size:.75rem;">'+esc([a.service_name, a.email].filter(Boolean).join(' · ') || 'Aucun service')+'</span></div>').join('')
                : '<div class="adp-item" style="color:var(--text3);">Aucun résultat — sera créé</div>');
              box.style.display='block';
              [...box.querySelectorAll('.adp-item[data-i]')].forEach(el => el.addEventListener('mousedown', e => {
                e.preventDefault(); const a = items[+el.dataset.i];
                inp.value = a.name; hid.value = a.id; hide(); mark();
              }));
            } catch(e){ hide(); }
          }, 250);
        });
        inp.addEventListener('blur', () => setTimeout(hide, 150));
      });
      </script>
    </div>
    <?php endif; ?>

    <!-- Bloc import CSV — reprise d'inventaire depuis un export -->
    <div class="card" style="margin-top:1.5rem;">
      <div class="card-header"><i class="bi bi-filetype-csv"></i> Importation CSV</div>
      <form method="post" enctype="multipart/form-data" style="padding:1.5rem;"
            onsubmit="return !document.getElementById('imp-trunc').checked || confirm('Vider TOUTE la base avant l\'import ? Cette opération est irréversible.')">
        <input type="hidden" name="<?=CSRF_TOKEN_NAME?>" value="<?=h($CSRF_TOKEN)?>">
        <input type="hidden" name="_entity" value="import">
        <input type="hidden" name="_action" value="preview">

        <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
          Reprise d'inventaire depuis un export CSV : lignes, cartes SIM, matériels, utilisateurs,
          services, modèles, forfaits et opérateurs sont créés en une passe.
          Les doublons (numéro de ligne, IMEI) sont ignorés, l'import est donc rejouable sans risque de duplicatas.<br>
          Après analyse, une <strong>étape de contrôle des utilisateurs</strong> vous est proposée :
          correspondances avec le référentiel, rapprochements manuels, créations — rien n'est écrit avant votre confirmation.
        </p>

        <div class="form-group form-full">
          <label>Fichier d'inventaire (.csv)</label>
          <input type="file" name="file_data" accept=".csv,text/csv" required
            style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.6rem;color:var(--text);width:100%;">
        </div>
        <p style="color:var(--text3);font-size:.82rem;line-height:1.6;margin:.5rem 0 1.25rem;">
          Séparateur <code style="font-family:var(--font-mono);">;</code>, encodage Windows-1252, 10 Mo maximum.
          Les lignes situées avant l'en-tête <code style="font-family:var(--font-mono);">LIGNE</code> sont ignorées.<br>
          <strong>Colonnes attendues :</strong> [0] Ligne, [2] Nom, [3] Prénom, [4] Notes, [5] CF Facturation,
          [6] Service, [7] Options, [9] Date activation, [10] IMEI, [11] Modèle, [12] Forfait, [13] ICCID,
          [14] PIN, [15] PUK, [16] Opérateur (optionnel).
        </p>
        <p style="margin:0 0 1.25rem;">
          <a href="?page=import_template" class="btn btn-secondary btn-sm">
            <i class="bi bi-download"></i> Télécharger le modèle CSV
          </a>
          <span style="color:var(--text3);font-size:.82rem;margin-left:.5rem;">En-tête au bon format + deux lignes d'exemple (à remplacer par vos données).</span>
        </p>

        <!-- Purge préalable : destructif, double confirmation exigée -->
        <div style="background:var(--danger-dim);border:1px solid var(--danger);border-radius:var(--radius-sm);padding:1rem;margin-bottom:1.25rem;font-size:.85rem;">
          <label style="display:flex;align-items:flex-start;gap:.6rem;cursor:pointer;">
            <input type="checkbox" name="truncate" value="1" id="imp-trunc"
              style="width:15px;height:15px;accent-color:var(--danger);flex-shrink:0;margin-top:3px;"
              onchange="document.getElementById('imp-purge-confirm').style.display=this.checked?'block':'none'">
            <span>
              <strong style="color:var(--danger);"><i class="bi bi-exclamation-triangle-fill"></i> Vider toute la base avant l'import</strong>
              <span style="color:var(--text2);display:block;margin-top:.3rem;">
                Lignes, matériels, utilisateurs, bons signés, historique, demandes de téléphone et paramètres
                (SMTP, logo, URL) sont supprimés définitivement. Les comptes d'administration sont conservés.
                Une sauvegarde de sécurité est créée automatiquement avant la purge.
              </span>
            </span>
          </label>
          <div id="imp-purge-confirm" style="display:none;margin-top:.75rem;">
            <label style="font-size:.82rem;font-weight:600;color:var(--danger);">Tapez <strong>PURGER</strong> pour confirmer :</label>
            <input type="text" name="confirm_purge" placeholder="PURGER" autocomplete="off"
              style="margin-top:.35rem;font-family:var(--font-mono);">
          </div>
        </div>

        <div style="padding-top:1rem;border-top:1px solid var(--border);">
          <button type="submit" class="btn-primary" style="display:inline-flex;align-items:center;gap:6px;"><i class="bi bi-search"></i> Analyser le fichier</button>
        </div>
      </form>
    </div>

    <!-- Bloc import depuis SFR — contrôle du référentiel contre l'état de parc -->
    <div class="card" style="margin-top:1.5rem;">
      <div class="card-header"><i class="bi bi-broadcast"></i> Import depuis SFR — état de parc</div>
      <form method="post" enctype="multipart/form-data" style="padding:1.5rem;">
        <input type="hidden" name="<?=CSRF_TOKEN_NAME?>" value="<?=h($CSRF_TOKEN)?>">
        <input type="hidden" name="_entity" value="parc">
        <input type="hidden" name="_action" value="preview">

        <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
          Déposez l'export « <strong>État de parc</strong> » de l'espace client SFR Business (fichier <code>EdP_…​.xlsx</code>).
          Il sert d'abord de <strong>contrôle</strong> : l'écran suivant compare ligne par ligne l'état réel chez l'opérateur
          avec le référentiel SimCity — titulaires, forfaits, statuts, comptes de facturation, cartes SIM et terminaux.<br>
          <strong>Rien n'est écrit sans votre validation</strong>, et vous choisissez alors poste par poste ce qui est mis à jour.
          Vous pouvez aussi ne rien appliquer et n'utiliser que le rapport.
        </p>

        <div class="form-group form-full">
          <label>Export de parc (.xlsx)</label>
          <input type="file" name="file_data" accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" required
            style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.6rem;color:var(--text);width:100%;">
        </div>
        <p style="color:var(--text3);font-size:.82rem;line-height:1.6;margin:.5rem 0 1.25rem;">
          15 Mo maximum. Les colonnes sont reconnues par leur en-tête, l'ordre du portail peut donc changer sans casser la lecture.
          <br>Les <strong>codes SIM (PIN 1/2, PUK 1/2)</strong> sont repris si vous cochez le poste correspondant à l'étape de contrôle.
          Ils sont alors stockés en clair, comme ceux saisis à la main ou importés par CSV : restreignez l'accès à la base et aux
          sauvegardes SQL en conséquence. Le RIO n'est pas dans ce fichier (le portail y renvoie vers un export dédié).
        </p>
        <p style="margin:0 0 1.25rem;font-size:.85rem;">
          <a href="https://www.sfrbusiness.fr/espace-client/portail/#/facturation-et-paiement/societe/multiple"
             target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:6px;">
            <i class="bi bi-box-arrow-up-right"></i> Ouvrir l'espace client SFR Business</a>
        </p>
        <p class="muted" style="margin:-.6rem 0 1.25rem;font-size:.83rem;"><i class="bi bi-arrow-right-circle"></i>
          Cet écran contrôle ce que l'opérateur a <strong>en parc</strong>. Pour contrôler ce qui est <strong>payé</strong>,
          voir <a href="?page=invoices&tab=reconcile">Facturation / Contrôle → Rapprochement des noms</a>.</p>

        <div style="padding-top:1rem;border-top:1px solid var(--border);">
          <button type="submit" class="btn-primary" style="display:inline-flex;align-items:center;gap:6px;"><i class="bi bi-search"></i> Analyser et contrôler</button>
        </div>
      </form>
    </div>

    <?php
    // ── Contrôle de l'export de parc SFR ─────────────────────────
    // Un export analysé attend une décision : on affiche le rapport de
    // comparaison, et l'opérateur choisit quels postes appliquer.
    $pendParc = $_SESSION['parc_pending'] ?? null;
    if ($pendParc && !is_file($pendParc['file'])) { unset($_SESSION['parc_pending']); $pendParc = null; }
    $parcCmp = null;
    if ($pendParc) {
        try {
            $parsed  = simcity_parc_parse($pendParc['file']);
            $parcCmp = simcity_parc_compare($pdo, $parsed['records']);
        } catch (Throwable $e) {
            $parcCmp = null;
            flash('error', "Lecture de l'export impossible : " . h($e->getMessage()));
        }
    }
    ?>
    <?php if($pendParc && $parcCmp): ?>
    <div class="card" style="margin-top:1.5rem;border:1px solid var(--primary);" id="parc-review">
      <div class="card-header"><i class="bi bi-clipboard-check"></i> Contrôle de l'état de parc — <?=h($pendParc['name'])?></div>
      <div style="padding:1.5rem;">
        <?=$parcControlReport($parcCmp, 'export SFR', 'pissue', 'parc-review')?>
        <?php $c = $parcCmp['counts']; ?>

        <form method="post" onsubmit="return confirm('Appliquer les postes cochés au référentiel SimCity ?')">
          <input type="hidden" name="<?=CSRF_TOKEN_NAME?>" value="<?=h($CSRF_TOKEN)?>">
          <input type="hidden" name="_entity" value="parc">
          <input type="hidden" name="_action" value="run">
          <input type="hidden" name="pend_sha1" value="<?=h($pendParc['sha1'] ?? '')?>">
          <h4 style="font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:var(--text2);margin-bottom:.6rem;">
            <i class="bi bi-sliders"></i> Que voulez-vous mettre à jour ?</h4>
          <p class="muted" style="font-size:.82rem;margin-bottom:.9rem;">
            Ne cochez que ce que vous voulez laisser l'export écraser. Les titulaires ne sont jamais modifiés automatiquement :
            un nom qui diffère se corrige à la main, sur la fiche de la ligne ou chez l'opérateur.</p>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:.6rem;margin-bottom:1.25rem;">
            <label style="display:flex;gap:.5rem;align-items:flex-start;font-size:.85rem;cursor:pointer;">
              <input type="checkbox" name="apply_billing" value="1" style="margin-top:3px;">
              <span><strong>Comptes de facturation</strong> <span class="badge badge-muted" style="font-size:.66rem;"><?=$c['billing']?> écart(s)</span>
              <span class="muted" style="display:block;">Rattache chaque ligne à son compte, et crée les comptes absents du référentiel.</span></span></label>
            <label style="display:flex;gap:.5rem;align-items:flex-start;font-size:.85rem;cursor:pointer;">
              <input type="checkbox" name="apply_plan" value="1" style="margin-top:3px;">
              <span><strong>Forfaits</strong> <span class="badge badge-muted" style="font-size:.66rem;"><?=$c['plan']?> écart(s)</span>
              <span class="muted" style="display:block;">Aligne le forfait sur celui de l'opérateur, et crée les forfaits inconnus.</span></span></label>
            <label style="display:flex;gap:.5rem;align-items:flex-start;font-size:.85rem;cursor:pointer;">
              <input type="checkbox" name="apply_status" value="1" style="margin-top:3px;">
              <span><strong>Statuts</strong> <span class="badge badge-muted" style="font-size:.66rem;"><?=$c['status']?> écart(s)</span>
              <span class="muted" style="display:block;">Actif / Suspendue. Les lignes en stock ne sont pas touchées.</span></span></label>
            <label style="display:flex;gap:.5rem;align-items:flex-start;font-size:.85rem;cursor:pointer;">
              <input type="checkbox" name="apply_iccid" value="1" style="margin-top:3px;">
              <span><strong>Cartes SIM</strong> <span class="badge badge-muted" style="font-size:.66rem;"><?=$c['iccid']?> écart(s)</span>
              <span class="muted" style="display:block;">Complète l'ICCID <em>uniquement</em> si le champ est vide dans SimCity.</span></span></label>
            <label style="display:flex;gap:.5rem;align-items:flex-start;font-size:.85rem;cursor:pointer;">
              <input type="checkbox" name="apply_codes" value="1" style="margin-top:3px;">
              <span><strong>Codes SIM (PIN, PUK, RIO)</strong> <span class="badge badge-muted" style="font-size:.66rem;"><?=$c['codes']?> écart(s)</span>
              <span class="muted" style="display:block;">PIN 1/2, PUK 1/2 tels que l'opérateur les publie. Ils sont stockés en clair :
              l'accès à la base et aux sauvegardes SQL doit être restreint en conséquence.</span></span></label>
            <label style="display:flex;gap:.5rem;align-items:flex-start;font-size:.85rem;cursor:pointer;">
              <input type="checkbox" name="apply_create" value="1" style="margin-top:3px;">
              <span><strong>Créer les lignes inconnues</strong> <span class="badge badge-muted" style="font-size:.66rem;"><?=$c['unknown']?></span>
              <span class="muted" style="display:block;">Créées en stock, sans utilisateur : l'affectation reste manuelle.</span></span></label>
          </div>
          <div style="display:flex;gap:.75rem;flex-wrap:wrap;padding-top:1rem;border-top:1px solid var(--border);">
            <button type="submit" class="btn-primary" style="display:inline-flex;align-items:center;gap:6px;"><i class="bi bi-check-lg"></i> Appliquer les postes cochés</button>
            <button type="submit" name="_action" value="cancel" class="btn-secondary" formnovalidate style="display:inline-flex;align-items:center;gap:6px;"><i class="bi bi-x-lg"></i> Fermer sans rien modifier</button>
          </div>
        </form>
      </div>
    </div>
    <?php endif; ?>

    <!-- Bloc vidage des données de test — conserve paramètres, circuits et comptes -->
    <div class="card" style="margin-top:1.5rem;">
      <div class="card-header"><i class="bi bi-trash3"></i> Vider les données (tests)</div>
      <form method="post" style="padding:1.5rem;"
            onsubmit="return confirm('Vider toutes les données (utilisateurs, lignes, matériels, bons, demandes, historiques, factures opérateur) ? Une sauvegarde de sécurité sera créée avant. Les paramètres, circuits de validation et comptes admin sont conservés.')">
        <?=csrf_field()?>
        <input type="hidden" name="_entity" value="wipe_data">
        <input type="hidden" name="_action" value="run">
        <p style="color:var(--text2);font-size:.88rem;margin-bottom:1rem;line-height:1.6;">
          Repartez d'une base propre après une phase de tests : supprime les <strong>utilisateurs (agents), lignes & SIM,
          matériels, bons et signatures, demandes de téléphone, pièces jointes et historiques</strong> — les numéros
          (bons, demandes) repartent de zéro.<br>
          Les <strong>factures opérateur</strong> sont comprises, PDF archivés inclus : elles décrivent le parc qu'on
          efface, et le module Facturation analyserait sinon des numéros qui n'existent plus.<br>
          <strong>Sont toujours conservés :</strong> les paramètres (SMTP, LDAP, textes du formulaire, valideurs par
          défaut…), les circuits de validation et les comptes admin. Une <strong>sauvegarde de sécurité</strong> est
          créée automatiquement avant l'opération.
        </p>
        <label style="display:flex;align-items:center;gap:.5rem;cursor:pointer;font-size:.88rem;margin-bottom:1rem;">
          <input type="checkbox" name="keep_refs" value="1" checked style="width:15px;height:15px;accent-color:var(--primary);flex-shrink:0;">
          Conserver aussi les référentiels (services, modèles, forfaits, opérateurs, comptes de facturation)
        </label>
        <div style="display:flex;gap:.75rem;flex-wrap:wrap;align-items:center;padding-top:1rem;border-top:1px solid var(--border);">
          <input type="text" name="confirm_wipe" placeholder="Tapez VIDER pour confirmer" autocomplete="off" required
            style="max-width:240px;font-family:var(--font-mono);">
          <button type="submit" class="btn-secondary" style="color:var(--danger);border-color:rgba(220,38,38,.35);display:inline-flex;align-items:center;gap:6px;"><i class="bi bi-trash3"></i> Vider les données</button>
        </div>
      </form>
    </div>

    <!-- Journal des opérations d'administration.
         Les imports (CSV, SFR, factures), suppressions de factures, purges et
         effacements de secrets appelaient déjà logHistory() : ces entrées
         portent un entity_type sans fiche (« admin », « invoice », « import »)
         et n'étaient donc affichées nulle part. La trace existait sans être
         consultable ; ce bloc la rend lisible. -->
    <?php
      $opsLog = $pdo->query("SELECT h.action_date, h.entity_type, h.action_desc, h.author
              FROM history_logs h WHERE h.entity_type IN ('admin','invoice','import')
              ORDER BY h.action_date DESC LIMIT 50")->fetchAll();
      $opsMeta = ['admin' => ['Administration', 'bi-shield-lock', 'badge-muted'],
                  'invoice' => ['Facturation',  'bi-receipt',     'badge-info'],
                  'import'  => ['Import',       'bi-box-arrow-in-down', 'badge-warning']];
    ?>
    <div class="card" style="margin-top:1.5rem;">
      <div class="card-header"><i class="bi bi-journal-text"></i> Journal des opérations d'administration
        <span class="muted" style="font-weight:400;text-transform:none;letter-spacing:0;font-size:.78rem;margin-left:.5rem;">50 dernières</span></div>
      <?php if(!$opsLog): ?>
      <p class="muted" style="padding:1.5rem;margin:0;"><i class="bi bi-info-circle"></i>
        Aucune opération enregistrée pour l'instant. Les imports, les suppressions de factures, les purges
        et les effacements de secrets sont tracés ici.</p>
      <?php else: ?>
      <div style="max-height:340px;overflow-y:auto;">
        <table class="data-table" style="font-size:.84rem;">
          <thead><tr><th style="width:140px;">Date</th><th style="width:130px;">Domaine</th><th>Opération</th><th style="width:140px;">Auteur</th></tr></thead>
          <tbody>
          <?php foreach($opsLog as $ol): [$ollbl, $olico, $olcls] = $opsMeta[$ol['entity_type']] ?? $opsMeta['admin']; ?>
          <tr>
            <td class="muted" style="white-space:nowrap;"><?=date('d/m/Y H:i', strtotime($ol['action_date']))?></td>
            <td><span class="badge <?=$olcls?>" style="font-size:.68rem;"><i class="bi <?=$olico?>"></i> <?=$ollbl?></span></td>
            <td><?=h($ol['action_desc'])?></td>
            <td class="muted"><?=h($ol['author'] ?: '—')?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <p class="muted" style="padding:.75rem 1.4rem 1rem;margin:0;font-size:.79rem;"><i class="bi bi-shield-check"></i>
        Les valeurs sensibles ne sont jamais consignées : un effacement de secret note la clé, un import de codes SIM
        note un décompte. Ce journal est vidé avec les données (il vit dans <code>history_logs</code>).</p>
      <?php endif; ?>
    </div>

    <!-- Bloc reset — super-admin uniquement -->
    <div class="card" style="margin-top:1.5rem;border-color:var(--danger);border-width:1px;">
      <div class="card-header" style="color:var(--danger);">⚠️ Zone dangereuse</div>
      <div style="padding:1.5rem;">
        <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
          Supprime <strong>toutes les données</strong> (lignes, matériels, agents, historique, comptes…) et recrée la structure vide.<br>
          <strong style="color:var(--danger);">Cette action est irréversible. Effectuez une sauvegarde MySQL avant de continuer.</strong>
        </p>
        <button type="button" class="btn-primary" style="background:var(--danger);box-shadow:none;"
          onclick="openModal('modal-db-reset')">🗑️ Réinitialiser la base de données</button>
      </div>
    </div>

    <!-- Modal confirmation reset DB -->
    <div class="modal-overlay" id="modal-db-reset">
      <div class="modal" style="border:1px solid var(--danger);">
        <div class="modal-header" style="border-color:var(--danger);">
          <h3 style="color:var(--danger);"><i class="bi bi-exclamation-triangle"></i> Confirmer la réinitialisation</h3>
          <button type="button" class="modal-close" onclick="closeModal('modal-db-reset')"><i class="bi bi-x-lg"></i></button>
        </div>
        <form method="post" style="padding:1.5rem;">
          <input type="hidden" name="_entity" value="db_reset">
          <input type="hidden" name="_action" value="reset">
          <p style="color:var(--text2);font-size:.9rem;margin-bottom:1.5rem;line-height:1.6;">
            Toutes les données seront supprimées et la structure recréée immédiatement (vide).
            Les comptes d'administration sont conservés et une sauvegarde de sécurité est créée avant la purge.<br><br>
            <strong>Tapez <span style="color:var(--danger);font-family:var(--font-mono);">SUPPRIMER</span> pour confirmer :</strong>
          </p>
          <div class="form-group form-full">
            <input type="text" name="confirm_word" autocomplete="off" placeholder="SUPPRIMER" required
              style="font-family:var(--font-mono);border-color:var(--danger);">
          </div>
          <div class="modal-footer">
            <button type="button" class="btn-secondary" onclick="closeModal('modal-db-reset')">Annuler</button>
            <button type="submit" class="btn-primary" style="background:var(--danger);box-shadow:none;">Supprimer toutes les données</button>
          </div>
        </form>
      </div>
    </div>
    <?php endif; ?>

    <?php else: ?>
    <?php if($tab === 'agents'): ?>
    <div style="display:flex;gap:10px;margin-bottom:1rem;border-bottom:2px solid var(--border);flex-wrap:wrap;">
      <a href="?page=refs&tab=agents" class="tab-btn <?=!$agentArchived?'active':''?>"><i class="bi bi-people"></i> Actifs <span class="badge badge-muted" style="font-size:.68rem;"><?=(int)($agCounts['actifs'] ?? 0)?></span></a>
      <a href="?page=refs&tab=agents&arch=1" class="tab-btn <?=$agentArchived?'active':''?>"><i class="bi bi-archive"></i> Partis <span class="badge badge-muted" style="font-size:.68rem;"><?=(int)($agCounts['partis'] ?? 0)?></span></a>
    </div>
    <?php endif; ?>
    <!-- Recherche compacte et bouton d'ajout sur la même ligne : le bandeau
         d'action pleine largeur au-dessus des onglets coûtait une ligne pour rien. -->
    <div class="search-bar-wrap search-bar-inline">
      <div class="search-bar"><span class="search-bar-icon"><i class="bi bi-search"></i></span><input type="text" placeholder="Filtrer..." oninput="tableSearch(this,'tbody-refs','count')"></div>
      <div class="search-count" id="count"></div>
      <?php if($tab !== 'settings'): ?>
      <button class="btn-primary" style="white-space:nowrap;" onclick="openModal('modal-add-<?=$ent?>')"><i class="bi bi-plus-lg"></i> <?=h($addLabels[$tab] ?? 'Ajouter')?></button>
      <?php endif; ?>
    </div>

    <div class="card" style="overflow-x:auto;">
      <table class="data-table">
        <thead><tr><?php foreach($cols as $name => $k) echo "<th>$name</th>"; ?><?php if($tab==='admins'): ?><th>Signature (visa DSI)</th><?php endif; ?><th>Actions</th></tr></thead>
        <tbody id="tbody-refs">
        <?php if(empty($data)): ?><tr><td colspan="<?=count($cols)+($tab==='admins'?2:1)?>" class="empty-cell">Aucune donnée</td></tr><?php endif; ?>
        <?php foreach($data as $row): ?>
        <tr style="<?=($tab==='agents' && !empty($row['archived'])) ? 'opacity:.65;' : ''?>">
          <?php foreach($cols as $name => $k): ?>
            <td>
              <?php if($name==='Nom' && $tab==='agents' && !empty($row['archived'])): ?>
                <?=h($row[$k])?> <span class="badge badge-danger" style="font-size:.65rem;"><i class="bi bi-archive"></i> Parti</span>
              <?php elseif($name==='Identifiant' && $tab==='admins'): ?>
                <?=h($row[$k])?>
                <?php if(($row['auth_source'] ?? 'local') === 'ldap'): ?>
                  <span class="badge badge-info" style="font-size:.65rem;margin-left:4px;" title="Compte Active Directory : authentification via LDAP, pas de mot de passe local"><i class="bi bi-globe2"></i> AD</span>
                <?php endif; ?>
                <?php if(empty($row['active'])): ?>
                  <span class="badge badge-warning" style="font-size:.65rem;margin-left:4px;"><i class="bi bi-lock"></i> Désactivé</span>
                <?php elseif($row['id'] === (int)$_SESSION['user_id']): ?>
                  <span class="badge badge-info" style="font-size:.65rem;margin-left:4px;"><i class="bi bi-person"></i> Vous</span>
                <?php endif; ?>
              <?php elseif($tab==='agents' && $k==='service_name' && trim((string)$row[$k]) !== ''): ?>
                <?php // Service cliquable : filtre la liste sur ce service. ?>
                <span class="cell-link" data-refs-filter="<?=h($row[$k])?>" title="Filtrer sur ce service"><?=h($row[$k])?></span>
              <?php elseif($tab==='services' && ($k==='nb_lines' || $k==='nb_devices') && (int)$row[$k] > 0): ?>
                <?php // Compteur cliquable : ouvre la liste pré-filtrée sur le nom du service (via le paramètre q). ?>
                <a href="?page=<?=$k==='nb_lines'?'lines':'devices'?>&tab=active&q=<?=urlencode($row['name'])?>" title="Voir les <?=$k==='nb_lines'?'lignes':'matériels'?> de ce service" style="font-weight:600;"><?=h($row[$k])?></a>
              <?php else: ?>
                <?=h($row[$k])?>
              <?php endif; ?>
            </td>
          <?php endforeach; ?>
          <?php if($tab === 'admins'): ?>
          <td>
            <?php if(!empty($sigMap[$row['id']])): ?>
              <img src="<?=h($sigMap[$row['id']])?>" alt="Signature" style="max-height:34px;max-width:110px;object-fit:contain;background:#fff;border:1px solid var(--border);border-radius:4px;padding:2px;vertical-align:middle;">
            <?php else: ?>
              <span style="color:var(--text3);font-size:.82rem;">— aucune —</span>
            <?php endif; ?>
          </td>
          <?php endif; ?>
          <td class="actions">
            <?php if($tab === 'agents'): ?>
                <button class="btn-icon" title="Voir la Fiche Utilisateur" style="color:var(--primary)" onclick="viewAgent(<?=$row['id']?>, '<?=h($row['first_name'].' '.$row['last_name'])?>')"><i class="bi bi-eye"></i></button>
                <?php if(empty($row['archived'])): ?>
                    <button class="btn-icon btn-edit" title="Modifier" onclick='openEditModal(<?=json_encode($row, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>,"<?=$ent?>")'><i class="bi bi-pencil"></i></button>
                    <form method="post" style="display:inline" onsubmit="return confirm('Archiver cet agent ? Son téléphone retournera en stock et sa ligne sera libérée automatiquement.')">
                        <input type="hidden" name="_entity" value="agent">
                        <input type="hidden" name="_action" value="archive">
                        <input type="hidden" name="_id" value="<?=$row['id']?>">
                        <button type="submit" class="btn-icon btn-del" title="Archiver (Départ de la société)"><i class="bi bi-archive"></i></button>
                    </form>
                <?php else: ?>
                    <form method="post" style="display:inline" onsubmit="return confirm('Restaurer cet agent dans la liste active ?')">
                        <input type="hidden" name="_entity" value="agent">
                        <input type="hidden" name="_action" value="restore">
                        <input type="hidden" name="_id" value="<?=$row['id']?>">
                        <button type="submit" class="btn-icon" title="Restaurer (Retour dans la société)" style="color:var(--success)"><i class="bi bi-arrow-counterclockwise"></i></button>
                    </form>
                <?php endif; ?>
            <?php elseif($tab === 'admins'): ?>
                <?php
                $isSelf    = ($row['id'] === (int)$_SESSION['user_id']);
                $isActive  = !empty($row['active']);
                ?>
                <?php if(!$isSelf): ?>
                    <span style="margin-right:4px">
                    <?php if($isActive): ?>
                        <form method="post" style="display:inline" onsubmit="return confirm('Désactiver le compte « <?=h($row['username']) ?> » ? Il ne pourra plus se connecter.')">
                            <input type="hidden" name="_entity" value="admin">
                            <input type="hidden" name="_action" value="disable">
                            <input type="hidden" name="_id" value="<?=$row['id']?>">
                            <button type="submit" class="btn-icon" title="Désactiver ce compte" style="color:var(--warning)"><i class="bi bi-lock"></i></button>
                        </form>
                    <?php else: ?>
                        <form method="post" style="display:inline" onsubmit="return confirm('Réactiver le compte « <?=h($row['username']) ?> » ?')">
                            <input type="hidden" name="_entity" value="admin">
                            <input type="hidden" name="_action" value="enable">
                            <input type="hidden" name="_id" value="<?=$row['id']?>">
                            <button type="submit" class="btn-icon" title="Réactiver ce compte" style="color:var(--success)"><i class="bi bi-unlock"></i></button>
                        </form>
                    <?php endif; ?>
                    </span>
                <?php endif; ?>
                <?php if($isSelf || !empty($_SESSION['is_admin'])): ?>
                    <button class="btn-icon" title="<?=$isSelf ? 'Ma signature (visa DSI)' : 'Signature (visa DSI) de ce compte'?>" style="color:var(--primary)"
                      onclick='openSigModal(<?=$row['id']?>, <?=json_encode(trim($row['first_name'].' '.$row['last_name']) ?: $row['username'], JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>, <?=json_encode($sigMap[$row['id']] ?? '', JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>)'><i class="bi bi-pencil-square"></i></button>
                <?php endif; ?>
                <button class="btn-icon btn-edit" title="Modifier" onclick='openEditModal(<?=json_encode($row, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>,"<?=$ent?>")'><i class="bi bi-pencil"></i></button>
                <?php if(!$isSelf): ?>
                    <form method="post" style="display:inline" onsubmit="return confirm('Supprimer définitivement le compte « <?=h($row['username']) ?> » ?')">
                        <input type="hidden" name="_entity" value="admin">
                        <input type="hidden" name="_action" value="delete">
                        <input type="hidden" name="_id" value="<?=$row['id']?>">
                        <button type="submit" class="btn-icon btn-del" title="Supprimer ce compte"><i class="bi bi-trash3"></i></button>
                    </form>
                <?php endif; ?>
            <?php else: ?>
            <button class="btn-icon btn-edit" title="Modifier" onclick='openEditModal(<?=json_encode($row, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>,"<?=$ent?>")'><i class="bi bi-pencil"></i></button>
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>

    <?php if($tab === 'admins'): ?>
    <!-- Modal signature (visa DSI) — une signature par compte admin -->
    <div class="modal-overlay" id="modal-signature">
      <div class="modal">
        <div class="modal-header">
          <h3><i class="bi bi-pencil-square"></i> Signature (visa DSI) — <span id="sig-admin-name"></span></h3>
          <button type="button" class="modal-close" onclick="closeModal('modal-signature')"><i class="bi bi-x-lg"></i></button>
        </div>
        <form method="post" id="dsi-sig-form" style="padding:1.5rem;">
          <input type="hidden" name="_entity" value="admin_signature">
          <input type="hidden" name="_action" value="save">
          <input type="hidden" name="_id" id="sig-admin-id">
          <input type="hidden" name="signature_data" id="dsi-sig-data">
          <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
            Cette signature est apposée dans le cadre <strong>« Visa de la DSI »</strong> des bons générés par <strong>ce compte</strong>.
            Elle est copiée dans chaque bon au moment de la génération (un bon déjà émis ne change jamais).
          </p>
          <div id="sig-current" style="display:none;align-items:center;gap:1.5rem;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:1rem;margin-bottom:1.25rem;">
            <img id="sig-current-img" src="" alt="Signature actuelle" style="max-height:70px;max-width:220px;object-fit:contain;background:#fff;border-radius:4px;padding:4px;">
            <button type="submit" name="delete_signature" value="1" class="btn-secondary" style="color:var(--danger);font-size:.82rem;padding:.4rem .9rem;"
              onclick="return confirm('Supprimer cette signature ?')"><i class="bi bi-trash3"></i> Supprimer cette signature</button>
          </div>
          <label style="margin-bottom:.4rem;" id="sig-canvas-label">Dessiner la signature</label>
          <div style="border:2px dashed var(--border2);border-radius:8px;background:#fff;touch-action:none;">
            <canvas id="dsiSigCanvas" height="140" style="display:block;width:100%;border-radius:8px;"></canvas>
          </div>
          <div class="modal-footer" style="margin-top:1rem;">
            <button type="button" class="btn-secondary" onclick="dsiSigClear()"><i class="bi bi-trash3"></i> Effacer le cadre</button>
            <button type="submit" class="btn-primary" id="dsi-sig-save" disabled><i class="bi bi-save"></i> Enregistrer la signature</button>
          </div>
        </form>
      </div>
    </div>
    <script>
    (function(){
      const canvas = document.getElementById('dsiSigCanvas');
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      let drawing = false, hasSig = false;
      function resize() {
        const w = canvas.parentElement.clientWidth || 500;
        canvas.width = w * devicePixelRatio; canvas.height = 140 * devicePixelRatio;
        canvas.style.width = w + 'px'; canvas.style.height = '140px';
        ctx.scale(devicePixelRatio, devicePixelRatio);
        ctx.strokeStyle = '#1e293b'; ctx.lineWidth = 2.2; ctx.lineCap = 'round'; ctx.lineJoin = 'round';
      }
      function pos(e) { const r = canvas.getBoundingClientRect(); const s = e.touches ? e.touches[0] : e; return {x: s.clientX - r.left, y: s.clientY - r.top}; }
      function start(e) { e.preventDefault(); drawing = true; const p = pos(e); ctx.beginPath(); ctx.moveTo(p.x, p.y); }
      function move(e)  { if (!drawing) return; e.preventDefault(); const p = pos(e); ctx.lineTo(p.x, p.y); ctx.stroke(); hasSig = true; document.getElementById('dsi-sig-save').disabled = false; }
      function stop(e)  { e.preventDefault(); drawing = false; }
      window.dsiSigClear = function() { ctx.clearRect(0, 0, canvas.width, canvas.height); hasSig = false; document.getElementById('dsi-sig-save').disabled = true; };
      canvas.addEventListener('mousedown', start); canvas.addEventListener('mousemove', move); canvas.addEventListener('mouseup', stop);
      canvas.addEventListener('touchstart', start, {passive:false}); canvas.addEventListener('touchmove', move, {passive:false}); canvas.addEventListener('touchend', stop, {passive:false});
      window.openSigModal = function(id, name, currentSig) {
        document.getElementById('sig-admin-id').value = id;
        document.getElementById('sig-admin-name').textContent = name;
        const cur = document.getElementById('sig-current');
        cur.style.display = currentSig ? 'flex' : 'none';
        if (currentSig) document.getElementById('sig-current-img').src = currentSig;
        document.getElementById('sig-canvas-label').textContent = currentSig ? 'Remplacer la signature' : 'Dessiner la signature';
        openModal('modal-signature');
        resize();               // le canvas doit être visible pour connaître sa largeur
        window.dsiSigClear();
      };
      document.getElementById('dsi-sig-form').addEventListener('submit', function(e) {
        if (e.submitter && e.submitter.name === 'delete_signature') return;
        if (!hasSig) { e.preventDefault(); alert('Dessinez la signature dans le cadre.'); return; }
        document.getElementById('dsi-sig-data').value = canvas.toDataURL('image/png');
      });
    })();
    </script>
    <?php endif; ?>
    <?php endif; /* end settings tab */ ?>

    <?php foreach(['add'=>'Ajouter', 'edit'=>'Modifier'] as $act => $title): ?>
    <div class="modal-overlay" id="modal-<?=$act?>-<?=$ent?>">
      <div class="modal"><div class="modal-header"><h3><?=$title?></h3><button type="button" class="modal-close" onclick="closeModal('modal-<?=$act?>-<?=$ent?>')"><i class="bi bi-x-lg"></i></button></div>
      <form method="post"><input type="hidden" name="_entity" value="<?=$ent?>"><input type="hidden" name="_action" value="<?=$act?>"><?php if($act==='edit') echo '<input type="hidden" name="_id" id="edit-id-'.$ent.'">'; ?>
      <div class="form-grid">
        <?php if ($ent === 'agent'): $svcs=$pdo->query("SELECT id,name FROM services")->fetchAll(); ?>
            <?php if (ldap_auth_enabled()): ?>
            <div class="form-group form-full" style="position:relative;">
              <label><i class="bi bi-search"></i> Rechercher dans l'annuaire (AD)</label>
              <input type="text" id="<?=$act?>-ad-search" placeholder="Nom ou prénom…" autocomplete="off">
              <div id="<?=$act?>-ad-suggest" class="adp-box"></div>
              <small class="muted" style="font-size:.75rem;">Sélectionnez une personne pour pré-remplir la fiche (modifiable ensuite).</small>
            </div>
            <?php endif; ?>
            <div class="form-group"><label>Nom *</label><input type="text" name="last_name" id="<?=$act?>-last_name" required></div>
            <div class="form-group"><label>Prénom *</label><input type="text" name="first_name" id="<?=$act?>-first_name" required></div>
            <div class="form-group form-full"><label>Fonction</label><input type="text" name="fonction" id="<?=$act?>-fonction" placeholder="ex : Responsable voirie"></div>
            <div class="form-group form-full"><label>Adresse e-mail</label><input type="email" name="email" id="<?=$act?>-email"></div>
            <div class="form-group form-full"><label>Service / Direction</label><div class="qa-row"><select name="service_id" id="<?=$act?>-service_id"><option value="">-- Aucun --</option><?php foreach($svcs as $s): ?><option value="<?=$s['id']?>"><?=h($s['name'])?></option><?php endforeach; ?></select><button type="button" class="btn-quickadd" onclick="quickAddOpen('service','<?=$act?>-service_id')" title="Ajouter un service"><i class="bi bi-plus-lg"></i></button></div></div>
        <?php elseif ($ent === 'service'): ?>
            <div class="form-group"><label>Nom</label><input type="text" name="name" id="<?=$act?>-name" required></div>
            <div class="form-group"><label>Direction</label><input type="text" name="direction" id="<?=$act?>-direction"></div>
            <div class="form-group form-full" style="margin-top:.25rem;padding-top:.75rem;border-top:1px dashed var(--border);"><span class="muted" style="font-size:.78rem;">Valideurs du circuit « Demandes de téléphone » — pré-remplis à chaque demande de ce service.</span></div>
            <div class="form-group"><label>Chef de service (visa)</label><div style="position:relative;"><input type="text" name="chef_name" id="<?=$act?>-chef_name" placeholder="Prénom Nom" autocomplete="off" data-svc-ad="<?=$act?>-chef_email"><div class="adp-box"></div></div></div>
            <div class="form-group"><label>E-mail du chef de service</label><input type="email" name="chef_email" id="<?=$act?>-chef_email" placeholder="chef@collectivite.fr"></div>
            <div class="form-group"><label>D.G.A. de secteur (visa)</label><div style="position:relative;"><input type="text" name="dga_name" id="<?=$act?>-dga_name" placeholder="Prénom Nom" autocomplete="off" data-svc-ad="<?=$act?>-dga_email"><div class="adp-box"></div></div></div>
            <div class="form-group"><label>E-mail du D.G.A.</label><input type="email" name="dga_email" id="<?=$act?>-dga_email" placeholder="dga@collectivite.fr"></div>
            <div class="form-group form-full"><label>Notes</label><textarea name="notes" id="<?=$act?>-notes" rows="2"></textarea></div>
        <?php elseif ($ent === 'model'): ?>
            <div class="form-group"><label>Marque</label><input type="text" name="brand" id="<?=$act?>-brand" required></div>
            <div class="form-group"><label>Modèle</label><input type="text" name="name" id="<?=$act?>-name" required></div>
            <div class="form-group form-full"><label>Catégorie</label><select name="category" id="<?=$act?>-category"><option>Smartphone</option><option>Tablette</option><option>Borne 4G</option></select></div>
        <?php elseif ($ent === 'plan'): ?>
            <div class="form-group form-full"><label>Opérateur *</label>
              <div class="qa-row">
              <select name="operator_id" id="<?=$act?>-operator_id" required>
                <option value="">-- Sélectionner un opérateur --</option>
                <?php foreach(($operators??[]) as $op): ?><option value="<?=$op['id']?>"><?=h($op['name'])?></option><?php endforeach; ?>
              </select>
              <button type="button" class="btn-quickadd" onclick="quickAddOpen('operator','<?=$act?>-operator_id')" title="Ajouter un opérateur"><i class="bi bi-plus-lg"></i></button>
              </div>
            </div>
            <div class="form-group"><label>Nom du Forfait *</label><input type="text" name="name" id="<?=$act?>-name" required></div>
            <div class="form-group"><label>Data Limit</label><input type="text" name="data_limit" id="<?=$act?>-data_limit" placeholder="ex: 50 Go"></div>
            <div class="form-group form-full"><label>Notes</label><textarea name="notes" id="<?=$act?>-notes" rows="2"></textarea></div>
        <?php elseif ($ent === 'operator'): ?>
            <div class="form-group form-full"><label>Nom de l'opérateur *</label><input type="text" name="name" id="<?=$act?>-name" required placeholder="ex: SFR, Orange, Bouygues..."></div>
            <div class="form-group form-full"><label>Site web</label><input type="url" name="website" id="<?=$act?>-website" placeholder="https://..."></div>
            <div class="form-group form-full"><label>Notes</label><textarea name="notes" id="<?=$act?>-notes" rows="2"></textarea></div>
        <?php elseif ($ent === 'billing'): ?>
            <div class="form-group"><label>N° Compte Facturation</label><input type="text" name="account_number" id="<?=$act?>-account_number" required></div>
            <div class="form-group"><label>Nom / Entité</label><input type="text" name="name" id="<?=$act?>-name"></div>
            <div class="form-group form-full"><label>Notes</label><textarea name="notes" id="<?=$act?>-notes" rows="2"></textarea></div>
        <?php elseif ($ent === 'admin'): ?>
            <div class="form-group"><label>Nom *</label><input type="text" name="last_name" id="<?=$act?>-last_name"></div>
            <div class="form-group"><label>Prénom *</label><input type="text" name="first_name" id="<?=$act?>-first_name"></div>
            <div class="form-group form-full"><label>Adresse e-mail</label><input type="email" name="email" id="<?=$act?>-email"></div>
            <div class="form-group"><label>Identifiant (login) *</label><input type="text" name="username" id="<?=$act?>-username" required></div>
            <div class="form-group"><label>Mot de passe <?=$act==='edit'?'(Laissez vide pour ne pas modifier)':'*'?></label><input type="password" name="password" id="<?=$act?>-password" <?=$act==='add'?'required':''?>></div>
            <?php if(!empty($_SESSION['is_admin'])): ?>
            <div class="form-group form-full">
              <label style="display:flex;align-items:center;gap:.6rem;cursor:pointer;">
                <input type="checkbox" name="is_admin" id="<?=$act?>-is_admin" value="1" style="width:15px;height:15px;accent-color:var(--danger);">
                <span>Super-administrateur <small style="color:var(--text3);">(accès à la réinitialisation de la base de données)</small></span>
              </label>
            </div>
            <?php endif; ?>
        <?php endif; ?>
      </div>
      <div class="modal-footer"><button type="button" class="btn-secondary" onclick="closeModal('modal-<?=$act?>-<?=$ent?>')">Annuler</button><button type="submit" class="btn-primary">Enregistrer</button></div>
      </form></div>
    </div>
    <?php endforeach;
}

// ==================================================================
// VUE : HISTORIQUE DES BONS DE REMISE
// ==================================================================
elseif ($page === 'history') {
    $bons = $pdo->query("
        SELECT b.*,
               DATE_FORMAT(b.created_at, '%d/%m/%Y %H:%i') as created_fmt,
               DATE_FORMAT(b.signed_at, '%d/%m/%Y %H:%i') as signed_fmt,
               CONCAT(IFNULL(a.first_name,''), ' ', IFNULL(a.last_name,'')) as agent_name,
               IFNULL(svc.name, '—') as service_name,
               a.archived as agent_archived
        FROM bons b
        LEFT JOIN agents a ON b.agent_id = a.id
        LEFT JOIN services svc ON a.service_id = svc.id
        ORDER BY b.created_at DESC, b.id DESC
    ")->fetchAll();

    // Numéros de ligne actuels par agent (repli pour les bons migrés sans snapshot)
    $currentPhones = [];
    foreach ($pdo->query("SELECT agent_id, GROUP_CONCAT(DISTINCT phone_number ORDER BY id SEPARATOR ' / ') as pn FROM mobile_lines WHERE agent_id IS NOT NULL AND archived=0 AND sim_vierge=0 GROUP BY agent_id")->fetchAll() as $r) {
        $currentPhones[(int)$r['agent_id']] = $r['pn'];
    }

    // Numéros de ligne du bon : depuis son snapshot figé, sinon dotation actuelle
    $phonesOf = function($b) use ($currentPhones) {
        if ($b && $b['items']) {
            $items = json_decode($b['items'], true);
            $nums = [];
            foreach (($items['lines'] ?? []) as $l) if (!empty($l['phone_number'])) $nums[] = formatPhone($l['phone_number']);
            return implode(' / ', $nums);
        }
        $pn = $b ? ($currentPhones[(int)$b['agent_id']] ?? '') : '';
        return $pn ? implode(' / ', array_map('formatPhone', explode(' / ', $pn))) : '';
    };

    // ── Appariement structurel : chaque restitution référence sa remise (parent_id) ──
    $childByParent = [];
    foreach ($bons as $b) {
        if ($b['type'] === 'restitution' && $b['parent_id']) $childByParent[$b['parent_id']][] = $b;
    }

    // Remises actives par agent + identifiants d'équipements d'un bon ('d3', 'l5'…),
    // pour repérer les cycles entièrement repris par un bon plus récent
    $remisesByAgent = [];
    foreach ($bons as $b) {
        if ($b['type'] === 'remise' && $b['status'] !== 'cancelled') $remisesByAgent[(int)$b['agent_id']][] = $b;
    }
    $bonItemIds = function($b) {
        if (empty($b['items'])) return null;
        $it = json_decode($b['items'], true);
        $ids = [];
        foreach (($it['devices'] ?? []) as $d) if (!empty($d['device_id'])) $ids[] = 'd' . $d['device_id'];
        foreach (($it['lines'] ?? []) as $l) if (!empty($l['line_id'])) $ids[] = 'l' . $l['line_id'];
        return $ids;
    };

    $pairs = [];
    foreach ($bons as $b) {
        // Les bons annulés restent consultables depuis la fiche agent, pas ici
        if ($b['status'] === 'cancelled') continue;
        if ($b['type'] === 'remise') {
            $child = null;
            foreach (($childByParent[$b['id']] ?? []) as $c) { if ($c['status'] !== 'cancelled') { $child = $c; break; } }
            // Cycle sans restitution : ses équipements sont-ils tous couverts par un bon plus récent ?
            $supersededBy = null;
            if (!$child) {
                $myIds = $bonItemIds($b);
                foreach (($remisesByAgent[(int)$b['agent_id']] ?? []) as $other) {
                    if ($other['id'] == $b['id']) continue;
                    if (strtotime($other['created_at']) < strtotime($b['created_at'])) continue;
                    if (strtotime($other['created_at']) == strtotime($b['created_at']) && $other['id'] < $b['id']) continue;
                    $oIds = $bonItemIds($other);
                    if ($myIds !== null && $oIds !== null && !array_diff($myIds, $oIds)) { $supersededBy = $other['numero']; break; }
                }
            }
            $pairs[] = ['remise' => $b, 'restitution' => $child, 'superseded_by' => $supersededBy,
                        'agent_name' => $b['agent_name'], 'agent_id' => $b['agent_id'],
                        'service_name' => $b['service_name'], 'agent_archived' => $b['agent_archived'],
                        'phone_numbers' => $phonesOf($b)];
        } elseif (!$b['parent_id']) {
            // Restitution orpheline (migration ancien système)
            $pairs[] = ['remise' => null, 'restitution' => $b,
                        'agent_name' => $b['agent_name'], 'agent_id' => $b['agent_id'],
                        'service_name' => $b['service_name'], 'agent_archived' => $b['agent_archived'],
                        'phone_numbers' => $phonesOf($b)];
        }
    }

    // ── État du CYCLE (remise + restitution), pas du bon isolé ──
    // Un bon de restitution signé clôt le cycle : plus rien n'est attendu.
    // Tant qu'une signature manque, le cycle réclame une action — c'est ce qui
    // commande l'ordre d'affichage, du plus urgent au plus classé.
    $cycleMeta = [
        'waiting'    => ['⏳', 'Remise à signer',        'badge-info',    '#2563eb'],
        'returning'  => ['✍️', 'Restitution à signer',   'badge-warning', '#d97706'],
        'active'     => ['📱', 'En dotation',            'badge-success', '#059669'],
        'closed'     => ['✅', 'Terminé — restitué',     'badge-muted',   '#64748b'],
        'superseded' => ['♻️', 'Clos — cycle remplacé',  'badge-muted',   '#94a3b8'],
    ];
    foreach ($pairs as &$p) {
        $rem = $p['remise']; $res = $p['restitution'];
        if     ($res && $res['status'] === 'signed')   $p['state'] = 'closed';
        elseif ($res)                                  $p['state'] = 'returning';
        elseif (!empty($p['superseded_by']))           $p['state'] = 'superseded';
        elseif ($rem && $rem['status'] === 'signed')   $p['state'] = 'active';
        else                                           $p['state'] = 'waiting';
    }
    unset($p);
    $cycleOrder = array_flip(array_keys($cycleMeta));
    usort($pairs, function($x, $y) use ($cycleOrder) {
        $c = $cycleOrder[$x['state']] <=> $cycleOrder[$y['state']];
        if ($c) return $c;
        $dx = strtotime(($x['remise'] ?: $x['restitution'])['created_at']);
        $dy = strtotime(($y['remise'] ?: $y['restitution'])['created_at']);
        return $dy <=> $dx;                                  // le plus récent d'abord
    });
    $cycleCounts = array_fill_keys(array_keys($cycleMeta), 0);
    foreach ($pairs as $p) $cycleCounts[$p['state']]++;

    $now = time();
    function bonStatusHtml(array $b, int $now): string {
        if ($b['status'] === 'signed')    return '<span style="background:rgba(5,150,105,.12);color:var(--success);font-size:.72rem;font-weight:700;padding:.15rem .5rem;border-radius:999px;white-space:nowrap;">✅ Signé</span>';
        if ($b['status'] === 'cancelled') return '<span style="background:rgba(148,163,184,.1);color:#94a3b8;font-size:.72rem;font-weight:700;padding:.15rem .5rem;border-radius:999px;white-space:nowrap;">🚫 Annulé</span>';
        if ($b['expires_at'] && strtotime($b['expires_at']) < $now) return '<span style="background:rgba(217,119,6,.12);color:var(--warning);font-size:.72rem;font-weight:700;padding:.15rem .5rem;border-radius:999px;white-space:nowrap;">⏰ Expiré</span>';
        return '<span style="background:rgba(37,99,235,.12);color:var(--info);font-size:.72rem;font-weight:700;padding:.15rem .5rem;border-radius:999px;white-space:nowrap;">⏳ En attente</span>';
    }
    ?>

    <?php if($pairs): ?>
    <div style="display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem;">
      <button type="button" class="hist-chip badge badge-info" data-state="" onclick="historyState('')" style="border:0;cursor:pointer;font-family:inherit;">Tout (<?=count($pairs)?>)</button>
      <?php foreach($cycleMeta as $k => [$ico, $lbl]): if(!$cycleCounts[$k]) continue; ?>
      <button type="button" class="hist-chip badge badge-muted" data-state="<?=$k?>" onclick="historyState('<?=$k?>')" style="border:0;cursor:pointer;font-family:inherit;"><?=$ico?> <?=h($lbl)?> (<?=$cycleCounts[$k]?>)</button>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <div class="search-bar-wrap">
      <div class="search-bar"><span class="search-bar-icon"><i class="bi bi-search"></i></span>
        <input type="text" id="history-search" placeholder="Rechercher agent, service, numéro de ligne..." oninput="historySearch(this.value)">
      </div>
      <div class="search-count" id="count-history"></div>
    </div>

    <div id="history-pairs-container">
    <?php if(empty($pairs)): ?>
      <div class="card" style="padding:2rem;text-align:center;color:var(--text3);">Aucun bon de remise généré.</div>
    <?php endif; ?>
    <?php foreach($pairs as $pi => $pair):
        [$stIco, $stLabel, $stCls, $borderColor] = $cycleMeta[$pair['state']];
        $agentName = trim($pair['agent_name']);
    ?>
    <div class="history-pair-card" data-state="<?=h($pair['state'])?>" data-search="<?=h(strtolower($agentName.' '.$pair['service_name'].' '.($pair['phone_numbers']??'').' '.($pair['remise']['dsi_name']??'').' '.($pair['restitution']['dsi_name']??'').' '.($pair['remise']['numero']??'').' '.($pair['restitution']['numero']??'')))?>" style="background:var(--card);border:1px solid var(--border);border-left:4px solid <?=$borderColor?>;border-radius:var(--radius);margin-bottom:1rem;overflow:hidden;">
      <!-- En-tête : Agent + Ligne -->
      <div style="padding:.75rem 1.25rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem;background:var(--card2);">
        <div style="display:flex;align-items:center;gap:.75rem;">
          <?php if($pair['agent_id']): ?>
            <strong style="cursor:pointer;font-size:.95rem;" onclick="viewAgent(<?=$pair['agent_id']?>, '<?=h($agentName)?>')" title="Voir la fiche">👤 <?=h($agentName)?></strong>
          <?php else: ?>
            <strong style="color:var(--text3);">👤 Agent supprimé</strong>
          <?php endif; ?>
          <span style="font-size:.8rem; color:var(--text3);"><i class="bi bi-building"></i> <?=h($pair['service_name'])?></span>
          <?php if($pair['agent_archived']): ?><span style="background:rgba(245,158,11,.15);color:var(--warning);font-size:.68rem;font-weight:600;padding:.1rem .4rem;border-radius:999px;"><i class="bi bi-archive"></i> Parti</span><?php endif; ?>
          <span class="badge <?=$stCls?>" style="font-size:.7rem;"><?=$stIco?> <?=h($stLabel)?></span>
        </div>
        <?php if($pair['phone_numbers']): ?>
        <div style="font-family:var(--font-mono);font-size:.85rem;color:var(--primary);font-weight:600;">
          📞 <?=h(implode(' / ', array_map('formatPhone', explode(' / ', $pair['phone_numbers']))))?></div>
        <?php endif; ?>
        <?php $printBon = $pair['remise'] ?: $pair['restitution']; if($printBon): ?>
        <a href="index.php?page=pdf_bon&bon_id=<?=$printBon['id']?>" target="_blank" class="btn-icon" title="Voir / imprimer ce bon" style="text-decoration:none;font-size:.8rem;"><i class="bi bi-printer"></i></a>
        <?php endif; ?>
      </div>
      <!-- Bons : deux colonnes côte à côte -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:0;">
        <?php foreach(['remise'=>['📥','Bon de Remise','#059669','rgba(5,150,105,.06)'],'restitution'=>['📤','Bon de Restitution','#d97706','rgba(217,119,6,.06)']] as $btype=>[$icon,$label,$color,$bg]):
            $b = $pair[$btype];
        ?>
        <div style="padding:1rem 1.25rem;border-right:<?=$btype==='remise'?'1px solid var(--border)':'none'?>;background:<?=$b?$bg:'var(--bg3)'?>;">
          <?php if($b): ?>
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem;gap:.5rem;flex-wrap:wrap;">
              <span style="font-weight:700;color:<?=$color?>;font-size:.9rem;"><?=$icon?> <?=$label?> <span style="font-weight:600;font-size:.75rem;"><?=h($b['numero']?:'')?></span></span>
              <span style="display:flex;align-items:center;gap:.4rem;"><?=bonStatusHtml($b,$now)?>
              <a href="index.php?page=pdf_bon&bon_id=<?=$b['id']?>" target="_blank" title="Voir / imprimer ce bon" style="text-decoration:none;font-size:.85rem;">🖨️</a></span>
            </div>
            <div style="font-size:.78rem;color:var(--text3);margin-bottom:.3rem;">
              Créé le <strong style="color:var(--text2);"><?=h($b['created_fmt'])?></strong>
              <?php if($b['dsi_name']||$b['created_by']): ?>— par <?=h($b['dsi_name']?:$b['created_by'])?><?php endif; ?>
            </div>
            <?php if($b['status'] === 'signed' && $b['signed_fmt']): ?>
            <div style="font-size:.78rem;color:<?=$color?>;margin-top:.3rem;">
              ✍️ <?=h($b['signer_name'])?> <span style="color:var(--text3);">— le <?=h($b['signed_fmt'])?></span>
            </div>
            <?php endif; ?>
          <?php elseif($btype==='restitution' && !empty($pair['superseded_by'])): ?>
            <div style="color:var(--text3);font-size:.82rem;font-style:italic;">♻️ Cycle remplacé<br><span style="font-size:.75rem;">Équipements repris dans le bon <strong><?=h($pair['superseded_by'])?></strong> — pas de restitution attendue ici</span></div>
          <?php else: ?>
            <div style="color:var(--text3);font-size:.82rem;font-style:italic;"><?=$icon?> <?=$label?><br><span style="font-size:.75rem;"><?=$btype==='restitution'?'Pas encore générée — matériel toujours en dotation':'Non généré'?></span></div>
          <?php endif; ?>
        </div>
        <?php endforeach; ?>
      </div>
    </div>
    <?php endforeach; ?>
    </div>

    <script>
    // Recherche texte et filtre d'état se cumulent : un seul point d'application.
    let histQuery = '', histState = '';
    function historySearch(q) { histQuery = q.toLowerCase().trim(); historyApply(); }
    function historyState(s) {
      histState = s;
      document.querySelectorAll('.hist-chip').forEach(c => {
        const on = c.dataset.state === s;
        c.classList.toggle('badge-info', on);
        c.classList.toggle('badge-muted', !on);
      });
      historyApply();
    }
    function historyApply() {
      let visible = 0;
      document.querySelectorAll('.history-pair-card').forEach(c => {
        const match = (!histQuery || c.dataset.search.includes(histQuery))
                   && (!histState || c.dataset.state === histState);
        c.style.display = match ? '' : 'none';
        if (match) visible++;
      });
      const el = document.getElementById('count-history');
      if (el) el.textContent = (histQuery || histState) ? visible + ' résultat(s)' : '';
    }
    </script>
    <?php
}

// ==================================================================
// VUE : DEMANDES DE TÉLÉPHONE (liste + détail / qualification)
// ==================================================================
elseif ($page === 'requests') {
    $viewId = (int)($_GET['view'] ?? 0);

    if ($viewId) {
        // ── DÉTAIL D'UNE DEMANDE ─────────────────────────────────
        $rq = $pdo->prepare("SELECT * FROM requests WHERE id=?"); $rq->execute([$viewId]);
        $req = $rq->fetch();
        if (!$req) {
            echo '<div class="card" style="padding:2rem;text-align:center;color:var(--text3);">Demande introuvable. <a href="?page=requests" style="color:var(--primary);">← Retour à la liste</a></div>';
        } else {
            $ss = $pdo->prepare("SELECT * FROM request_steps WHERE request_id=? ORDER BY ordre");
            $ss->execute([$viewId]);
            $steps = $ss->fetchAll();
            [$stLbl, $stCls] = requestStatusInfo($req['status']);
            $linkedAgent = $req['agent_id'] ? $pdo->query("SELECT a.*, s.name as service_name FROM agents a LEFT JOIN services s ON a.service_id=s.id WHERE a.id=" . (int)$req['agent_id'])->fetch() : null;
            $bonRow = $req['bon_id'] ? $pdo->query("SELECT * FROM bons WHERE id=" . (int)$req['bon_id'])->fetch() : null;
            $smtpConfigured = trim(smtpSetting($pdo, 'smtp_host', '')) !== '';
            // Circuit proposé (statut « à qualifier ») : valideurs du service + paramètres
            $draftSteps = ($req['status'] === 'a_qualifier') ? requestDefaultSteps($pdo, $req['service_id']) : [];
            // Circuits enregistrés (Paramètres → Demandes) proposés à la qualification
            $savedCircuits = ($req['status'] === 'a_qualifier')
                ? $pdo->query("SELECT id, name, steps FROM request_circuits ORDER BY name")->fetchAll() : [];
            // Agent remplacé : rapprochement avec le référentiel (e-mail prioritaire,
            // sinon nom exact unique) pour afficher sa dotation actuelle.
            $replacedAgent = $req['replace_agent']
                ? requestMatchAgent($pdo, $req['replaced_agent_email'] ?? '', $req['replaced_agent_name'] ?? '') : null;
    ?>
    <div style="margin-bottom:1rem;"><a href="?page=requests" style="color:var(--primary);font-size:.85rem;">← Toutes les demandes</a></div>

    <div class="card">
      <div class="card-header" style="display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;">
        <span class="card-title">📱 Demande <?=h($req['numero'])?> — <?=h($req['agent_name'])?></span>
        <span style="display:flex;gap:.5rem;align-items:center;">
          <span class="badge <?=$stCls?>"><?=h($stLbl)?></span>
          <a href="?page=pdf_demande&id=<?=$viewId?>" target="_blank" class="btn-icon" title="Récapitulatif imprimable (pièce justificative)" style="text-decoration:none;"><i class="bi bi-printer"></i></a>
        </span>
      </div>
      <div style="padding:.7rem 1.5rem;background:var(--bg3);border-bottom:1px solid var(--border);font-size:.88rem;display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;">
        🙋 <strong>Demandeur :</strong> <?=h($req['requester_name'] ?: '—')?>
        <?php if ($req['requester_email']): ?>
        — <a href="mailto:<?=h($req['requester_email'])?>" style="color:var(--primary);"><?=h($req['requester_email'])?></a>
        <?php endif; ?>
      </div>
      <div style="padding:1.5rem;display:flex;gap:2rem;flex-wrap:wrap;">
        <div style="flex:1;min-width:300px;">
          <h4 style="color:var(--primary);margin-bottom:10px;border-bottom:1px solid var(--border);padding-bottom:5px;">📋 La demande</h4>
          <table class="data-table" style="font-size:.85rem;">
            <tr><td style="color:var(--text2);width:190px;">Type</td><td><?=h(requestTypeLabel($req['type']))?></td></tr>
            <tr><td style="color:var(--text2);">Bénéficiaire</td><td><strong><?=h($req['agent_name'])?></strong><?=$req['agent_fonction'] ? ' — ' . h($req['agent_fonction']) : ''?></td></tr>
            <tr><td style="color:var(--text2);">E-mail bénéficiaire</td><td><?=h($req['agent_email'] ?: '—')?></td></tr>
            <tr><td style="color:var(--text2);">Demandeur</td><td><?=h($req['requester_name'] ?: '—')?><?=$req['requester_email'] ? ' — ' . h($req['requester_email']) : ''?></td></tr>
            <tr><td style="color:var(--text2);">Service</td><td><?=h($req['service_name'] ?: '—')?></td></tr>
            <tr><td style="color:var(--text2);">Remplacement d'agent</td><td><?=$req['replace_agent'] ? 'Oui' . ($req['replaced_agent_name'] ? ' — ' . h($req['replaced_agent_name']) : '') : 'Non'?></td></tr>
            <tr><td style="color:var(--text2);">Remplacement de téléphone</td><td><?=$req['replace_device'] ? 'Oui — <strong>' . h($req['replace_motif'] ?: 'motif non précisé') . '</strong>' : 'Non'?></td></tr>
            <tr><td style="color:var(--text2);">Déposée le</td><td><?=date('d/m/Y à H:i', strtotime($req['created_at']))?></td></tr>
            <?php if ($req['refusal_reason']): ?><tr><td style="color:var(--text2);">Motif de clôture</td><td style="color:var(--danger);"><?=h($req['refusal_reason'])?></td></tr><?php endif; ?>
          </table>
          <div style="margin-top:.75rem;background:var(--bg3);border-radius:var(--radius-sm);padding:.85rem 1rem;">
            <div style="font-size:.72rem;font-weight:700;color:var(--text2);text-transform:uppercase;margin-bottom:.3rem;">Motivation du besoin</div>
            <div style="font-size:.88rem;white-space:pre-line;"><?=h($req['motivation'])?></div>
          </div>
        </div>

        <div style="flex:1;min-width:300px;">
          <h4 style="color:var(--primary);margin-bottom:10px;border-bottom:1px solid var(--border);padding-bottom:5px;">👤 Agent au référentiel & équipement actuel</h4>
          <?php if ($linkedAgent): ?>
          <div style="background:var(--bg3);border-radius:var(--radius-sm);padding:.85rem 1rem;margin-bottom:.75rem;">
            <strong class="cell-link" onclick="viewAgent(<?=(int)$linkedAgent['id']?>, '<?=h(addslashes(trim($linkedAgent['first_name'] . ' ' . $linkedAgent['last_name'])))?>')" title="Ouvrir la fiche"><?=h(trim($linkedAgent['first_name'] . ' ' . $linkedAgent['last_name']))?></strong>
            <span class="muted">— <?=h($linkedAgent['service_name'] ?: 'Aucun service')?></span>
            <div style="margin-top:.6rem;"><?=requestEquipmentHtml($pdo, (int)$linkedAgent['id'])?></div>
          </div>
          <?php else: ?>
          <div style="background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.25);border-radius:var(--radius-sm);padding:.85rem 1rem;margin-bottom:.75rem;font-size:.85rem;color:var(--text2);">
            ⚠️ Demande non rattachée au référentiel — l'équipement actuel n'est pas visible des valideurs. Liez l'agent (ou créez-le d'abord dans « Utilisateurs »).
          </div>
          <?php endif; ?>
          <?php if ($req['replace_agent']): ?>
          <div style="background:var(--bg3);border-radius:var(--radius-sm);padding:.85rem 1rem;margin-bottom:.75rem;">
            <div style="font-size:.72rem;font-weight:700;color:var(--text2);text-transform:uppercase;margin-bottom:.35rem;">♻️ Agent remplacé</div>
            <?php if ($replacedAgent): ?>
            <strong class="cell-link" onclick="viewAgent(<?=(int)$replacedAgent['id']?>, '<?=h(addslashes(trim($replacedAgent['first_name'] . ' ' . $replacedAgent['last_name'])))?>')" title="Ouvrir la fiche"><?=h(trim($replacedAgent['first_name'] . ' ' . $replacedAgent['last_name']))?></strong>
            <?php if ($req['replaced_agent_email']): ?><span class="muted" style="font-size:.8rem;"> — <?=h($req['replaced_agent_email'])?></span><?php endif; ?>
            <div style="margin-top:.6rem;"><?=requestEquipmentHtml($pdo, (int)$replacedAgent['id'])?></div>
            <div class="muted" style="font-size:.75rem;margin-top:.5rem;">💡 Matériel / lignes à récupérer ou transférer au nouvel agent.</div>
            <?php else: ?>
            <span><?=h($req['replaced_agent_name'] ?: 'Nom non précisé')?></span>
            <div class="muted" style="font-size:.78rem;margin-top:.4rem;">Agent introuvable au référentiel — aucune dotation connue dans l'outil.</div>
            <?php endif; ?>
          </div>
          <?php endif; ?>
          <?php if (in_array($req['status'], ['a_qualifier', 'en_validation', 'validee'], true)): ?>
          <form method="post" action="index.php" style="display:flex;gap:.5rem;align-items:center;">
            <?=csrf_field()?>
            <input type="hidden" name="_entity" value="request">
            <input type="hidden" name="_action" value="link_agent">
            <input type="hidden" name="request_id" value="<?=$viewId?>">
            <div style="position:relative;flex:1;">
              <input type="text" id="reqlink-agent_search" placeholder="🔎 Rechercher l'agent au référentiel (vide = délier)" autocomplete="off" value="<?=$linkedAgent ? h(trim($linkedAgent['last_name'] . ' ' . $linkedAgent['first_name'])) : ''?>">
              <input type="hidden" name="agent_id" id="reqlink-agent_id" value="<?=$req['agent_id'] ? (int)$req['agent_id'] : ''?>">
              <div class="adp-box" id="reqlink-agent_suggest"></div>
            </div>
            <button type="submit" class="btn-secondary" style="white-space:nowrap;">🔗 Lier</button>
          </form>
          <?php endif; ?>
        </div>
      </div>
    </div>

    <!-- Circuit de validation -->
    <div class="card">
      <div class="card-header"><span class="card-title">🖊️ Circuit de validation</span></div>
      <div style="padding:1.5rem;">
      <?php if ($req['status'] === 'a_qualifier'): ?>
        <p class="muted" style="margin-bottom:1rem;">Circuit pré-rempli depuis le service (« <?=h($req['service_name'] ?: '—')?> ») et les paramètres. Ajustez librement (libellé, valideur, e-mail, ordre), puis lancez : chaque valideur recevra un lien personnel, l'un après l'autre. <a href="?page=refs&tab=services" style="color:var(--primary);">Compléter les valideurs des services →</a></p>
        <?php if ($savedCircuits): ?>
        <div style="display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;margin-bottom:1rem;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.6rem .9rem;">
          <span style="font-size:.82rem;color:var(--text2);white-space:nowrap;">📚 Circuit enregistré :</span>
          <select id="circuit-preset" style="flex:1;min-width:220px;">
            <option value="">— Circuit par défaut (service + paramètres) —</option>
            <?php foreach ($savedCircuits as $c): $cSteps = json_decode($c['steps'] ?: '[]', true) ?: []; ?>
            <option value="<?=(int)$c['id']?>"><?=h($c['name'])?> (<?=count($cSteps)?> étape<?=count($cSteps) > 1 ? 's' : ''?>)</option>
            <?php endforeach; ?>
          </select>
          <span class="muted" style="font-size:.75rem;">Remplace les étapes ci-dessous (modifiables ensuite). <a href="?page=refs&tab=settings&sub=requests" style="color:var(--primary);">Gérer les circuits →</a></span>
        </div>
        <?php endif; ?>
        <form method="post" action="index.php">
          <?=csrf_field()?>
          <input type="hidden" name="_entity" value="request">
          <input type="hidden" name="_action" value="launch">
          <input type="hidden" name="request_id" value="<?=$viewId?>">
          <table class="data-table" id="circuit-table" style="font-size:.85rem;">
            <thead><tr><th style="width:30px;"></th><th>Visa (libellé)</th><th>Valideur</th><th>E-mail</th><th style="width:40px;"></th></tr></thead>
            <tbody>
            <?php foreach ($draftSteps as $i => $ds): ?>
            <tr>
              <td class="drag-cell" title="Glisser pour réordonner"><i class="bi bi-grip-vertical"></i></td>
              <td><input type="text" name="step_label[]" value="<?=h($ds['label'])?>" placeholder="ex : Direction du service"></td>
              <td style="position:relative;"><input type="text" class="circuit-name" name="step_name[]" value="<?=h($ds['name'])?>" placeholder="Prénom Nom" autocomplete="off"><div class="adp-box circuit-suggest"></div></td>
              <td><input type="email" class="circuit-email" name="step_email[]" value="<?=h($ds['email'])?>" placeholder="valideur@collectivite.fr" <?=$ds['email'] === '' ? 'style="border-color:rgba(245,158,11,.6);"' : ''?>></td>
              <td><button type="button" class="btn-icon btn-del" title="Retirer cette étape" onclick="this.closest('tr').remove()"><i class="bi bi-x-lg"></i></button></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
          <div style="display:flex;gap:.75rem;margin-top:1rem;flex-wrap:wrap;align-items:center;">
            <button type="button" class="btn-secondary" onclick="circuitAddRow()">➕ Ajouter une étape</button>
            <button type="button" class="btn-secondary" onclick="circuitPrependDirection()" title="Insère un visa « Direction du service » en première position — utile quand la demande n'émane pas de la direction du service">⬆️ Direction du service en tête</button>
            <button type="submit" class="btn-primary" <?=$smtpConfigured ? '' : 'title="SMTP non configuré : le lien devra être transmis manuellement"'?>
              onclick="return confirm('Lancer le circuit de validation ? Le premier valideur recevra immédiatement le lien par e-mail.')">🚀 Lancer le circuit</button>
            <?php if (!$smtpConfigured): ?><span style="color:var(--warning);font-size:.8rem;">⚠️ SMTP non configuré — <a href="?page=refs&tab=settings&sub=email" style="color:var(--primary);">Paramètres → Envoi d'e-mails</a></span><?php endif; ?>
          </div>
        </form>
        <script>
        function circuitAddRow(step, atTop) {
          const tb = document.querySelector('#circuit-table tbody');
          const tr = document.createElement('tr');
          tr.innerHTML = '<td class="drag-cell" title="Glisser pour réordonner"><i class="bi bi-grip-vertical"></i></td>'
            + '<td><input type="text" name="step_label[]" placeholder="Libellé du visa"></td>'
            + '<td style="position:relative;"><input type="text" class="circuit-name" name="step_name[]" placeholder="Prénom Nom" autocomplete="off"><div class="adp-box circuit-suggest"></div></td>'
            + '<td><input type="email" class="circuit-email" name="step_email[]" placeholder="valideur@collectivite.fr"></td>'
            + '<td><button type="button" class="btn-icon btn-del" onclick="this.closest(\'tr\').remove()"><i class="bi bi-x-lg"></i></button></td>';
          if (step) {
            tr.querySelector('[name="step_label[]"]').value = step.label || '';
            tr.querySelector('[name="step_name[]"]').value  = step.name  || '';
            tr.querySelector('[name="step_email[]"]').value = step.email || '';
          }
          if (atTop && tb.firstChild) tb.insertBefore(tr, tb.firstChild); else tb.appendChild(tr);
        }
        // ── Visa « Direction du service » en tête de circuit ──
        // Les circuits enregistrés sont génériques (DSI, DGA, DGS…) : quand la
        // demande n'émane pas de la direction du service, celle-ci doit viser en
        // premier. Le bouton insère l'étape en position 1, pré-remplie avec le
        // chef du service demandeur s'il est renseigné au référentiel, sinon
        // vide (à compléter via l'annuaire).
        const DIR_STEP = <?=json_encode(($draftSteps[0] ?? null) && ($draftSteps[0]['label'] ?? '') === 'Direction du service'
            ? ['label' => $draftSteps[0]['label'], 'name' => $draftSteps[0]['name'], 'email' => $draftSteps[0]['email']]
            : ['label' => 'Direction du service', 'name' => '', 'email' => ''], JSON_UNESCAPED_UNICODE)?>;
        function circuitPrependDirection() {
          circuitAddRow(DIR_STEP, true);
          const first = document.querySelector('#circuit-table tbody tr .circuit-name');
          if (first && !first.value) first.focus();
        }
        // ── Circuits enregistrés (Paramètres) : recharge le tableau d'étapes ──
        (function(){
          const sel = document.getElementById('circuit-preset');
          if (!sel) return;
          const CIRCUITS = <?=json_encode(array_column(array_map(fn($c) => ['id' => (int)$c['id'], 'steps' => json_decode($c['steps'] ?: '[]', true) ?: []], $savedCircuits), null, 'id'), JSON_UNESCAPED_UNICODE)?>;
          const DEFAULT_STEPS = <?=json_encode(array_map(fn($ds) => ['label' => $ds['label'], 'name' => $ds['name'], 'email' => $ds['email']], $draftSteps), JSON_UNESCAPED_UNICODE)?>;
          sel.addEventListener('change', function(){
            const steps = this.value ? ((CIRCUITS[this.value] || {}).steps || []) : DEFAULT_STEPS;
            document.querySelector('#circuit-table tbody').innerHTML = '';
            steps.forEach(s => circuitAddRow(s));
            if (!steps.length) circuitAddRow();
          });
        })();
        // ── Autocomplétion annuaire (AD + référentiel) sur le champ Valideur ──
        // Délégation : couvre les lignes initiales ET celles ajoutées ensuite.
        // Sélectionner une personne remplit le valideur ET son e-mail sur la ligne.
        (function(){
          const table = document.getElementById('circuit-table');
          if (!table) return;
          const esc = s => { const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; };
          table.addEventListener('input', e => {
            const inp = e.target;
            if (!inp.classList || !inp.classList.contains('circuit-name')) return;
            const box = inp.parentElement.querySelector('.circuit-suggest');
            const q = inp.value.trim();
            clearTimeout(inp._t);
            if (q.length < 2) { box.style.display='none'; box.innerHTML=''; return; }
            inp._t = setTimeout(async () => {
              try {
                const r = await fetch('index.php?ajax_request_lookup=1&q='+encodeURIComponent(q));
                const items = await r.json();
                if (!Array.isArray(items) || !items.length) { box.style.display='none'; box.innerHTML=''; return; }
                box.innerHTML = items.map((p,i) =>
                  '<div class="adp-item" data-i="'+i+'"><strong>'+esc(p.name)+'</strong>'
                  + (p.source==='ad' ? ' <span style="color:var(--info);font-size:.7rem;">AD</span>' : '')
                  + '<br><span class="muted" style="font-size:.75rem;">'+esc([p.fonction,p.email].filter(Boolean).join(' · '))+'</span></div>').join('');
                box.style.display='block';
                const emailInp = inp.closest('tr').querySelector('.circuit-email');
                [...box.querySelectorAll('.adp-item')].forEach(el => el.addEventListener('mousedown', ev => {
                  ev.preventDefault(); const p = items[+el.dataset.i];
                  inp.value = p.name || '';
                  if (emailInp && p.email) { emailInp.value = p.email; emailInp.style.borderColor=''; }
                  box.style.display='none'; box.innerHTML='';
                }));
              } catch(err) { box.style.display='none'; }
            }, 250);
          });
          table.addEventListener('focusout', e => {
            if (e.target.classList && e.target.classList.contains('circuit-name')) {
              const box = e.target.parentElement.querySelector('.circuit-suggest');
              setTimeout(() => { if (box) { box.style.display='none'; } }, 150);
            }
          });
        })();
        </script>
      <?php else: ?>
        <table class="data-table" style="font-size:.86rem;">
          <thead><tr><th style="width:30px;">#</th><th>Visa</th><th>Valideur</th><th>Décision</th><th>Avis motivé</th><th>Notifié</th></tr></thead>
          <tbody>
          <?php foreach ($steps as $s):
              $isCur = ($req['status'] === 'en_validation' && (int)$req['current_step'] === (int)$s['ordre']);
              if ($s['decision'] === 'approuve')   $dec = '<span class="badge badge-success">✅ Favorable</span><br><span class="muted" style="font-size:.72rem;">' . date('d/m/Y H:i', strtotime($s['decided_at'])) . '</span>';
              elseif ($s['decision'] === 'refuse') $dec = '<span class="badge badge-danger">⛔ Défavorable</span><br><span class="muted" style="font-size:.72rem;">' . date('d/m/Y H:i', strtotime($s['decided_at'])) . '</span>';
              elseif ($isCur)                      $dec = '<span class="badge badge-info">⏳ En attente</span>';
              elseif (in_array($req['status'], ['refusee', 'annulee'], true)) $dec = '<span class="badge badge-muted">Sans objet</span>';
              else                                 $dec = '<span class="badge badge-muted">À venir</span>';
          ?>
          <tr style="<?=$isCur ? 'background:var(--primary-dim);' : ''?>">
            <td class="muted"><?=(int)$s['ordre']?></td>
            <td><strong><?=h($s['label'])?></strong></td>
            <td><?=h($s['validator_name'] ?: '—')?><br><span class="muted" style="font-size:.75rem;"><?=h($s['validator_email'])?></span></td>
            <td><?=$dec?></td>
            <td style="max-width:280px;"><?=$s['avis'] ? '« ' . h($s['avis']) . ' »' : '<span class="muted">—</span>'?></td>
            <td class="muted" style="font-size:.75rem;">
              <?=$s['notified_at'] ? '📧 ' . date('d/m H:i', strtotime($s['notified_at'])) : '—'?>
              <?php if($isCur && !$s['notified_at']): ?><br><span style="color:var(--warning);" title="L'e-mail n'a pas pu être envoyé (voir le journal de la demande). Transmettez le lien de visa manuellement.">⚠️ e-mail non parti</span><?php endif; ?>
              <?=$s['reminded_at'] ? '<br>🔔 ' . date('d/m H:i', strtotime($s['reminded_at'])) : ''?>
              <?php if ($isCur): ?><br><button type="button" class="btn-icon" style="font-size:.78rem;color:var(--primary);padding:0;" title="Copier le lien de visa" onclick="copySignLink(this, '<?=h(baseUrl($pdo) . '?page=valider&token=' . $s['token'])?>')">🔗 lien</button><?php endif; ?>
            </td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      <?php endif; ?>
      </div>
    </div>

    <!-- Actions -->
    <div class="card">
      <div class="card-header"><span class="card-title">⚡ Actions</span></div>
      <div style="padding:1.5rem;display:flex;gap:.75rem;flex-wrap:wrap;align-items:flex-start;">
        <?php if ($req['status'] === 'en_validation'): ?>
        <form method="post" action="index.php" style="display:inline;">
          <?=csrf_field()?>
          <input type="hidden" name="_entity" value="request"><input type="hidden" name="_action" value="resend"><input type="hidden" name="request_id" value="<?=$viewId?>">
          <button type="submit" class="btn-secondary">📧 Relancer le valideur en cours</button>
        </form>
        <?php endif; ?>

        <?php if ($req['status'] === 'validee'): ?>
        <?php if ($linkedAgent): ?>
        <button type="button" class="btn-primary" onclick="viewAgent(<?=(int)$linkedAgent['id']?>, '<?=h(addslashes(trim($linkedAgent['first_name'] . ' ' . $linkedAgent['last_name'])))?>')">👤 Attribuer matériel / ligne (fiche agent)</button>
        <form method="post" action="index.php" style="display:inline;" target="_blank">
          <?=csrf_field()?>
          <input type="hidden" name="_entity" value="request"><input type="hidden" name="_action" value="generate_bon"><input type="hidden" name="request_id" value="<?=$viewId?>">
          <button type="submit" class="btn-secondary">📄 Générer le bon de remise lié</button>
        </form>
        <?php else: ?>
        <span style="color:var(--warning);font-size:.85rem;align-self:center;">⚠️ Liez d'abord la demande à un agent du référentiel pour attribuer et générer le bon.</span>
        <?php endif; ?>
        <form method="post" action="index.php" style="display:inline;" onsubmit="return confirm('Marquer la demande comme livrée ? (Utile si la remise s\'est faite sans bon électronique.)')">
          <?=csrf_field()?>
          <input type="hidden" name="_entity" value="request"><input type="hidden" name="_action" value="deliver"><input type="hidden" name="request_id" value="<?=$viewId?>">
          <button type="submit" class="btn-secondary">📦 Marquer livrée</button>
        </form>
        <?php endif; ?>

        <?php if ($bonRow): ?>
        <a href="?page=pdf_bon&bon_id=<?=(int)$bonRow['id']?>" target="_blank" class="btn-secondary" style="text-decoration:none;display:inline-flex;align-items:center;gap:5px;">🖨️ Bon <?=h($bonRow['numero'])?> — <?=$bonRow['status'] === 'signed' ? '✅ signé' : ($bonRow['status'] === 'pending' ? '⏳ en attente de signature' : '🚫 annulé')?></a>
        <?php endif; ?>

        <?php if (in_array($req['status'], ['a_qualifier', 'en_validation'], true)): ?>
        <details style="flex-basis:100%;background:rgba(220,38,38,.04);border:1px solid rgba(220,38,38,.2);border-radius:8px;padding:.6rem .9rem;">
          <summary style="cursor:pointer;font-size:.85rem;color:var(--danger);font-weight:600;">⛔ Refuser ou annuler la demande</summary>
          <div style="display:flex;gap:.75rem;flex-wrap:wrap;margin-top:.75rem;align-items:center;">
            <form method="post" action="index.php" style="display:flex;gap:.5rem;flex:1;min-width:280px;" onsubmit="return confirm('Refuser définitivement cette demande ? Le demandeur sera informé par e-mail.')">
              <?=csrf_field()?>
              <input type="hidden" name="_entity" value="request"><input type="hidden" name="_action" value="refuse"><input type="hidden" name="request_id" value="<?=$viewId?>">
              <input type="text" name="reason" required placeholder="Motif du refus (transmis au demandeur)" style="flex:1;">
              <button type="submit" class="btn-secondary" style="color:var(--danger);border-color:rgba(220,38,38,.3);">⛔ Refuser</button>
            </form>
            <form method="post" action="index.php" style="display:inline;" onsubmit="return confirm('Annuler cette demande (sans notification au demandeur) ?')">
              <?=csrf_field()?>
              <input type="hidden" name="_entity" value="request"><input type="hidden" name="_action" value="cancel"><input type="hidden" name="request_id" value="<?=$viewId?>">
              <button type="submit" class="btn-secondary">🚫 Annuler sans notifier</button>
            </form>
          </div>
        </details>
        <?php endif; ?>
      </div>
    </div>

    <!-- Historique de la demande -->
    <div class="card">
      <div class="card-header"><span class="card-title">🕐 Historique</span></div>
      <div style="padding:1rem 1.5rem;">
        <?php $hist = fetchEntityHistory($pdo, 'request', $viewId); if (!$hist): ?>
        <div class="muted">Aucun événement.</div>
        <?php else: foreach ($hist as $hrow): ?>
        <div style="display:flex;gap:1rem;padding:.4rem 0;border-bottom:1px solid var(--border);font-size:.83rem;">
          <span class="muted" style="white-space:nowrap;"><?=h($hrow['dt'])?></span>
          <span style="flex:1;"><?=h($hrow['action_desc'])?></span>
          <span class="muted"><?=h($hrow['author'])?></span>
        </div>
        <?php endforeach; endif; ?>
      </div>
    </div>
    <?php
        }
    } else {
        // ── LISTE DES DEMANDES ───────────────────────────────────
        // Deux onglets : « En cours » (à traiter) et « Terminées »
        // (livrées / refusées / annulées).
        $reqClosed      = ($_GET['closed'] ?? '') === '1';
        $openStatuses   = "'a_qualifier','en_validation','validee'";
        $closedStatuses = "'livree','refusee','annulee'";
        $reqCounts = $pdo->query("SELECT
                SUM(status IN ($openStatuses))   AS en_cours,
                SUM(status IN ($closedStatuses)) AS terminees
            FROM requests")->fetch();
        $reqs = $pdo->query("SELECT r.*,
                DATE_FORMAT(r.created_at, '%d/%m/%Y') as created_fmt,
                (SELECT label FROM request_steps s WHERE s.request_id=r.id AND s.ordre=r.current_step LIMIT 1) as current_label,
                (SELECT COUNT(*) FROM request_steps s WHERE s.request_id=r.id) as nb_steps,
                (SELECT COUNT(*) FROM request_steps s WHERE s.request_id=r.id AND s.decision='approuve') as nb_ok
            FROM requests r
            WHERE r.status IN (" . ($reqClosed ? $closedStatuses : $openStatuses) . ")
            ORDER BY FIELD(r.status, 'a_qualifier', 'en_validation', 'validee', 'livree', 'refusee', 'annulee'), r.created_at DESC")->fetchAll();
        $publicUrl = baseUrl($pdo) . '?page=demande';
    ?>
    <div class="page-header" style="justify-content:space-between;flex-wrap:wrap;gap:.75rem;">
      <div style="display:flex;align-items:center;gap:.6rem;font-size:.85rem;color:var(--text2);">
        <span>🔗 Formulaire public :</span>
        <code style="font-family:var(--font-mono);font-size:.78rem;background:var(--bg3);padding:.3rem .6rem;border-radius:6px;word-break:break-all;"><?=h($publicUrl)?></code>
        <button type="button" class="btn-secondary" style="font-size:.78rem;padding:.35rem .8rem;" onclick="copySignLink(this, '<?=h($publicUrl)?>')">📋 Copier</button>
      </div>
      <a href="<?=h($publicUrl)?>" target="_blank" class="btn-primary" style="text-decoration:none;">➕ Nouvelle demande (formulaire)</a>
    </div>

    <div style="display:flex;gap:10px;margin-bottom:1rem;border-bottom:2px solid var(--border);flex-wrap:wrap;">
      <a href="?page=requests" class="tab-btn <?=!$reqClosed?'active':''?>"><i class="bi bi-hourglass-split"></i> En cours <span class="badge badge-muted" style="font-size:.68rem;"><?=(int)($reqCounts['en_cours'] ?? 0)?></span></a>
      <a href="?page=requests&closed=1" class="tab-btn <?=$reqClosed?'active':''?>"><i class="bi bi-check2-circle"></i> Terminées <span class="badge badge-muted" style="font-size:.68rem;"><?=(int)($reqCounts['terminees'] ?? 0)?></span></a>
    </div>

    <div class="search-bar-wrap">
      <div class="search-bar"><span class="search-bar-icon"><i class="bi bi-search"></i></span>
        <input type="text" placeholder="Filtrer par numéro, agent, service, statut..." oninput="tableSearch(this,'tbody-requests','count-req')">
      </div>
      <div class="search-count" id="count-req"></div>
    </div>

    <div class="card" style="overflow-x:auto;">
      <table class="data-table">
        <thead><tr><th>N°</th><th>Déposée le</th><th>Agent</th><th>Demandeur</th><th>Service</th><th>Type</th><th>Statut</th><th>Avancement</th><th>Actions</th></tr></thead>
        <tbody id="tbody-requests">
        <?php if (!$reqs): ?><tr><td colspan="9" class="empty-cell"><?=$reqClosed ? 'Aucune demande terminée pour l\'instant.' : 'Aucune demande en cours. Diffusez le lien du formulaire public ci-dessus.'?></td></tr><?php endif; ?>
        <?php foreach ($reqs as $r): [$lbl, $cls] = requestStatusInfo($r['status']); ?>
        <tr style="<?=in_array($r['status'], ['refusee', 'annulee'], true) ? 'opacity:.6;' : ''?>">
          <td><a href="?page=requests&view=<?=$r['id']?>" class="cell-link" style="font-family:var(--font-mono);font-weight:700;color:var(--primary);"><?=h($r['numero'])?></a></td>
          <td class="muted"><?=h($r['created_fmt'])?></td>
          <td><strong><?=h($r['agent_name'])?></strong><?=$r['agent_id'] ? '' : ' <span class="muted" style="font-size:.72rem;" title="Non rattachée au référentiel">⚠️</span>'?></td>
          <td><?=h($r['requester_name'] ?: '—')?><?=$r['requester_email'] ? '<br><span class="muted" style="font-size:.75rem;">' . h($r['requester_email']) . '</span>' : ''?></td>
          <td class="muted"><?=h($r['service_name'] ?: '—')?></td>
          <td><span class="badge badge-muted"><?=$r['type'] === 'renouvellement' ? '♻️ Renouvellement' : '🆕 Attribution'?></span></td>
          <td><span class="badge <?=$cls?>"><?=h($lbl)?></span></td>
          <td class="muted" style="font-size:.8rem;">
            <?php if ($r['status'] === 'en_validation'): ?>Étape <?=(int)$r['current_step']?>/<?=(int)$r['nb_steps']?><?=$r['current_label'] ? ' — ' . h($r['current_label']) : ''?>
            <?php elseif ((int)$r['nb_steps'] > 0): ?><?=(int)$r['nb_ok']?>/<?=(int)$r['nb_steps']?> visas favorables
            <?php else: ?>—<?php endif; ?>
          </td>
          <td><a href="?page=requests&view=<?=$r['id']?>" class="btn-icon" title="Ouvrir la demande" style="text-decoration:none;color:var(--primary);"><i class="bi bi-eye"></i></a></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    <?php
    }
}

// ==================================================================
// VUE : STATISTIQUES
// ==================================================================
elseif ($page === 'stats') {
    $col = fn($rows, $k) => array_map(fn($r) => $r[$k], $rows);

    // ── Chiffres-clés ──
    $sDevActive   = (int)$pdo->query("SELECT COUNT(*) FROM devices WHERE archived=0")->fetchColumn();
    $sDevDeployed = (int)$pdo->query("SELECT COUNT(*) FROM devices WHERE archived=0 AND status='Deployed'")->fetchColumn();
    $sLinesActive = (int)$pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived=0 AND status='Active'")->fetchColumn();
    $sAgents      = (int)$pdo->query("SELECT COUNT(*) FROM agents WHERE archived=0")->fetchColumn();
    $sReqTotal    = (int)$pdo->query("SELECT COUNT(*) FROM requests")->fetchColumn();
    $sReqOpen     = (int)$pdo->query("SELECT COUNT(*) FROM requests WHERE status IN ('a_qualifier','en_validation','validee')")->fetchColumn();

    // ── 1. Parc & stock ──
    // LEFT JOIN : un matériel sans modèle (import CSV, IMEI seul) compte dans
    // « Matériels actifs » — il doit aussi apparaître dans le camembert.
    $statBrand   = $pdo->query("SELECT IFNULL(m.brand,'(sans modèle)') AS k, COUNT(d.id) AS c FROM devices d LEFT JOIN models m ON d.model_id=m.id WHERE d.archived=0 GROUP BY k ORDER BY c DESC")->fetchAll();
    $devStatusMap = ['Deployed'=>'Déployé', 'Stock'=>'En stock', 'Repair'=>'Réparation', 'HS'=>'HS / Rebut', 'Lost'=>'Perdu / Volé'];
    $statDevStat = $pdo->query("SELECT status AS k, COUNT(*) AS c FROM devices WHERE archived=0 GROUP BY status ORDER BY c DESC")->fetchAll();
    $statOper    = $pdo->query("SELECT IFNULL(o.name,'Sans opérateur') AS k, COUNT(l.id) AS c FROM mobile_lines l LEFT JOIN plan_types p ON l.plan_id=p.id LEFT JOIN operators o ON p.operator_id=o.id WHERE l.archived=0 AND l.sim_vierge=0 GROUP BY o.name ORDER BY c DESC")->fetchAll();
    $statPlan    = $pdo->query("SELECT IFNULL(p.name,'Sans forfait') AS k, COUNT(l.id) AS c FROM mobile_lines l LEFT JOIN plan_types p ON l.plan_id=p.id WHERE l.archived=0 AND l.sim_vierge=0 GROUP BY p.name ORDER BY c DESC LIMIT 8")->fetchAll();
    // Les deux cartes forment un couple : mêmes filtres de part et d'autre
    // (les SIM vierges en stock — physiques OU eSIM — n'y figurent pas).
    $sEsim    = (int)$pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived=0 AND esim=1 AND sim_vierge=0")->fetchColumn();
    $sPhysSim = (int)$pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived=0 AND esim=0 AND sim_vierge=0")->fetchColumn();
    $sByod    = (int)$pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived=0 AND personal_device=1")->fetchColumn();

    // ── Facturation : vue panoramique (12 derniers mois facturés) ──
    // La page Statistiques reste le tour d'horizon ; le pilotage fin (période,
    // compte, tops, alertes) est dans le module Facturation / Contrôle.
    $statInvMonths = $pdo->query("SELECT month_key, SUM(total_ht) t, SUM(hf_ht) hf, COUNT(*) n
            FROM invoice_lines GROUP BY month_key ORDER BY month_key DESC LIMIT 12")->fetchAll();
    $statInvMonths = array_reverse($statInvMonths);
    $statInvLastTotal = 0.0; $statInvHf = 0.0; $statInvUnit = 0.0; $statInvSvc = [];
    $statInvAxis = []; $statInvByKey = []; $statInvMissingAcc = [];
    if ($statInvMonths) {
        $last = end($statInvMonths);
        $statInvLastTotal = (float)$last['t'];
        $statInvHf        = (float)$last['hf'];
        $statInvUnit      = (int)$last['n'] > 0 ? (float)$last['t'] / (int)$last['n'] : 0.0;

        // Axe des mois CONTINU, comme le module Facturation : un mois sans
        // facture doit se lire comme un trou du tracé, pas être escamoté de
        // l'axe (deux barres voisines séparées de plusieurs mois sans indice).
        $statInvByKey = array_column($statInvMonths, null, 'month_key');
        for ($i = 11; $i >= 0; $i--) $statInvAxis[] = date('Y-m', strtotime($last['month_key'] . "-01 -$i months"));
        while ($statInvAxis && !isset($statInvByKey[$statInvAxis[0]])) array_shift($statInvAxis);

        // Le dernier mois est-il complet ? Un compte facturé les 3 mois
        // précédents mais absent du dernier laisse un total partiel — le
        // module lève une alerte « facture manquante », la carte doit au
        // moins prévenir.
        $stAcc = $pdo->prepare("SELECT DISTINCT IFNULL(billing_account,'') FROM invoice_lines WHERE month_key = ?");
        $stAcc->execute([$last['month_key']]);
        $accLastSet = $stAcc->fetchAll(PDO::FETCH_COLUMN);
        $stAccPrev = $pdo->prepare("SELECT DISTINCT IFNULL(billing_account,'') FROM invoice_lines WHERE month_key < ? AND month_key >= ?");
        $stAccPrev->execute([$last['month_key'], date('Y-m', strtotime($last['month_key'] . '-01 -3 months'))]);
        $statInvMissingAcc = array_values(array_diff($stAccPrev->fetchAll(PDO::FETCH_COLUMN), $accLastSet));

        // Coût par service : rapprochement en PHP sur le numéro CANONIQUE
        // (règle commune, +33 compris), référentiel restreint aux lignes
        // actives — la jointure SQL naïve dupliquait les montants quand un
        // numéro existait en double (ligne archivée + ligne recréée) et
        // rangeait les archivées dans un faux « (sans service) ». Les numéros
        // facturés inconnus du référentiel sont regroupés « (hors SimCity) »
        // au lieu de disparaître du total.
        $svcOfPhone = [];
        foreach ($pdo->query("SELECT " . sprintf(SIMCITY_SQL_PHONE_CANON, 'l.phone_number') . " ph, IFNULL(s.name,'') svc
                FROM mobile_lines l
                LEFT JOIN agents a ON l.agent_id = a.id
                LEFT JOIN services s ON COALESCE(l.service_id, a.service_id) = s.id
                WHERE l.archived = 0 AND l.phone_number IS NOT NULL AND l.phone_number != ''") as $r) {
            if ($r['ph'] !== '') $svcOfPhone[$r['ph']] = (string)$r['svc'];
        }
        $stSvcInv = $pdo->prepare("SELECT phone_number, SUM(total_ht) t FROM invoice_lines WHERE month_key = ? GROUP BY phone_number");
        $stSvcInv->execute([$last['month_key']]);
        $svcAgg = [];
        foreach ($stSvcInv as $r) {
            $ph  = simcity_phone_canon((string)$r['phone_number']);
            $svc = array_key_exists($ph, $svcOfPhone)
                 ? ($svcOfPhone[$ph] !== '' ? $svcOfPhone[$ph] : '(sans service)')
                 : '(hors SimCity)';
            $svcAgg[$svc] = ($svcAgg[$svc] ?? 0.0) + (float)$r['t'];
        }
        arsort($svcAgg);
        foreach (array_slice($svcAgg, 0, 10, true) as $svc => $t) $statInvSvc[] = ['svc' => $svc, 't' => $t];
    }

    // ── 2. Par service ──
    // Même définition du « service d'une ligne » que le graphique facturation
    // de cette page : service de la ligne, à défaut celui de l'agent — sinon
    // un service pouvait afficher 0 ligne ici et un coût réel juste au-dessus.
    $statSvc = $pdo->query("SELECT s.name AS k,
            (SELECT COUNT(*) FROM mobile_lines l LEFT JOIN agents ag ON l.agent_id=ag.id
                WHERE COALESCE(l.service_id, ag.service_id)=s.id AND l.archived=0)     AS lignes,
            (SELECT COUNT(*) FROM devices d WHERE d.service_id=s.id AND d.archived=0)  AS mats
        FROM services s HAVING lignes+mats > 0 ORDER BY lignes+mats DESC LIMIT 10")->fetchAll();

    // ── 3. Demandes de téléphone ──
    // 12 mois CALENDAIRES pleins (le mois courant compris) : borner à « il y a
    // 12 mois jour pour jour » affichait un 13e mois amputé de ses premiers
    // jours, présenté comme un mois entier. Les mois à zéro sont réinjectés :
    // sans eux, un creux de plusieurs mois disparaissait de l'axe.
    $statReqMonth  = $pdo->query("SELECT DATE_FORMAT(created_at,'%Y-%m') AS k, COUNT(*) AS c FROM requests
            WHERE created_at >= DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL 11 MONTH),'%Y-%m-01') GROUP BY k ORDER BY k")->fetchAll();
    $reqByMonth = array_column($statReqMonth, 'c', 'k');
    $statReqMonth = [];
    for ($i = 11; $i >= 0; $i--) {
        $k = date('Y-m', strtotime(date('Y-m-01') . " -$i months"));
        $statReqMonth[] = ['k' => $k, 'c' => (int)($reqByMonth[$k] ?? 0)];
    }
    $reqStatusMap  = ['a_qualifier'=>'À qualifier','en_validation'=>'En validation','validee'=>'Validée','livree'=>'Livrée','refusee'=>'Refusée','annulee'=>'Annulée'];
    $statReqStatus = $pdo->query("SELECT status AS k, COUNT(*) AS c FROM requests GROUP BY status")->fetchAll();
    $statReqType   = $pdo->query("SELECT type AS k, COUNT(*) AS c FROM requests GROUP BY type")->fetchAll();
    $statReqMotif  = $pdo->query("SELECT replace_motif AS k, COUNT(*) AS c FROM requests WHERE replace_device=1 AND replace_motif IS NOT NULL AND replace_motif<>'' GROUP BY replace_motif ORDER BY c DESC")->fetchAll();
    $sReqValidated = (int)$pdo->query("SELECT COUNT(*) FROM requests WHERE status IN ('validee','livree')")->fetchColumn();
    $sReqRefused   = (int)$pdo->query("SELECT COUNT(*) FROM requests WHERE status='refusee'")->fetchColumn();
    $sReqAvgDays   = $pdo->query("SELECT ROUND(AVG(DATEDIFF(closed_at, launched_at)),1) FROM requests WHERE status IN ('validee','livree') AND launched_at IS NOT NULL AND closed_at IS NOT NULL")->fetchColumn();

    // ── 4. Incidents & renouvellement ──
    // Matériels archivés par motif : un motif par matériel ACTUELLEMENT
    // archivé, pris sur son dernier journal d'archivage. Couvre aussi les
    // archivages en cascade (« archivé automatiquement — ligne associée
    // archivée (X) »), et ne compte ni les matériels restaurés depuis, ni
    // deux fois un matériel archivé-restauré-réarchivé.
    $archLogs = $pdo->query("SELECT h.entity_id, h.action_desc
            FROM history_logs h
            JOIN devices d ON d.id = h.entity_id AND d.archived = 1
            WHERE h.entity_type='device'
              AND (h.action_desc LIKE '%Motif :%' OR h.action_desc LIKE '%archivé automatiquement%')
            ORDER BY h.id")->fetchAll();
    $archLast = [];
    foreach ($archLogs as $al) $archLast[(int)$al['entity_id']] = (string)$al['action_desc'];   // le plus récent gagne
    $motifCounts = [];
    foreach ($archLast as $desc) {
        if (preg_match('/Motif\s*:\s*([^—\-]+)/u', $desc, $mm)) $mo = trim($mm[1]);
        elseif (preg_match('/archivé automatiquement.*\(([^)]+)\)/u', $desc, $mm)) $mo = trim($mm[1]) . ' (via ligne)';
        else $mo = '';
        if ($mo !== '') $motifCounts[$mo] = ($motifCounts[$mo] ?? 0) + 1;
    }
    arsort($motifCounts);
    // Vieillissement du parc (matériels actifs par tranche d'âge)
    $ageBuckets = ['< 1 an'=>0, '1–2 ans'=>0, '2–3 ans'=>0, '3–4 ans'=>0, '> 4 ans'=>0, 'Sans date'=>0];
    foreach ($pdo->query("SELECT purchase_date FROM devices WHERE archived=0")->fetchAll(PDO::FETCH_COLUMN) as $pd) {
        if (!$pd) { $ageBuckets['Sans date']++; continue; }
        $y = (time() - strtotime($pd)) / 31557600;
        if ($y < 1) $ageBuckets['< 1 an']++; elseif ($y < 2) $ageBuckets['1–2 ans']++;
        elseif ($y < 3) $ageBuckets['2–3 ans']++; elseif ($y < 4) $ageBuckets['3–4 ans']++;
        else $ageBuckets['> 4 ans']++;
    }
    // GROUP BY sur l'expression affichée : sinon reason='' et « Non précisé »
    // formaient deux barres homonymes.
    $statSimReason = $pdo->query("SELECT IFNULL(NULLIF(reason,''),'Non précisé') AS k, COUNT(*) AS c FROM sim_history GROUP BY k ORDER BY c DESC LIMIT 8")->fetchAll();

    // Rendu d'une carte-graphique (canvas + état vide)
    $chartCard = function($title, $icon, $canvasId, $hasData, $empty = 'Aucune donnée pour l\'instant.') {
        echo '<div class="card" style="margin-bottom:0;"><div class="card-header"><span><i class="bi bi-' . $icon . '"></i> ' . h($title) . '</span></div><div style="padding:1rem;height:260px;">';
        echo $hasData ? '<canvas id="' . $canvasId . '"></canvas>'
                      : '<div style="height:100%;display:flex;align-items:center;justify-content:center;color:var(--text3);font-size:.88rem;text-align:center;">' . h($empty) . '</div>';
        echo '</div></div>';
    };
    $svcNames = $col($statSvc, 'k'); $svcLines = array_map('intval', $col($statSvc, 'lignes')); $svcMats = array_map('intval', $col($statSvc, 'mats'));
    ?>
    <div style="display:flex;flex-direction:column;gap:1.5rem;">

      <!-- Chiffres-clés -->
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;">
        <?php foreach ([
            ['👤 Utilisateurs', $sAgents, 'var(--success)'],
            ['📞 Lignes actives', $sLinesActive, '#2563eb'],
            ['📱 Matériels actifs', $sDevActive, '#7c3aed'],
            ['🚀 Déployés', $sDevDeployed, '#0891b2'],
            ['📨 Demandes (total)', $sReqTotal, '#d97706'],
            ['⏳ Demandes en cours', $sReqOpen, '#dc2626'],
        ] as [$lbl, $val, $clr]): ?>
        <div class="card" style="margin:0;padding:1.1rem 1.25rem;border-left:4px solid <?=$clr?>;">
          <div style="font-family:var(--font-mono);font-size:1.7rem;font-weight:600;color:var(--text-strong);line-height:1;"><?=$val?></div>
          <div style="font-size:.76rem;color:var(--text2);text-transform:uppercase;letter-spacing:.03em;margin-top:.3rem;"><?=$lbl?></div>
        </div>
        <?php endforeach; ?>
      </div>

      <!-- 1. PARC & STOCK -->
      <h3 style="font-size:1rem;color:var(--text-strong);margin-top:.5rem;"><i class="bi bi-hdd-stack"></i> Parc &amp; stock</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;">
        <?php $chartCard('Matériels par marque', 'phone', 'stBrand', (bool)$statBrand); ?>
        <?php $chartCard('Statut des matériels', 'pie-chart', 'stDevStat', (bool)$statDevStat); ?>
        <?php $chartCard('Lignes par opérateur', 'broadcast', 'stOper', (bool)$statOper); ?>
        <?php $chartCard('Lignes par forfait', 'globe2', 'stPlan', (bool)$statPlan); ?>
      </div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;">
        <div class="card" style="margin:0;padding:1.1rem 1.25rem;text-align:center;"><div style="font-family:var(--font-mono);font-size:1.5rem;font-weight:600;color:#7c3aed;"><?=$sEsim?></div><div style="font-size:.78rem;color:var(--text2);">eSIM</div></div>
        <div class="card" style="margin:0;padding:1.1rem 1.25rem;text-align:center;"><div style="font-family:var(--font-mono);font-size:1.5rem;font-weight:600;color:#2563eb;"><?=$sPhysSim?></div><div style="font-size:.78rem;color:var(--text2);">SIM physique</div></div>
        <div class="card" style="margin:0;padding:1.1rem 1.25rem;text-align:center;"><div style="font-family:var(--font-mono);font-size:1.5rem;font-weight:600;color:#0891b2;"><?=$sByod?></div><div style="font-size:.78rem;color:var(--text2);">Appareils perso (BYOD)</div></div>
      </div>

      <!-- 2. PAR SERVICE -->
      <h3 style="font-size:1rem;color:var(--text-strong);margin-top:.5rem;"><i class="bi bi-building"></i> Par service / direction</h3>
      <?php $chartCard('Lignes & matériels par service (top 10)', 'bar-chart', 'stSvc', (bool)$statSvc); ?>

      <!-- 3. DEMANDES -->
      <h3 style="font-size:1rem;color:var(--text-strong);margin-top:.5rem;"><i class="bi bi-inbox"></i> Demandes de téléphone</h3>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;">
        <div class="card" style="margin:0;padding:1.1rem 1.25rem;text-align:center;border-left:4px solid var(--success);"><div style="font-family:var(--font-mono);font-size:1.6rem;font-weight:600;color:var(--success);"><?=$sReqValidated?></div><div style="font-size:.78rem;color:var(--text2);">Validées / livrées</div></div>
        <div class="card" style="margin:0;padding:1.1rem 1.25rem;text-align:center;border-left:4px solid var(--danger);"><div style="font-family:var(--font-mono);font-size:1.6rem;font-weight:600;color:var(--danger);"><?=$sReqRefused?></div><div style="font-size:.78rem;color:var(--text2);">Refusées</div></div>
        <div class="card" style="margin:0;padding:1.1rem 1.25rem;text-align:center;border-left:4px solid var(--primary);"><div style="font-family:var(--font-mono);font-size:1.6rem;font-weight:600;color:var(--primary);"><?=$sReqAvgDays !== null && $sReqAvgDays !== false ? h($sReqAvgDays) . ' j' : '—'?></div><div style="font-size:.78rem;color:var(--text2);">Délai moyen du circuit</div></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;">
        <?php $chartCard('Demandes par mois (12 mois)', 'calendar3', 'stReqMonth', (bool)array_filter($col($statReqMonth, 'c'))); ?>
        <?php $chartCard('Répartition par statut', 'pie-chart', 'stReqStatus', (bool)$statReqStatus); ?>
        <?php $chartCard('Par type de demande', 'tags', 'stReqType', (bool)$statReqType); ?>
        <?php $chartCard('Motifs de remplacement', 'exclamation-triangle', 'stReqMotif', (bool)$statReqMotif, 'Aucun renouvellement avec motif.'); ?>
      </div>

      <!-- 4. FACTURATION — vue panoramique ; l'analyse fine est dans le module -->
      <?php if($statInvMonths): ?>
      <h3 style="font-size:1rem;color:var(--text-strong);margin-top:.5rem;"><i class="bi bi-receipt"></i> Facturation
        <a href="?page=invoices" style="font-size:.78rem;font-weight:400;margin-left:.5rem;">analyse détaillée →</a></h3>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;">
        <div class="card" style="margin:0;padding:1.1rem 1.25rem;text-align:center;border-left:4px solid var(--primary);">
          <div style="font-family:var(--font-mono);font-size:1.6rem;font-weight:600;color:var(--primary);"><?=number_format($statInvLastTotal, 0, ',', ' ')?> €</div>
          <div style="font-size:.78rem;color:var(--text2);">Dernier mois facturé (HT)</div>
          <?php if($statInvMissingAcc): ?>
          <div style="font-size:.72rem;color:var(--warning);margin-top:.25rem;" title="Compte(s) facturé(s) les mois précédents mais absent(s) du dernier mois : <?=h(implode(', ', $statInvMissingAcc))?>">
            <i class="bi bi-exclamation-triangle"></i> total probablement partiel — <?=count($statInvMissingAcc)?> compte(s) sans facture</div>
          <?php endif; ?></div>
        <div class="card" style="margin:0;padding:1.1rem 1.25rem;text-align:center;border-left:4px solid var(--warning);">
          <div style="font-family:var(--font-mono);font-size:1.6rem;font-weight:600;color:var(--warning);"><?=number_format($statInvHf, 2, ',', ' ')?> €</div>
          <div style="font-size:.78rem;color:var(--text2);">Hors-forfait du mois</div></div>
        <div class="card" style="margin:0;padding:1.1rem 1.25rem;text-align:center;border-left:4px solid var(--info);">
          <div style="font-family:var(--font-mono);font-size:1.6rem;font-weight:600;color:var(--info);"><?=number_format($statInvUnit, 2, ',', ' ')?> €</div>
          <div style="font-size:.78rem;color:var(--text2);">Coût moyen par ligne</div></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;">
        <?php $chartCard('Coût mensuel des lignes (€ HT)', 'graph-up', 'stInvMonth', true); ?>
        <?php $chartCard('Coût par service (top 10, dernier mois)', 'building', 'stInvSvc', (bool)$statInvSvc, 'Aucune ligne facturée rattachée à un service — voir le rapprochement.'); ?>
      </div>
      <?php endif; ?>

      <!-- 5. INCIDENTS & RENOUVELLEMENT -->
      <h3 style="font-size:1rem;color:var(--text-strong);margin-top:.5rem;"><i class="bi bi-tools"></i> Incidents &amp; renouvellement</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;">
        <?php $chartCard('Matériels archivés par motif', 'trash3', 'stArch', (bool)$motifCounts, 'Aucun matériel archivé.'); ?>
        <?php $chartCard('Vieillissement du parc (matériels actifs)', 'hourglass-split', 'stAge', array_sum($ageBuckets) > 0); ?>
        <?php $chartCard('Changements de SIM par motif', 'sim', 'stSim', (bool)$statSimReason, 'Aucun changement de SIM.'); ?>
      </div>
    </div>

    <script src="vendor/chart.umd.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
      const PAL = ['#4f46e5','#2563eb','#7c3aed','#d97706','#059669','#dc2626','#0891b2','#db2777','#65a30d','#ea580c'];
      // Couleurs d'axe lues sur le thème courant, comme les graphiques du
      // module Facturation : les valeurs figées passaient mal en thème clair.
      const _css  = getComputedStyle(document.documentElement);
      const _var  = (n, d) => (_css.getPropertyValue(n) || '').trim() || d;
      const AXIS  = _var('--text2', '#64748b');
      const GRID  = _var('--border', 'rgba(148,163,184,.15)');
      // `link` (optionnel) : fonction libellé → URL. Rend le graphique
      // cliquable — un clic sur une part/barre ouvre la vue filtrée.
      const clickOpts = (labels, link) => link ? {
        onClick: (e, a) => { if(a.length) location = link(labels[a[0].index]); },
        onHover: (e, a) => { e.native.target.style.cursor = a.length ? 'pointer' : 'default'; },
      } : {};
      function doughnut(id, labels, data, link){ const el=document.getElementById(id); if(!el||!labels.length)return;
        new Chart(el,{type:'doughnut',data:{labels,datasets:[{data,backgroundColor:PAL,borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,...clickOpts(labels,link),plugins:{legend:{position:'bottom',labels:{color:AXIS,boxWidth:12,padding:10}}}}}); }
      function bars(id, labels, datasets, horizontal, link){ const el=document.getElementById(id); if(!el||!labels.length)return;
        new Chart(el,{type:'bar',data:{labels,datasets},options:{indexAxis:horizontal?'y':'x',responsive:true,maintainAspectRatio:false,...clickOpts(labels,link),scales:{x:{beginAtZero:true,ticks:{color:AXIS,precision:0},grid:{color:GRID}},y:{beginAtZero:true,ticks:{color:AXIS,precision:0},grid:{color:GRID}}},plugins:{legend:{display:datasets.length>1,labels:{color:AXIS}}}}}); }
      const toBrands = l => '?page=brands&q=' + encodeURIComponent(l);
      const toLines  = l => '?page=lines&tab=active&q=' + encodeURIComponent(l);

      // Parc & stock — cliquables : marque → synthèse par marque/modèle,
      // opérateur / forfait / service → liste des lignes pré-filtrée.
      doughnut('stBrand', <?=json_encode($col($statBrand,'k'))?>, <?=json_encode(array_map('intval',$col($statBrand,'c')))?>, toBrands);
      doughnut('stDevStat', <?=json_encode(array_map(fn($k)=>$devStatusMap[$k]??$k, $col($statDevStat,'k')))?>, <?=json_encode(array_map('intval',$col($statDevStat,'c')))?>);
      bars('stOper', <?=json_encode($col($statOper,'k'))?>, [{label:'Lignes',data:<?=json_encode(array_map('intval',$col($statOper,'c')))?>,backgroundColor:'#2563eb',borderRadius:4}], false, toLines);
      bars('stPlan', <?=json_encode($col($statPlan,'k'))?>, [{label:'Lignes',data:<?=json_encode(array_map('intval',$col($statPlan,'c')))?>,backgroundColor:'#7c3aed',borderRadius:4}], true, toLines);

      // Par service (barres groupées)
      bars('stSvc', <?=json_encode($svcNames)?>, [
        {label:'Lignes',   data:<?=json_encode($svcLines)?>, backgroundColor:'<?=uiPrimaryColor($pdo) ?: '#4f46e5'?>', borderRadius:4},
        {label:'Matériels',data:<?=json_encode($svcMats)?>,  backgroundColor:'#7c3aed', borderRadius:4}
      ], false, toLines);

      // Demandes
      bars('stReqMonth', <?=json_encode($col($statReqMonth,'k'))?>, [{label:'Demandes',data:<?=json_encode(array_map('intval',$col($statReqMonth,'c')))?>,backgroundColor:'#d97706',borderRadius:4}]);
      doughnut('stReqStatus', <?=json_encode(array_map(fn($k)=>$reqStatusMap[$k]??$k, $col($statReqStatus,'k')))?>, <?=json_encode(array_map('intval',$col($statReqStatus,'c')))?>);
      doughnut('stReqType', <?=json_encode(array_map(fn($k)=>$k==='renouvellement'?'Renouvellement':'Attribution', $col($statReqType,'k')))?>, <?=json_encode(array_map('intval',$col($statReqType,'c')))?>);
      bars('stReqMotif', <?=json_encode($col($statReqMotif,'k'))?>, [{label:'Demandes',data:<?=json_encode(array_map('intval',$col($statReqMotif,'c')))?>,backgroundColor:'#dc2626',borderRadius:4}]);

      // Facturation — axe continu : un mois sans facture est un TROU du tracé
      // (barre absente), jamais un mois escamoté de l'axe.
      <?php if($statInvMonths):
        $moisCourt = function(string $mk): string {
            $n = [1=>'janv.',2=>'févr.',3=>'mars',4=>'avr.',5=>'mai',6=>'juin',7=>'juil.',8=>'août',9=>'sept.',10=>'oct.',11=>'nov.',12=>'déc.'];
            [$y, $m] = array_pad(explode('-', $mk), 2, '0');   // month_key malformé → « ? »
            return ($n[(int)$m] ?? '?') . ' ' . substr($y, 2);
        }; ?>
      bars('stInvMonth', <?=json_encode(array_map($moisCourt, $statInvAxis))?>,
           [{label:'Total € HT',data:<?=json_encode(array_map(fn($k) => isset($statInvByKey[$k]) ? round((float)$statInvByKey[$k]['t'], 2) : null, $statInvAxis))?>,backgroundColor:'#4f46e5',borderRadius:4},
            {label:'Hors-forfait € HT',data:<?=json_encode(array_map(fn($k) => isset($statInvByKey[$k]) ? round((float)$statInvByKey[$k]['hf'], 2) : null, $statInvAxis))?>,backgroundColor:'#d97706',borderRadius:4}]);
      bars('stInvSvc', <?=json_encode($col($statInvSvc,'svc'))?>,
           [{label:'€ HT',data:<?=json_encode(array_map(fn($v) => round((float)$v, 2), $col($statInvSvc,'t')))?>,backgroundColor:'#0891b2',borderRadius:4}], true,
           l => l === '(hors SimCity)'   ? '?page=invoices&tab=conso&flag=unknown'
              : l === '(sans service)'   ? '?page=invoices&tab=conso&flag=nosvc'
              : '?page=invoices&tab=conso&svc=' + encodeURIComponent(l));
      <?php endif; ?>

      // Incidents & renouvellement
      bars('stArch', <?=json_encode(array_keys($motifCounts))?>, [{label:'Matériels',data:<?=json_encode(array_values($motifCounts))?>,backgroundColor:'#dc2626',borderRadius:4}]);
      bars('stAge', <?=json_encode(array_keys($ageBuckets))?>, [{label:'Matériels',data:<?=json_encode(array_values($ageBuckets))?>,backgroundColor:'#0891b2',borderRadius:4}]);
      bars('stSim', <?=json_encode($col($statSimReason,'k'))?>, [{label:'Changements',data:<?=json_encode(array_map('intval',$col($statSimReason,'c')))?>,backgroundColor:'#65a30d',borderRadius:4}], true);
    });
    </script>
    <?php
}

$content = ob_get_clean();
?>

<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title><?=h($pageTitles[$page]??'SimCity')?> – SimCity</title>
<link rel="icon" type="image/svg+xml" href="index.php?logo=1"><?php echo uiPrimaryCssOverride($pdo); ?>
<link href="vendor/plex.css" rel="stylesheet">
<link href="vendor/bootstrap-icons.css" rel="stylesheet">
<script>(function(){ if (localStorage.getItem('pm_theme') === 'dark') document.documentElement.setAttribute('data-theme','dark'); })();</script>
<style>
/* CSS UNIFIÉ MINIFIÉ — design system aligné sur Sentinelle (IBM Plex, indigo + slate) */
:root{--bg:#f8fafc;--bg2:#ffffff;--bg3:#f1f5f9;--card:#ffffff;--card2:#f1f5f9;--border:#e2e8f0;--border2:#cbd5e1;--primary:#4f46e5;--primary-dark:#4338ca;--primary-dim:rgba(79,70,229,.08);--primary-glow:rgba(79,70,229,.35);--success:#059669;--success-dim:#d1fae5;--danger:#dc2626;--danger-dim:#fee2e2;--warning:#d97706;--warning-dim:#fef3c7;--info:#2563eb;--info-dim:#dbeafe;--text:#334155;--text-strong:#0f172a;--text2:#64748b;--text3:#94a3b8;--sidebar-w:255px;--topbar-h:64px;--radius:10px;--radius-sm:7px;--radius-lg:14px;--shadow:0 1px 3px rgba(15,23,42,.06),0 1px 2px rgba(15,23,42,.04);--shadow-md:0 4px 12px rgba(15,23,42,.08),0 2px 4px rgba(15,23,42,.04);--shadow-lg:0 12px 28px rgba(15,23,42,.12),0 4px 10px rgba(15,23,42,.06);--ring:0 0 0 3px rgba(79,70,229,.35);--font:'IBM Plex Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;--font-display:'IBM Plex Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;--font-mono:'IBM Plex Mono',ui-monospace,'SFMono-Regular','Consolas',monospace;}
[data-theme="dark"]{--bg:#0b1120;--bg2:#111827;--bg3:#0f1b2d;--card:#1e293b;--card2:#233247;--border:#2b3a4f;--border2:#3a4a61;--primary:#818cf8;--primary-dark:#6366f1;--primary-dim:rgba(129,140,248,.14);--primary-glow:rgba(129,140,248,.35);--success:#34d399;--success-dim:#064e3b;--danger:#f87171;--danger-dim:#7f1d1d;--warning:#fbbf24;--warning-dim:#78350f;--info:#60a5fa;--info-dim:#1e3a5f;--text:#e2e8f0;--text-strong:#f8fafc;--text2:#94a3b8;--text3:#64748b;--shadow:0 1px 3px rgba(0,0,0,.45);--shadow-md:0 4px 14px rgba(0,0,0,.5);--shadow-lg:0 14px 32px rgba(0,0,0,.6);--ring:0 0 0 3px rgba(129,140,248,.35);}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0} body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:.9rem;line-height:1.5;letter-spacing:-.005em;-webkit-font-smoothing:antialiased;transition:background-color .2s ease,color .2s ease;}
h1,h2,h3,h4,h5,h6{color:var(--text-strong)}
::-webkit-scrollbar{width:10px;height:10px} ::-webkit-scrollbar-track{background:transparent} ::-webkit-scrollbar-thumb{background:var(--border2);border-radius:999px;border:2px solid var(--bg)} ::-webkit-scrollbar-thumb:hover{background:var(--text3)}
.app{display:flex;min-height:100vh}
.sidebar{width:var(--sidebar-w);height:100vh;position:fixed;left:0;top:0;z-index:100;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden;}
.sidebar-logo{padding:1.5rem 1.5rem 1rem;display:flex;align-items:center;gap:.75rem;border-bottom:1px solid var(--border);}
.sidebar-logo .logo-icon{width:32px;height:32px;flex-shrink:0}
.sidebar-logo .logo-text{font-family:var(--font-display);font-weight:700;font-size:1.15rem;color:var(--text-strong);letter-spacing:.3px;}
.sidebar-section{padding:.85rem 1rem .3rem;font-size:.64rem;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.13em;}
.sidebar-nav{flex:1;padding:.5rem;overflow-y:auto;}
.nav-item{display:flex;align-items:center;gap:.75rem;padding:.6rem 1rem;border-radius:var(--radius-sm);color:var(--text2);text-decoration:none;font-size:.875rem;font-weight:500;transition:all .18s ease;}
.nav-item:hover{background:var(--bg3);color:var(--text-strong)} .nav-item.active{color:var(--primary);font-weight:600}
.nav-icon{width:20px;text-align:center;font-size:1.02rem;flex-shrink:0} .nav-item.active .nav-icon{color:var(--primary)}
.btn-hamburger{display:none;background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);width:38px;height:38px;font-size:1.25rem;align-items:center;justify-content:center;cursor:pointer}
.btn-hamburger:hover{background:var(--bg3)}
/* ── Pied de sidebar : carte utilisateur + actions, comme Sentinelle ── */
.sidebar-footer{border-top:1px solid var(--border);padding:12px 12px 10px;margin-top:auto;}
.sidebar-footer-user{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px;border-radius:var(--radius);background:var(--bg3);margin-bottom:8px;}
.sidebar-footer-user .sfu-id{display:flex;align-items:center;gap:8px;min-width:0;}
.sidebar-avatar{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,var(--primary),var(--primary-dark));display:flex;align-items:center;justify-content:center;color:#fff;font-size:.9rem;flex-shrink:0;}
.sidebar-username{font-size:.8rem;font-weight:600;color:var(--text-strong);line-height:1.2;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.sidebar-role{font-size:.64rem;color:var(--text3);text-transform:uppercase;letter-spacing:.05em;}
.sidebar-footer-actions{display:flex;gap:4px;}
.sidebar-footer-link{flex:1;display:flex;align-items:center;justify-content:center;gap:5px;padding:7px 4px;font-size:.74rem;color:var(--text2);border-radius:var(--radius-sm);text-decoration:none;transition:background-color .18s ease,color .18s ease;}
.sidebar-footer-link:hover{background:var(--bg3);color:var(--text-strong);}
.sidebar-footer-link-danger:hover{background:var(--danger-dim);color:var(--danger);}
/* Backdrop mobile (sidebar off-canvas) */
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(15,23,42,.5);z-index:99;backdrop-filter:blur(1px);}
.sidebar-overlay.open{display:block;}
.main{margin-left:var(--sidebar-w);flex:1;display:flex;flex-direction:column;min-width:0}
.topbar{height:var(--topbar-h);background:var(--bg2);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 1.5rem;gap:1rem;position:sticky;top:0;z-index:50;}
.topbar-title{font-family:var(--font-display);font-weight:700;font-size:1.05rem;color:var(--text-strong);flex:1}
/* Bascule de thème : icône Bootstrap Icons (bi-sun / bi-moon), comme Sentinelle */
.theme-toggle{cursor:pointer;color:var(--text2);font-size:1rem;padding:6px 8px;border-radius:var(--radius-sm);line-height:1;transition:background-color .18s ease,color .18s ease}
.theme-toggle:hover{color:var(--text-strong);background:var(--bg3)}
.content{padding:2rem;flex:1;max-width:1720px;margin:0 auto;width:100%;}
.page-header{display:flex;align-items:center;justify-content:flex-end;margin-bottom:1.5rem;}
.page-title-txt{font-family:var(--font-display);font-weight:700;font-size:1.4rem;color:var(--text-strong);}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius-lg);margin-bottom:1.5rem;break-inside:avoid;box-shadow:var(--shadow);}
.card-header{padding:.85rem 1.5rem .85rem 2.15rem;border-bottom:1px solid var(--border);background:rgba(79,70,229,.03);font-family:var(--font-display);font-weight:700;font-size:.9rem;color:var(--text);position:relative;}
.card-header::before{content:'';position:absolute;left:1.5rem;top:50%;transform:translateY(-50%);width:4px;height:1.05em;border-radius:3px;background:var(--primary);}

/* Sections repliables (thèmes du tableau de bord Facturation) */
.acc{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);margin-bottom:1rem;overflow:hidden}
.acc>summary{cursor:pointer;padding:.85rem 1.5rem .85rem 2.15rem;font-family:var(--font-display);font-weight:700;font-size:.9rem;color:var(--text);position:relative;display:flex;align-items:center;gap:.55rem;list-style:none}
.acc>summary::-webkit-details-marker{display:none}
.acc>summary::before{content:'';position:absolute;left:1.5rem;top:50%;transform:translateY(-50%);width:4px;height:1.05em;border-radius:3px;background:var(--primary)}
.acc>summary:hover{background:var(--bg3)}
.acc[open]>summary{border-bottom:1px solid var(--border);background:rgba(79,70,229,.03)}
.acc>summary .acc-hint{font-weight:400;font-size:.79rem;color:var(--text2)}
.acc>summary .acc-chev{margin-left:auto;color:var(--text2);font-size:.8rem;transition:transform .2s ease}
.acc[open]>summary .acc-chev{transform:rotate(180deg)}
.acc-body{padding:1.1rem 1.4rem 1.3rem}
.acc-body.flush{padding:0}
.acc-body.flush>.data-table{margin:0}

.data-table{width:100%;border-collapse:collapse}
.data-table th{padding:.75rem 1.25rem;text-align:left;font-size:.68rem;font-weight:700;letter-spacing:.06em;color:var(--text2);text-transform:uppercase;background:var(--card2);border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer;user-select:none;transition:color 0.15s;}
.data-table th:hover{color:var(--primary);}
.data-table th.sorted{color:var(--primary);font-weight:700;}
/* En-tête portant un lien de tri SERVEUR : le lien occupe toute la cellule,
   sinon un clic à côté du texte ne déclenche rien (ou pire, un tri JS qui ne
   porterait que sur la page affichée). */
.data-table thead th>a{display:block;color:inherit;text-decoration:none;}
.data-table thead th>a:hover{color:var(--primary);}

.data-table td{padding:.8rem 1.25rem;border-bottom:1px solid var(--border);font-size:.875rem;line-height:1.4} .data-table tbody tr{transition:background-color .12s ease} .data-table tbody tr:hover{background:var(--bg3)}
.empty-cell{text-align:center;color:var(--text3);padding:3rem!important;font-style:italic} .muted{color:var(--text2)!important;font-size:.82rem;}
.search-bar-wrap{margin-bottom:1rem;} .search-bar{display:flex;align-items:center;gap:.6rem;background:var(--card);border:1px solid var(--border2);border-radius:var(--radius-sm);padding:.55rem .9rem; transition:border-color .2s, box-shadow .2s; }
/* Variante compacte : recherche limitée en largeur, action alignée à droite */
.search-bar-inline{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;}
.search-bar-inline>.search-bar{flex:0 1 380px;min-width:200px;}
.search-bar-inline>.search-count{margin:0;}
.search-bar-inline>.btn-primary{margin-left:auto;}
[data-theme="dark"] .search-bar{background:var(--bg3)}
.search-bar:focus-within { border-color:var(--primary); box-shadow:var(--ring); }
.search-bar-icon{font-size:1rem;opacity:.5;flex-shrink:0;} .search-bar input{flex:1;background:none;border:none;outline:none;color:var(--text);font-size:.9rem;} .search-count{font-size:.75rem;color:var(--text3);margin-top:.3rem;}
.badge{display:inline-block;padding:.2rem .65rem;border-radius:999px;font-size:.72rem;font-weight:600;white-space:nowrap;line-height:1.4;}
.badge-success{background:var(--success-dim);color:#065f46;} .badge-danger{background:var(--danger-dim);color:#991b1b;} .badge-warning{background:var(--warning-dim);color:#92400e;} .badge-info{background:var(--info-dim);color:#1e40af;} .badge-muted{background:var(--bg3);color:var(--text2);}
[data-theme="dark"] .badge-success{color:#6ee7b7} [data-theme="dark"] .badge-danger{color:#fca5a5} [data-theme="dark"] .badge-warning{color:#fcd34d} [data-theme="dark"] .badge-info{color:#93c5fd}
.btn-primary{background:var(--primary);border:1px solid var(--primary);border-radius:var(--radius-sm);padding:.6rem 1.4rem;color:#fff;font-weight:500;font-size:.85rem;cursor:pointer;transition:all .18s ease;} .btn-primary:hover{background:var(--primary-dark);border-color:var(--primary-dark);box-shadow:var(--shadow);} .btn-primary:active{transform:translateY(1px);}
.btn-secondary{background:var(--card);border:1px solid var(--border2);border-radius:var(--radius-sm);padding:.6rem 1.25rem;color:var(--text2);font-size:.85rem;cursor:pointer;transition:all .18s ease;} .btn-secondary:hover{border-color:var(--primary);color:var(--text-strong)}
.btn-icon{background:none;border:none;cursor:pointer;font-size:1rem;padding:.3rem .5rem;border-radius:var(--radius-sm);color:var(--text2);transition:all .15s;}
/* Colonne Actions : réduite à la largeur de son contenu (width:1% + nowrap),
   les icônes restent toujours sur une seule ligne ; les formulaires inline
   (archiver/restaurer) ne provoquent plus de retour à la ligne. */
td.actions{white-space:nowrap;width:1%;} td.actions form{display:inline;white-space:nowrap;} .btn-edit:hover{background:var(--primary-dim);color:var(--primary)} .btn-del:hover{background:var(--danger-dim);color:var(--danger)}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:1.25rem;} .form-group{display:flex;flex-direction:column;gap:.4rem;} .form-full{grid-column:1/-1;}
label{font-size:.78rem;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.03em;} input,select,textarea{background:var(--card);border:1px solid var(--border2);border-radius:var(--radius-sm);padding:.6rem .9rem;color:var(--text);width:100%;font-family:inherit;font-size:.85rem;transition:border-color .18s ease,box-shadow .18s ease;}
[data-theme="dark"] input,[data-theme="dark"] select,[data-theme="dark"] textarea{background:var(--bg3)}
input:hover:not(:focus):not(:disabled),select:hover:not(:focus):not(:disabled),textarea:hover:not(:focus):not(:disabled){border-color:rgba(79,70,229,.55)}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--primary);box-shadow:var(--ring);}
/* Exemples (placeholder) : nettement plus pâles et en italique, sinon on les
   confond avec une valeur déjà saisie. */
input::placeholder,textarea::placeholder{color:var(--text3);opacity:.75;font-style:italic;}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:1000;align-items:center;justify-content:center;padding:1rem;backdrop-filter:blur(4px)} .modal-overlay.open{display:flex;animation:fadeIn .2s ease;}
.modal{background:var(--card);border:1px solid var(--border2);border-radius:var(--radius);width:100%;max-width:580px;max-height:90vh;overflow-y:auto;box-shadow:var(--shadow-lg);animation:slideUp .25s ease;} .modal-lg{max-width:700px;}
@keyframes fadeIn{from{opacity:0}to{opacity:1}} @keyframes slideUp{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}
.modal-header{padding:1.25rem 1.5rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;position:sticky;top:0;background:var(--card);z-index:1} .modal-close{background:none;border:none;color:var(--text3);font-size:1.1rem;cursor:pointer} .modal-close:hover{color:var(--text);}
.modal form{padding:1.5rem;} .modal-footer{display:flex;justify-content:flex-end;gap:.75rem;padding-top:1.25rem;border-top:1px solid var(--border);margin-top:1.25rem}
.dashboard-grid{display:flex;flex-direction:column;gap:1.5rem;} .kpi-row{display:grid;grid-template-columns:repeat(3,1fr);gap:1.25rem;}
.kpi-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem 1.5rem;display:flex;align-items:center;gap:1rem;position:relative;overflow:hidden;box-shadow:var(--shadow);transition:transform .18s ease,box-shadow .18s ease,border-color .18s ease;}
.kpi-card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;} .kpi-card:hover{transform:translateY(-2px);box-shadow:var(--shadow-md);border-color:var(--border2);}
.kpi-blue::before{background:var(--primary);}
.kpi-violet::before{background:var(--primary-dark);}
.kpi-green::before{background:var(--primary);}
.kpi-icon{font-size:2rem;} .kpi-val{font-family:var(--font-mono);font-size:1.7rem;font-weight:600;line-height:1.1;color:var(--text-strong);letter-spacing:-.01em;} .kpi-label{font-size:.74rem;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;}
.kpi-main{display:flex;align-items:center;gap:1rem;flex:1;min-width:0;text-decoration:none;color:inherit;}
.kpi-info{display:flex;flex-direction:column;min-width:0;}
.kpi-sub{font-size:.75rem;color:var(--text2);margin-top:.15rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.kpi-add{flex-shrink:0;display:inline-flex;align-items:center;gap:.35rem;padding:.45rem .85rem;border-radius:999px;background:var(--primary-dim);color:var(--primary);font-size:.76rem;font-weight:600;text-decoration:none;white-space:nowrap;transition:background-color .15s,color .15s;}
.kpi-add:hover{background:var(--primary);color:#fff;}
.shortcut-btn{display:flex;flex-direction:column;gap:.35rem;padding:1.25rem;border-radius:var(--radius);border:1px solid var(--border);text-decoration:none;transition:border-color .2s;} .shortcut-btn:hover{border-color:var(--primary);}
.shortcut-label{font-weight:700;color:var(--text-strong)} .shortcut-in{background:rgba(5,150,105,.07);} .shortcut-order{background:rgba(79,70,229,.07);} .shortcut-resa{background:rgba(37,99,235,.07);}
.tab-btn{padding:.6rem 1.2rem;border:1px solid transparent;border-radius:var(--radius-sm) var(--radius-sm) 0 0;text-decoration:none;color:var(--text2);font-weight:600;font-size:.9rem;} .tab-btn.active{background:var(--card);border-color:var(--border);border-bottom-color:var(--card);color:var(--primary);font-weight:700;margin-bottom:-2px;z-index:2;}
@media(max-width:900px){.sidebar{transform:translateX(-100%);transition:transform .25s ease;box-shadow:var(--shadow-lg)}.sidebar.open{transform:translateX(0)}.main{margin-left:0}.btn-hamburger{display:inline-flex}}
a{color:inherit;text-decoration:none} a:hover{color:var(--primary)}
/* Ajout rapide (+) : select accolé à un bouton d'ajout d'entité liée */
.qa-row{display:flex;gap:.5rem;align-items:stretch}
.qa-row select{flex:1;min-width:0}
.btn-quickadd{flex-shrink:0;width:42px;display:inline-flex;align-items:center;justify-content:center;background:var(--primary-dim);color:var(--primary);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:1rem;transition:background-color .15s,color .15s}
.btn-quickadd:hover{background:var(--primary);color:#fff}
.drag-cell{cursor:grab;color:var(--text3);text-align:center;user-select:none;} .drag-cell:active{cursor:grabbing;} .drag-cell:hover{color:var(--primary);}
/* Autocomplétion annuaire (AD) — recherche de personne dans la fiche utilisateur */
.adp-box{position:absolute;left:0;right:0;top:100%;z-index:40;background:var(--card);border:1px solid var(--border2);border-radius:var(--radius-sm);box-shadow:var(--shadow-lg);margin-top:.25rem;max-height:240px;overflow-y:auto;display:none;}
.adp-item{padding:.5rem .75rem;cursor:pointer;border-bottom:1px solid var(--border);font-size:.85rem;}
.adp-item:last-child{border-bottom:none;}
.adp-item:hover{background:var(--bg3);}
/* Cellules cliquables (numéro de ligne, nom d'utilisateur) → fiche concernée */
.cell-link{cursor:pointer;text-decoration:none;border-bottom:1px dashed transparent;transition:border-color .15s,color .15s}
.cell-link:hover{border-bottom-color:currentColor;color:var(--primary)}
/* Lien « Voir tout → » dans les en-têtes de graphiques */
.card-see-all{color:var(--primary);font-size:.8rem;font-weight:600;text-transform:none;letter-spacing:0;white-space:nowrap;display:inline-flex;align-items:center;gap:.3rem;transition:gap .15s}
.card-see-all:hover{color:var(--primary);gap:.5rem}
.modal-overlay{background:rgba(15,23,42,.5)!important}
[data-theme="dark"] .modal-overlay{background:rgba(0,0,0,.75)!important}
</style>
</head>
<body>
<div class="app">
<div class="sidebar-overlay" id="sidebar-overlay" onclick="closeSidebar()"></div>
<aside class="sidebar" id="sidebar">
  <div class="sidebar-logo">
    <img src="index.php?logo=1" alt="" class="logo-icon">
    <div><div class="logo-text">SimCity</div><div class="logo-ver">v<?=defined('APP_VERSION') ? APP_VERSION : '1.0'?></div></div>
  </div>
  <nav class="sidebar-nav">
    <div class="sidebar-section">Principal</div>
    <a href="?page=dashboard" class="nav-item <?=$page==='dashboard'?'active':''?>"><i class="bi bi-grid-1x2 nav-icon"></i><span class="nav-label">Tableau de bord</span></a>

    <?php $navRefsTab = $page==='refs' ? ($_GET['tab'] ?? 'agents') : ''; ?>
    <div class="sidebar-section">Parc & Stocks</div>
    <a href="?page=refs&tab=agents" class="nav-item <?=$navRefsTab==='agents'?'active':''?>"><i class="bi bi-people nav-icon"></i><span class="nav-label">Utilisateurs</span></a>
    <a href="?page=lines" class="nav-item <?=$page==='lines'?'active':''?>"><i class="bi bi-sim nav-icon"></i><span class="nav-label">Lignes & SIM</span></a>
    <a href="?page=devices" class="nav-item <?=$page==='devices'?'active':''?>"><i class="bi bi-phone nav-icon"></i><span class="nav-label">Matériels</span></a>

    <div class="sidebar-section">Outils</div>
    <?php $navReqPending = (int)$pdo->query("SELECT COUNT(*) FROM requests WHERE status IN ('a_qualifier','en_validation')")->fetchColumn(); ?>
    <a href="?page=requests" class="nav-item <?=$page==='requests'?'active':''?>"><i class="bi bi-inbox nav-icon"></i><span class="nav-label">Demandes de téléphone</span><?php if($navReqPending): ?><span style="margin-left:auto;background:var(--primary);color:#fff;font-size:.68rem;font-weight:700;border-radius:999px;padding:.1rem .5rem;"><?=$navReqPending?></span><?php endif; ?></a>
    <a href="?page=history" class="nav-item <?=$page==='history'?'active':''?>"><i class="bi bi-file-earmark-text nav-icon"></i><span class="nav-label">Historique des bons</span></a>
    <a href="?page=stats" class="nav-item <?=$page==='stats'?'active':''?>"><i class="bi bi-bar-chart-line nav-icon"></i><span class="nav-label">Statistiques</span></a>
    <a href="?page=invoices" class="nav-item <?=$page==='invoices'?'active':''?>"><i class="bi bi-receipt nav-icon"></i><span class="nav-label">Facturation / Contrôle</span></a>
    <a href="?page=refs&tab=services" class="nav-item <?=($navRefsTab!=='' && $navRefsTab!=='agents')?'active':''?>"><i class="bi bi-gear nav-icon"></i><span class="nav-label">Référentiels et Paramètres</span></a>
    <?php
    $navOperators = $pdo->query("SELECT name, website FROM operators WHERE website IS NOT NULL AND website != '' ORDER BY name")->fetchAll();
    foreach($navOperators as $op): ?>
    <a href="<?=h($op['website'])?>" target="_blank" class="nav-item"><i class="bi bi-globe2 nav-icon"></i><span class="nav-label"><?=h($op['name'])?></span></a>
    <?php endforeach; ?>
  </nav>
  <div class="sidebar-footer">
    <div class="sidebar-footer-user">
      <div class="sfu-id">
        <div class="sidebar-avatar"><i class="bi bi-person-fill"></i></div>
        <div style="min-width:0;">
          <div class="sidebar-username"><?=h(!empty($_SESSION['admin_fullname']) ? $_SESSION['admin_fullname'] : $_SESSION['username'])?></div>
          <div class="sidebar-role"><?=!empty($_SESSION['is_admin']) ? 'Super-administrateur' : 'Administrateur'?></div>
        </div>
      </div>
      <span class="theme-toggle" onclick="toggleTheme()" title="Changer le thème" aria-label="Changer le thème" role="button" tabindex="0">
        <i class="bi bi-moon js-theme-icon"></i>
      </span>
    </div>
    <div class="sidebar-footer-actions">
      <a href="?page=refs&tab=admins" class="sidebar-footer-link"><i class="bi bi-gear"></i> Mon compte</a>
      <a href="?action=logout" class="sidebar-footer-link sidebar-footer-link-danger"><i class="bi bi-box-arrow-right"></i> Déconnexion</a>
    </div>
  </div>
</aside>

<main class="main">
  <div class="topbar">
    <button class="btn-hamburger" onclick="openSidebar()" aria-label="Ouvrir le menu"><i class="bi bi-list"></i></button>
    <span class="topbar-title"><?php
      // « Utilisateurs » a son propre menu : titre dédié quand on y accède
      if ($page === 'refs' && ($_GET['tab'] ?? 'agents') === 'agents') echo 'Utilisateurs';
      else echo h($pageTitles[$page] ?? 'Accueil');
    ?></span>
  </div>
  <?php $flashes=getFlashes(); if($flashes): ?><div style="padding:1rem 2rem 0"><?php foreach($flashes as $f): $isErr=($f['type']??'')==='error'; ?><div style="display:flex;align-items:center;gap:.6rem;padding:.85rem 1rem;border-radius:var(--radius);margin-bottom:1rem;box-shadow:var(--shadow);border:1px solid transparent;border-left-width:4px;<?=$isErr ? 'background:var(--danger-dim);color:var(--danger);border-left-color:var(--danger)' : 'background:var(--success-dim);color:var(--success);border-left-color:var(--success)'?>"><i class="bi bi-<?=$isErr?'exclamation-octagon-fill':'check-circle-fill'?>" style="flex-shrink:0;"></i><div><?=h($f['msg'])?></div></div><?php endforeach; ?></div><?php endif; ?>
  <div class="content"><?=$content?></div>
</main>
</div>

<div class="modal-overlay" id="modal-history">
  <div class="modal"><div class="modal-header"><h3><i class="bi bi-clock-history"></i> Historique des affectations</h3><button type="button" class="modal-close" onclick="closeModal('modal-history')"><i class="bi bi-x-lg"></i></button></div>
  <div style="padding:1.5rem;" id="history-content"></div>
  </div>
</div>

<div class="modal-overlay" id="modal-view-agent">
  <div class="modal modal-lg" style="max-width:900px">
    <div class="modal-header"><h3 id="agent-view-title"><i class="bi bi-person-vcard"></i> Fiche Utilisateur</h3><button type="button" class="modal-close" onclick="closeModal('modal-view-agent')"><i class="bi bi-x-lg"></i></button></div>
    <div id="agent-view-content" style="padding:1.5rem; max-height: 70vh; overflow-y:auto;"></div>
  </div>
</div>

<!-- Proposition de changement de statut (ligne → Active, matériel → Déployé) -->
<div class="modal-overlay" id="modal-status-proposal">
  <div class="modal" style="max-width:440px;">
    <div class="modal-header"><h3 id="sp-title"><i class="bi bi-arrow-up-circle"></i> Changer le statut ?</h3><button type="button" class="modal-close" onclick="statusProposalResolve('cancel')"><i class="bi bi-x-lg"></i></button></div>
    <div style="padding:1.5rem;">
      <div style="display:flex;gap:1rem;align-items:flex-start;">
        <div style="flex-shrink:0;width:44px;height:44px;border-radius:50%;background:var(--primary-dim);color:var(--primary);display:flex;align-items:center;justify-content:center;font-size:1.4rem;"><i id="sp-icon" class="bi bi-arrow-up-circle"></i></div>
        <p id="sp-message" style="color:var(--text2);line-height:1.6;margin:0;"></p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn-secondary" id="sp-keep" onclick="statusProposalResolve('keep')">Garder en stock</button>
        <button type="button" class="btn-primary" id="sp-activate" onclick="statusProposalResolve('activate')">Activer</button>
      </div>
    </div>
  </div>
</div>

<!-- Ajout rapide (+) : mini-formulaire générique, champs injectés par le JS -->
<div class="modal-overlay" id="modal-quickadd">
  <div class="modal" style="max-width:440px;">
    <div class="modal-header"><h3 id="qa-title"><i class="bi bi-plus-lg"></i> Ajout rapide</h3><button type="button" class="modal-close" onclick="closeModal('modal-quickadd')"><i class="bi bi-x-lg"></i></button></div>
    <div style="padding:1.5rem;">
      <div id="qa-fields" class="form-grid" style="grid-template-columns:1fr;"></div>
      <div id="qa-error" style="display:none;margin-top:1rem;padding:.7rem .9rem;border-radius:var(--radius-sm);background:var(--danger-dim);color:var(--danger);font-size:.85rem;"></div>
      <div class="modal-footer">
        <button type="button" class="btn-secondary" onclick="closeModal('modal-quickadd')">Annuler</button>
        <button type="button" class="btn-primary" id="qa-save" onclick="quickAddSave()">Enregistrer</button>
      </div>
    </div>
  </div>
</div>

<script>
// ── CSRF : Injection automatique dans tous les formulaires POST ─
// Évite d'avoir à modifier chaque formulaire manuellement
(function() {
    const token = <?= json_encode($CSRF_TOKEN) ?>;
    const tokenName = <?= json_encode(CSRF_TOKEN_NAME) ?>;
    function injectCsrf(root) {
        root.querySelectorAll('form[method="post"], form[method="POST"]').forEach(function(form) {
            if (!form.querySelector('input[name="' + tokenName + '"]')) {
                const inp = document.createElement('input');
                inp.type = 'hidden';
                inp.name = tokenName;
                inp.value = token;
                form.appendChild(inp);
            }
        });
    }
    // Injecter sur le DOM initial
    document.addEventListener('DOMContentLoaded', function() { injectCsrf(document); });

    // Observer les mutations DOM pour couvrir les contenus injectés dynamiquement
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(m) {
            m.addedNodes.forEach(function(n) {
                if (n.nodeType === 1) injectCsrf(n);
            });
        });
    });
    document.addEventListener('DOMContentLoaded', function() {
        observer.observe(document.body, { childList: true, subtree: true });
    });
})();

// THEME
function applyTheme(t){
  document.documentElement.setAttribute('data-theme',t==='dark'?'dark':'light');
  localStorage.setItem('pm_theme',t);
  // Icône Bootstrap Icons, comme Sentinelle : lune en clair (→ passer en
  // sombre), soleil en sombre (→ passer en clair).
  var cls = (t==='dark' ? 'bi bi-sun js-theme-icon' : 'bi bi-moon js-theme-icon');
  document.querySelectorAll('.js-theme-icon').forEach(function(icon){ icon.className = cls; });
}
function toggleTheme(){ applyTheme((localStorage.getItem('pm_theme')||'light')==='dark'?'light':'dark'); }
applyTheme(localStorage.getItem('pm_theme')||'light');

// Rafraîchissement inter-onglets : lorsqu'un bon est signé dans un autre onglet
// (page de signature), l'événement « storage » se déclenche ici et recharge la
// page pour refléter le nouveau statut (Historique, fiche agent, tableau de bord…).
window.addEventListener('storage', function(e){
  if (e.key === 'simcity_bon_signed') location.reload();
});

// COPIE DU LIEN DE SIGNATURE D'UN BON
function copySignLink(btn, url) {
    function fallback() { window.prompt('Copiez le lien de signature :', url); }
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(function() {
            var t = btn.textContent; btn.textContent = '✅';
            setTimeout(function(){ btn.textContent = t; }, 1800);
        }, fallback);
    } else { fallback(); }
}

// CHARGEMENT FICHE UTILISATEUR AJAX
let _currentAgentId = null;
async function viewAgent(id, name) {
    _currentAgentId = id;
    document.getElementById('agent-view-title').innerText = '👤 ' + name;
    openModal('modal-view-agent');
    document.getElementById('agent-view-content').innerHTML = '<div style="text-align:center;padding:2rem;color:var(--text3)">⏳ Chargement de la fiche...</div>';
    try {
        const res = await fetch('index.php?ajax_agent_details=' + id);
        document.getElementById('agent-view-content').innerHTML = await res.text();
    } catch(e) {
        document.getElementById('agent-view-content').innerHTML = '<div style="text-align:center;padding:2rem;color:var(--danger)">❌ Erreur lors du chargement.</div>';
    }
}

// Attribution rapide (ligne / matériel du stock) depuis la fiche, sans fermer la modale
async function quickAssign(form) {
    const btn = form.querySelector('button[type=submit]');
    if (btn) btn.disabled = true;
    try {
        const res = await fetch('index.php', { method: 'POST', body: new FormData(form) });
        const data = await res.json();
        if (!data.ok) alert(data.error || "L'attribution a échoué.");
    } catch(e) {
        alert("L'attribution a échoué. Rechargez la page et réessayez.");
    }
    if (_currentAgentId) {
        try {
            const res = await fetch('index.php?ajax_agent_details=' + _currentAgentId);
            document.getElementById('agent-view-content').innerHTML = await res.text();
        } catch(e) { if (btn) btn.disabled = false; }
    }
    return false;
}

// Rafraîchir la fiche ouverte quand on revient sur l'onglet (ex. : après avoir
// généré ou signé un bon dans un autre onglet) — remplacement silencieux, sans spinner.
window.addEventListener('focus', async function() {
    const m = document.getElementById('modal-view-agent');
    if (!m || !m.classList.contains('open') || !_currentAgentId) return;
    try {
        const res = await fetch('index.php?ajax_agent_details=' + _currentAgentId);
        document.getElementById('agent-view-content').innerHTML = await res.text();
    } catch(e) { /* silencieux : on garde l'affichage actuel */ }
});

// TRI DYNAMIQUE DES TABLEAUX
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.data-table').forEach(table => {
    const headers = table.querySelectorAll('thead th');
    const tbody = table.querySelector('tbody');

    // Tableau DÉJÀ trié côté serveur (en-têtes = liens ?sort=…) : ne pas y
    // superposer le tri JS. Il ne verrait que la page affichée — trier 50
    // lignes sur 350 donne un classement faux — et la réécriture de
    // l'innerHTML de l'en-tête détache le lien cliqué, ce qui annule la
    // navigation dans les navigateurs.
    if (table.querySelector('thead th a[href*="sort="]')) {
      headers.forEach(th => { th.style.cursor = 'default'; });
      return;
    }

    headers.forEach((th, index) => {
      // Ne pas rendre triable la colonne « Actions » ni la colonne de sélection
      // groupée (case « tout sélectionner ») : trier cette dernière recréerait
      // son innerHTML et détruirait la case à cocher en plein clic.
      if(th.textContent.trim() === 'Actions' || th.querySelector('input')) { th.style.cursor = 'default'; return; }
      th.title = 'Cliquez pour trier'; let sortOrder = 1;

      th.addEventListener('click', () => {
        const rows = Array.from(tbody.querySelectorAll('tr'));
        if (rows.length === 0 || rows[0].querySelector('.empty-cell')) return;

        sortOrder = sortOrder === 1 ? -1 : 1;
        // On ne réécrit pas le HTML des en-têtes contenant un champ (case de
        // sélection) : cela réinitialiserait la case.
        headers.forEach(h => { if(h.querySelector('input')) return; h.innerHTML = h.innerHTML.replace(' ↑', '').replace(' ↓', ''); h.classList.remove('sorted'); });
        th.innerHTML += sortOrder === 1 ? ' ↑' : ' ↓'; th.classList.add('sorted');

        rows.sort((a, b) => {
          let aVal = a.cells[index].textContent.trim(); let bVal = b.cells[index].textContent.trim();
          const dateReg = /^(\d{2})\/(\d{2})\/(\d{4})/;
          if (dateReg.test(aVal) && dateReg.test(bVal)) { aVal = aVal.replace(dateReg, '$3$2$1'); bVal = bVal.replace(dateReg, '$3$2$1'); }

          const numA = parseFloat(aVal.replace(/[^0-9.-]+/g,"")); const numB = parseFloat(bVal.replace(/[^0-9.-]+/g,""));
          if (!isNaN(numA) && !isNaN(numB) && /^[0-9\s€.,-]+$/.test(aVal) && /^[0-9\s€.,-]+$/.test(bVal)) return (numA - numB) * sortOrder;
          return aVal.localeCompare(bVal, 'fr', {numeric: true}) * sortOrder;
        });
        rows.forEach(row => tbody.appendChild(row));
      });
    });
  });
});

// BULK ACTIONS
function updateBulkBar(type) {
  const checked = document.querySelectorAll('.bulk-chk-' + type + ':checked');
  const bar = document.getElementById('bulk-bar-' + type);
  const countEl = document.getElementById('bulk-count-' + type);
  if (checked.length > 0) {
    bar.style.display = 'flex';
    countEl.textContent = checked.length + ' sélectionné(s)';
  } else {
    bar.style.display = 'none';
  }
  // Sync select-all checkbox
  const all = document.querySelectorAll('.bulk-chk-' + type);
  const allChk = document.getElementById('chk-all-' + type);
  if (allChk) allChk.indeterminate = (checked.length > 0 && checked.length < all.length);
  if (allChk) allChk.checked = (all.length > 0 && checked.length === all.length);
}
function toggleAllBulk(type, state) {
  document.querySelectorAll('.bulk-chk-' + type).forEach(c => {
    // Only toggle visible rows
    if (c.closest('tr').style.display !== 'none') c.checked = state;
  });
  updateBulkBar(type);
}
function clearBulk(type) {
  document.querySelectorAll('.bulk-chk-' + type).forEach(c => c.checked = false);
  const allChk = document.getElementById('chk-all-' + type);
  if (allChk) { allChk.checked = false; allChk.indeterminate = false; }
  updateBulkBar(type);
}
function submitBulk(type) {
  const action = document.querySelector('#bulk-form-' + type + ' select[name="bulk_action"]').value;
  if (!action) { alert('Veuillez choisir une action.'); return; }
  const checked = document.querySelectorAll('.bulk-chk-' + type + ':checked');
  if (!checked.length) { alert('Aucun élément sélectionné.'); return; }
  const label = action === 'archive' ? 'archiver' : 'restaurer';
  if (!confirm('Confirmer : ' + label + ' les ' + checked.length + ' élément(s) sélectionné(s) ?')) return;
  // Build hidden inputs for IDs
  const container = document.getElementById('bulk-ids-' + type);
  container.innerHTML = '';
  checked.forEach(c => {
    const inp = document.createElement('input');
    inp.type = 'hidden'; inp.name = 'bulk_ids[]'; inp.value = c.value;
    container.appendChild(inp);
  });
  document.getElementById('bulk-form-' + type).submit();
}
// Highlight selected rows
document.addEventListener('change', function(e) {
  if (e.target.classList.contains('bulk-chk-line') || e.target.classList.contains('bulk-chk-device')) {
    e.target.closest('tr').style.background = e.target.checked ? 'var(--primary-dim)' : '';
  }
});

function tableSearch(inp, tbodyId, countId) {
  const q = inp.value.trim().toLowerCase(); const qNoSpaces = q.replace(/\s+/g, '');
  // Requête entièrement numérique (n° de ligne, ICCID, IMEI... avec ou sans séparateurs) :
  // comparaison sur la seule suite de chiffres. Le découpage en mots serait trop lâche :
  // chaque paire de « 06 01 27 16 60 » matcherait un champ différent (PIN, PUK, IMEI, CF...).
  const numeric = /^[\d\s.\-]+$/.test(q) && /\d/.test(q);
  const qDigits = q.replace(/\D/g, '');
  const tbody = document.getElementById(tbodyId); const count = document.getElementById(countId);
  if (!tbody) return;
  const rows  = Array.from(tbody.querySelectorAll('tr')); const words = q.split(/\s+/).filter(Boolean);
  let visible = 0;

  rows.forEach(function(tr) {
    if (tr.querySelector('td.empty-cell')) return;
    const txt = tr.textContent.toLowerCase(); const txtNoSpaces = txt.replace(/\s+/g, '');
    let match;
    if (numeric) {
      match = txtNoSpaces.includes(qDigits);
    } else {
      const matchWords = (!words.length || words.every(function(w) { return txt.includes(w); }));
      const matchNoSpace = qNoSpaces.length > 0 && txtNoSpaces.includes(qNoSpaces);
      match = matchWords || matchNoSpace;
    }
    tr.style.display = match ? '' : 'none';
    if (match) visible++;
  });

  // État vide DANS le tableau : quand la recherche masque toutes les lignes,
  // un tableau réduit à ses seuls en-têtes semble cassé — on affiche une
  // ligne explicite (créée à la volée, réutilisée ensuite).
  let emptyRow = tbody.querySelector('tr.search-empty');
  if (q && visible === 0 && rows.length) {
    if (!emptyRow) {
      emptyRow = document.createElement('tr');
      emptyRow.className = 'search-empty';
      const td = document.createElement('td');
      td.className = 'empty-cell';
      td.colSpan = (tbody.closest('table')?.querySelectorAll('thead th').length) || 12;
      emptyRow.appendChild(td);
      tbody.appendChild(emptyRow);
    }
    emptyRow.firstChild.textContent = 'Aucune ligne ne correspond à « ' + inp.value.trim() + ' »';
    emptyRow.style.display = '';
  } else if (emptyRow) {
    emptyRow.style.display = 'none';
  }

  if (count) {
    if (!q) count.textContent = '';
    else if (visible === 0) count.textContent = 'Aucun résultat.';
    else count.textContent = visible + ' résultat(s) trouvé(s)';
  }
}

// Filtrage par clic sur une cellule (ex. service dans la liste des utilisateurs) :
// remplit la barre de recherche de la page avec la valeur cliquée.
document.addEventListener('click', function(e) {
  const cell = e.target.closest('[data-refs-filter]');
  if (!cell) return;
  const inp = document.querySelector('.search-bar input:not(#dash-search)');
  if (!inp) return;
  inp.value = cell.dataset.refsFilter;
  inp.dispatchEvent(new Event('input'));
  inp.scrollIntoView({behavior:'smooth', block:'center'});
});

// AUTO-FILTRAGE DEPUIS LA RECHERCHE GLOBALE
window.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const q = params.get('q');
  if (q) {
    const searchInputs = document.querySelectorAll('.search-bar input:not(#dash-search)');
    searchInputs.forEach(inp => { inp.value = q; inp.dispatchEvent(new Event('input')); });
  }
});

// MODALES
function openModal(id){ 
  const e=document.getElementById(id); 
  if(e){
    e.classList.add('open');
    document.body.style.overflow='hidden';
    // Réinitialise l'état téléphone perso si c'est le modal d'ajout de ligne
    if(id === 'modal-add-line') {
      const chk = document.getElementById('add-personal_device');
      if(chk) { chk.checked = false; togglePersonalDevice('add'); }
      const chkSv = document.getElementById('add-sim_vierge');
      if(chkSv) { chkSv.checked = false; toggleSimVierge('add'); }
      const chkEsim = document.getElementById('add-esim');
      if(chkEsim) { chkEsim.checked = false; toggleEsim('add'); }
    }
  }
}
function closeModal(id){ const e=document.getElementById(id); if(e){e.classList.remove('open');document.body.style.overflow='';} }
document.querySelectorAll('.modal-overlay').forEach(o=>o.addEventListener('click',e=>{if(e.target===o)closeModal(o.id)}));

// ── Ajout rapide (+) : crée une entité liée sans quitter le formulaire ──
const QA_CSRF = { name: <?= json_encode(CSRF_TOKEN_NAME) ?>, token: <?= json_encode($CSRF_TOKEN) ?> };
<?php
// Listes pour les sélecteurs des modales d'ajout rapide (mêmes choix que les
// formulaires complets des référentiels). try/catch : tables absentes pendant
// une installation en cours.
$qaSvcOpts = $qaOpOpts = [];
try {
    foreach ($pdo->query("SELECT id,name FROM services ORDER BY name") as $r)  $qaSvcOpts[] = ['value'=>(string)$r['id'],'label'=>$r['name']];
    foreach ($pdo->query("SELECT id,name FROM operators ORDER BY name") as $r) $qaOpOpts[]  = ['value'=>(string)$r['id'],'label'=>$r['name']];
} catch (Throwable $e) { /* base pas encore prête */ }
?>
// Chaque modale « + » reprend l'intégralité des champs du formulaire complet
// du référentiel correspondant : rien à ressaisir après coup.
const QA_SERVICES  = <?= json_encode($qaSvcOpts) ?>;
const QA_OPERATORS = <?= json_encode($qaOpOpts) ?>;
const QA_CONFIG = {
  service:  { title:'Ajouter un service',  icon:'building',  fields:[
    {name:'name',label:'Nom du service',required:true},{name:'direction',label:'Direction'},
    {name:'chef_name',label:'Chef de service (visa)',adEmail:'chef_email'},{name:'chef_email',label:'E-mail du chef de service'},
    {name:'dga_name',label:'D.G.A. de secteur (visa)',adEmail:'dga_email'},{name:'dga_email',label:'E-mail du D.G.A.'},
    {name:'notes',label:'Notes',type:'textarea'}] },
  model:    { title:'Ajouter un modèle',   icon:'phone',     fields:[{name:'brand',label:'Marque',required:true},{name:'name',label:'Modèle',required:true},{name:'category',label:'Catégorie',type:'select',options:['Smartphone','Tablette','Clé 4G','Modem','Autre']}] },
  agent:    { title:'Ajouter un utilisateur', icon:'person', fields:[
    {type:'adlookup',label:'Rechercher dans l\'annuaire (AD)'},
    {name:'first_name',label:'Prénom'},{name:'last_name',label:'Nom',required:true},
    {name:'fonction',label:'Fonction'},{name:'email',label:'E-mail'},
    {name:'service_id',label:'Service / Direction',type:'select',options:QA_SERVICES,emptyLabel:'-- Aucun --'}] },
  plan:     { title:'Ajouter un forfait',  icon:'globe2',    fields:[
    {name:'name',label:'Nom du forfait',required:true},{name:'data_limit',label:'Enveloppe data (ex : 100 Go)'},
    {name:'operator_id',label:'Opérateur',type:'select',options:QA_OPERATORS,emptyLabel:'-- Aucun --'},
    {name:'notes',label:'Notes',type:'textarea'}] },
  billing:  { title:'Ajouter un compte de facturation', icon:'cash-coin', fields:[
    {name:'account_number',label:'N° de compte',required:true},{name:'name',label:'Nom / Entité'},
    {name:'notes',label:'Notes',type:'textarea'}] },
  operator: { title:'Ajouter un opérateur',icon:'broadcast', fields:[
    {name:'name',label:"Nom de l'opérateur",required:true},{name:'website',label:'Site web'},
    {name:'notes',label:'Notes',type:'textarea'}] },
};
let _qaEntity=null, _qaTarget=null;
// Autocomplétion annuaire générique pour les modales d'ajout rapide :
// interroge ajax_request_lookup (AD + référentiel local), affiche les
// suggestions sous le champ et appelle onPick(personne) à la sélection.
function qaBindLookup(inp, onPick){
  const box = inp.parentElement.querySelector('.adp-box');
  const esc = s => { const d=document.createElement('div'); d.textContent=s==null?'':s; return d.innerHTML; };
  inp.addEventListener('input', () => {
    const q = inp.value.trim();
    clearTimeout(inp._t);
    if(q.length < 2){ box.style.display='none'; box.innerHTML=''; return; }
    inp._t = setTimeout(async () => {
      try {
        const r = await fetch('index.php?ajax_request_lookup=1&q='+encodeURIComponent(q));
        const items = await r.json();
        if(!Array.isArray(items) || !items.length){ box.style.display='none'; box.innerHTML=''; return; }
        box.innerHTML = items.map((p,i) =>
          '<div class="adp-item" data-i="'+i+'"><strong>'+esc(p.name)+'</strong>'
          + (p.source==='ad' ? ' <span style="color:var(--info);font-size:.7rem;">AD</span>' : '')
          + '<br><span class="muted" style="font-size:.75rem;">'+esc([p.fonction,p.email].filter(Boolean).join(' · '))+'</span></div>').join('');
        box.style.display='block';
        [...box.querySelectorAll('.adp-item')].forEach(el => el.addEventListener('mousedown', ev => {
          ev.preventDefault(); onPick(items[+el.dataset.i]);
          box.style.display='none'; box.innerHTML='';
        }));
      } catch(err){ box.style.display='none'; }
    }, 250);
  });
  inp.addEventListener('blur', () => setTimeout(() => { box.style.display='none'; }, 150));
}
function qaError(msg){ const b=document.getElementById('qa-error'); if(b){ b.textContent=msg||''; b.style.display=msg?'block':'none'; } }
function quickAddOpen(entity, targetSelectId, prefill){
  const cfg = QA_CONFIG[entity]; if(!cfg) return;
  _qaEntity = entity; _qaTarget = targetSelectId;
  document.getElementById('qa-title').innerHTML = '<i class="bi bi-'+(cfg.icon||'plus-lg')+'"></i> ' + cfg.title;
  qaError('');
  const wrap = document.getElementById('qa-fields');
  const esc = s => { const d=document.createElement('div'); d.textContent=s==null?'':s; return d.innerHTML; };
  wrap.innerHTML = cfg.fields.map(f => {
    const req = f.required ? ' <span style="color:var(--danger)">*</span>' : '';
    let input;
    if(f.type === 'select'){
      const opts = (f.emptyLabel ? '<option value="">'+esc(f.emptyLabel)+'</option>' : '')
        + f.options.map(o => typeof o === 'object'
            ? '<option value="'+esc(o.value)+'">'+esc(o.label)+'</option>'
            : '<option value="'+esc(o)+'">'+esc(o)+'</option>').join('');
      input = '<select data-qa="'+f.name+'">' + opts + '</select>';
    } else if(f.type === 'textarea'){
      input = '<textarea data-qa="'+f.name+'" rows="2"></textarea>';
    } else if(f.type === 'adlookup'){
      // Champ de recherche annuaire, non soumis : remplit les autres champs
      input = '<div style="position:relative;"><input type="text" data-adlookup="1" placeholder="🔎 Nom, prénom ou e-mail…" autocomplete="off"><div class="adp-box"></div></div>';
    } else if(f.adEmail){
      // Champ nom avec suggestion AD ; la sélection remplit aussi l'e-mail lié
      input = '<div style="position:relative;"><input type="text" data-qa="'+f.name+'" data-ad-email="'+f.adEmail+'"'+(f.required?' data-req="1"':'')+' autocomplete="off"><div class="adp-box"></div></div>';
    } else {
      input = '<input type="text" data-qa="'+f.name+'"'+(f.required?' data-req="1"':'')+'>';
    }
    return '<div class="form-group"><label>'+f.label+req+'</label>'+input+'</div>';
  }).join('');
  // Autocomplétion annuaire (AD + référentiel) sur les champs qui la déclarent
  wrap.querySelectorAll('input[data-ad-email]').forEach(inp => {
    qaBindLookup(inp, p => {
      inp.value = p.name || '';
      const e = wrap.querySelector('[data-qa="'+inp.getAttribute('data-ad-email')+'"]');
      if(e && p.email) e.value = p.email;
    });
  });
  wrap.querySelectorAll('input[data-adlookup]').forEach(inp => {
    qaBindLookup(inp, p => {
      const set = (k,v) => { const e = wrap.querySelector('[data-qa="'+k+'"]'); if(e && v) e.value = v; };
      set('first_name', p.first_name); set('last_name', p.last_name);
      set('email', p.email); set('fonction', p.fonction);
      inp.value = p.name || '';
    });
  });
  // Pré-remplissage (ex : nom saisi dans un sélecteur d'agent avant « Créer »)
  if(prefill){ Object.keys(prefill).forEach(k=>{ const f = wrap.querySelector('[data-qa="'+k+'"]'); if(f) f.value = prefill[k]; }); }
  openModal('modal-quickadd');
  const first = wrap.querySelector('[data-qa]'); if(first) setTimeout(()=>first.focus(), 50);
}
function quickAddSave(){
  qaError('');
  const wrap = document.getElementById('qa-fields');
  const inputs = [...wrap.querySelectorAll('[data-qa]')];
  const fd = new FormData();
  fd.append('_entity', _qaEntity);
  fd.append(QA_CSRF.name, QA_CSRF.token);
  let missing = false;
  inputs.forEach(inp => {
    const v = (inp.value||'').trim();
    if(inp.hasAttribute('data-req') && !v) missing = true;
    fd.append(inp.getAttribute('data-qa'), v);
  });
  if(missing){ qaError('Veuillez remplir les champs obligatoires.'); return; }
  const btn = document.getElementById('qa-save'); btn.disabled = true;
  fetch('index.php?ajax_quickadd=1', { method:'POST', body:fd })
    .then(r => r.json().catch(()=>({ok:false,error:'Réponse invalide du serveur.'})))
    .then(j => {
      btn.disabled = false;
      if(!j || !j.ok){ qaError((j&&j.error)||'Échec de la création.'); return; }
      const sel = document.getElementById(_qaTarget);
      if(sel){
        if(sel.tagName === 'SELECT'){
          const opt = document.createElement('option');
          opt.value = j.id; opt.textContent = j.label; opt.selected = true;
          sel.appendChild(opt);
        } else {
          // Cible = champ caché d'un sélecteur à autocomplétion (agent picker) :
          // on pose l'id et on affiche le nom dans le champ de recherche associé.
          sel.value = j.id;
          const vis = document.getElementById(_qaTarget.replace(/agent_id$/, 'agent_search'));
          if(vis) vis.value = j.label;
        }
        sel.dispatchEvent(new Event('change', {bubbles:true}));
      }
      closeModal('modal-quickadd');
    })
    .catch(()=>{ btn.disabled = false; qaError('Erreur réseau.'); });
}

// ── Autocomplétion annuaire (AD) dans la fiche utilisateur ──
// Réutilise l'endpoint public ajax_request_lookup (recherche AD + référentiel).
// Une sélection pré-remplit nom, prénom, e-mail et fonction (tout reste éditable).
function bindAgentAd(prefix){
  const search = document.getElementById(prefix+'-ad-search');
  if(!search) return;
  const box = document.getElementById(prefix+'-ad-suggest');
  const esc = s => { const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; };
  const hide = () => { box.style.display='none'; box.innerHTML=''; };
  let timer=null;
  search.addEventListener('input', ()=>{
    const q = search.value.trim(); clearTimeout(timer);
    if(q.length < 2){ hide(); return; }
    timer = setTimeout(async ()=>{
      try {
        const r = await fetch('index.php?ajax_request_lookup=1&q='+encodeURIComponent(q));
        const items = await r.json();
        if(!Array.isArray(items) || !items.length){ hide(); return; }
        box.innerHTML = items.map((p,i) =>
          '<div class="adp-item" data-i="'+i+'"><strong>'+esc(p.name)+'</strong>'
          + (p.in_tool ? ' <span style="color:var(--warning);font-size:.7rem;">déjà en base</span>' : '')
          + (p.source==='ad' ? ' <span style="color:var(--info);font-size:.7rem;">AD</span>' : '')
          + '<br><span class="muted" style="font-size:.75rem;">'+esc([p.fonction,p.email].filter(Boolean).join(' · '))+'</span></div>').join('');
        box.style.display='block';
        [...box.querySelectorAll('.adp-item')].forEach(el=>el.addEventListener('mousedown', e=>{
          e.preventDefault(); const p = items[+el.dataset.i];
          const set = (id,v)=>{ const f=document.getElementById(prefix+'-'+id); if(f && v!=null && v!=='') f.value=v; };
          document.getElementById(prefix+'-last_name').value = p.last_name || '';
          document.getElementById(prefix+'-first_name').value = p.first_name || '';
          document.getElementById(prefix+'-email').value = p.email || '';
          set('fonction', p.fonction);
          search.value = p.name || ''; hide();
        }));
      } catch(e){ hide(); }
    }, 250);
  });
  search.addEventListener('blur', ()=>setTimeout(hide,150));
}
// ── Réordonnancement des étapes de circuit par glisser-déposer ──
// L'ordre des <tr> fait foi à la soumission (champs step_*[]) : déplacer
// une ligne suffit. La poignée seule est saisissable, pour ne pas gêner
// la sélection de texte dans les champs.
function circuitSortable(table){
  const tb = table.tBodies[0];
  let dragging = null;
  tb.addEventListener('mousedown', e => {
    const h = e.target.closest('.drag-cell');
    if(h) h.closest('tr').draggable = true;
  });
  tb.addEventListener('dragstart', e => {
    const tr = e.target.closest('tr');
    if(!tr || !tr.draggable) return;
    dragging = tr; tr.style.opacity = '.45';
    e.dataTransfer.effectAllowed = 'move';
    try { e.dataTransfer.setData('text/plain', ''); } catch(_){}
  });
  tb.addEventListener('dragover', e => {
    if(!dragging) return;
    e.preventDefault();
    const tr = e.target.closest('tr');
    if(!tr || tr === dragging || tr.parentNode !== tb) return;
    const r = tr.getBoundingClientRect();
    tb.insertBefore(dragging, (e.clientY - r.top) > r.height / 2 ? tr.nextSibling : tr);
  });
  tb.addEventListener('dragend', () => {
    if(dragging){ dragging.style.opacity = ''; dragging.draggable = false; dragging = null; }
  });
}

document.addEventListener('DOMContentLoaded', ()=>{
  ['circuit-table','preset-table'].forEach(id => { const t = document.getElementById(id); if(t) circuitSortable(t); });
  bindAgentAd('add'); bindAgentAd('edit');
  // Recherche annuaire sur les valideurs (chef / DGA) des fiches service :
  // la sélection remplit le nom et l'e-mail associé.
  document.querySelectorAll('input[data-svc-ad]').forEach(inp => qaBindLookup(inp, p => {
    inp.value = p.name || '';
    const e = document.getElementById(inp.getAttribute('data-svc-ad'));
    if(e && p.email) e.value = p.email;
  }));
});

function openEditModal(data, ent){
  if(document.getElementById('edit-id-'+ent)) document.getElementById('edit-id-'+ent).value=data.id;
  Object.keys(data).forEach(k=>{
    const e = document.getElementById('edit-'+k);
    if(e) {
      if(e.type === 'checkbox') return; // les cases à cocher sont gérées séparément
      if(ent === 'admin' && k === 'password') e.value = '';
      else e.value = data[k] || '';
    }
  });
  // Réinitialise le champ de recherche annuaire (aide de saisie, non persistée)
  if(ent === 'agent'){ const s=document.getElementById('edit-ad-search'); if(s) s.value=''; const b=document.getElementById('edit-ad-suggest'); if(b){ b.style.display='none'; b.innerHTML=''; } }
  // Sélecteur d'utilisateur (lignes / matériels) : affiche le nom de l'agent affecté
  if(ent === 'line' || ent === 'device'){
    const as = document.getElementById('edit-agent_search');
    if(as) as.value = data.agent_id ? ((data.last_name||'')+' '+(data.first_name||'')).trim() : '';
  }
  // Restaure la case is_admin pour les comptes admin
  if(ent === 'admin') {
    const chkAdmin = document.getElementById('edit-is_admin');
    if(chkAdmin) chkAdmin.checked = (data.is_admin == 1 || data.is_admin === '1');
    // Compte Active Directory : le mot de passe est géré par l'AD, pas ici
    const pw = document.getElementById('edit-password');
    if(pw) {
      const isLdap = (data.auth_source === 'ldap');
      pw.disabled = isLdap;
      pw.placeholder = isLdap ? 'Compte Active Directory — géré par l\'AD' : '';
      if(isLdap) pw.value = '';
    }
  }
  // Restaure la case téléphone perso pour les lignes
  if(ent === 'line') {
    const chk = document.getElementById('edit-personal_device');
    if(chk) { chk.checked = (data.personal_device == 1 || data.personal_device === '1'); togglePersonalDevice('edit'); }
    const chkSv = document.getElementById('edit-sim_vierge');
    if(chkSv) { chkSv.checked = (data.sim_vierge == 1 || data.sim_vierge === '1'); toggleSimVierge('edit'); }
    const chkEsim = document.getElementById('edit-esim');
    if(chkEsim) { chkEsim.checked = (data.esim == 1 || data.esim === '1'); toggleEsim('edit'); }
    // Si la ligne a déjà un téléphone (Deployed), il n'est pas dans le dropdown (filtré sur Stock).
    // On l'ajoute dynamiquement pour qu'il soit sélectionnable et ne soit pas remis en stock à chaque édition.
    const devSel = document.getElementById('edit-device_id');
    if(devSel && data.device_id) {
      const exists = Array.from(devSel.options).some(o => o.value == data.device_id);
      if(!exists) {
        const label = '(Actuellement assigné) ' + (data.brand||'') + ' ' + (data.model_name||'') + ' — S/N: ' + (data.serial_number || data.imei || data.device_id);
        devSel.add(new Option(label, data.device_id));
      }
      devSel.value = data.device_id;
    }
  }
  openModal('modal-edit-'+ent);
}

function toggleEsim(act) {
  const chk   = document.getElementById(act + '-esim');
  const fEid  = document.getElementById(act + '-esim-fields');
  const fCode = document.getElementById(act + '-esim-code');
  if (!chk) return;
  const on = chk.checked;
  if (fEid)  fEid.style.display  = on ? '' : 'none';
  if (fCode) fCode.style.display = on ? '' : 'none';
}
function toggleSimVierge(act) {
  const chk       = document.getElementById(act + '-sim_vierge');
  const wrapper   = document.getElementById(act + '-phone-wrapper');
  const inp       = document.getElementById(act + '-phone_number');
  const statusWrap = document.getElementById(act + '-status-wrapper');
  const statusSel = document.getElementById(act + '-status');
  if (!chk || !wrapper) return;
  if (chk.checked) {
    wrapper.style.opacity    = '.4';
    wrapper.style.pointerEvents = 'none';
    if (inp) inp.value = '';
    if (statusWrap) { statusWrap.style.opacity = '.4'; statusWrap.style.pointerEvents = 'none'; }
    if (statusSel)  { statusSel.value = 'Stock'; }
  } else {
    wrapper.style.opacity    = '1';
    wrapper.style.pointerEvents = '';
    if (statusWrap) { statusWrap.style.opacity = '1'; statusWrap.style.pointerEvents = ''; }
  }
}

// ── Proposition de changement de statut (belle modale, pas de confirm()) ──
let _spResolve = null;
function openStatusProposal(cfg) {
  document.getElementById('sp-icon').className = 'bi bi-' + (cfg.icon || 'arrow-up-circle');
  document.getElementById('sp-title').innerHTML = '<i class="bi bi-' + (cfg.icon || 'arrow-up-circle') + '"></i> ' + cfg.title;
  document.getElementById('sp-message').innerHTML = cfg.message;
  document.getElementById('sp-keep').textContent = cfg.keepLabel;
  document.getElementById('sp-activate').innerHTML = '<i class="bi bi-check-lg"></i> ' + cfg.activateLabel;
  openModal('modal-status-proposal');
  return new Promise(res => { _spResolve = res; });
}
function statusProposalResolve(choice) {
  closeModal('modal-status-proposal');
  const r = _spResolve; _spResolve = null;
  if (r) r(choice);
}
// À la soumission, si un utilisateur est affecté mais le matériel/la ligne est
// resté(e) « En Stock » → proposer le passage en Active / Déployé via la modale.
// La validation HTML5 s'est déjà exécutée (l'événement submit vient de passer),
// donc un form.submit() ultérieur est sûr.
function statusFormCheck(act, cfg) {
  const agentSel  = document.getElementById(act + '-agent_id');
  const statusSel = document.getElementById(act + '-status');
  if (!(agentSel && statusSel && agentSel.value !== '' && statusSel.value === 'Stock')) return true;
  const form = statusSel.closest('form');
  openStatusProposal(cfg).then(choice => {
    if (choice === 'cancel') return;                       // fermeture : on n'enregistre pas
    if (choice === 'activate') statusSel.value = cfg.activeValue;
    form.submit();                                         // « garder » ou « activer » : on enregistre
  });
  return false;   // bloque la soumission initiale ; la modale décide de la suite
}
// ── Sélecteur d'utilisateur à autocomplétion (lignes, matériels, demandes) ──
// Remplace les <select> exhaustifs, inutilisables avec beaucoup d'agents :
// recherche le référentiel LOCAL (ajax_agent_search) et, si la personne n'y
// est pas, propose sa création (modale d'ajout rapide pré-remplie).
// Convention d'ids : {prefix}-agent_search (texte), {prefix}-agent_id (hidden),
// {prefix}-agent_suggest (boîte). Sélection → remplit aussi {prefix}-service_id.
function bindAgentPicker(prefix){
  const inp = document.getElementById(prefix+'-agent_search');
  if(!inp || inp._apBound) return;
  inp._apBound = true;
  const hid = document.getElementById(prefix+'-agent_id');
  const box = document.getElementById(prefix+'-agent_suggest');
  const esc = s => { const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; };
  const hide = () => { box.style.display='none'; box.innerHTML=''; };
  let timer=null;
  inp.addEventListener('input', ()=>{
    hid.value = '';                 // texte modifié : la sélection ne vaut plus
    const q = inp.value.trim();
    clearTimeout(timer);
    if(q.length < 2){ hide(); return; }
    timer = setTimeout(async ()=>{
      try {
        const r = await fetch('index.php?ajax_agent_search=1&q='+encodeURIComponent(q));
        const items = await r.json();
        let html = (Array.isArray(items) ? items : []).map((a,i)=>
          '<div class="adp-item" data-i="'+i+'"><strong>'+esc(a.name)+'</strong>'
          + '<br><span class="muted" style="font-size:.75rem;">'+esc([a.service_name, a.email].filter(Boolean).join(' · ') || 'Aucun service')+'</span></div>').join('');
        html += '<div class="adp-item adp-create"><span style="color:var(--primary);font-weight:600;">➕ Créer « '+esc(q)+' »</span>'
              + '<br><span class="muted" style="font-size:.75rem;">Nouvel utilisateur au référentiel</span></div>';
        box.innerHTML = html; box.style.display='block';
        [...box.querySelectorAll('.adp-item:not(.adp-create)')].forEach(el=>el.addEventListener('mousedown', e=>{
          e.preventDefault(); const a = items[+el.dataset.i];
          inp.value = a.name; hid.value = a.id; hide();
          // Auto-attribution du service de l'agent (modifiable ensuite)
          const svcSel = document.getElementById(prefix+'-service_id');
          if(svcSel && a.service_id) svcSel.value = a.service_id;
        }));
        box.querySelector('.adp-create').addEventListener('mousedown', e=>{
          e.preventDefault(); hide();
          // Découpe « Prénom Nom » (corrigeable dans la modale)
          const parts = q.split(/\s+/);
          const prefill = parts.length > 1
            ? {first_name: parts.slice(0, -1).join(' '), last_name: parts[parts.length-1]}
            : {last_name: q};
          quickAddOpen('agent', prefix+'-agent_id', prefill);
        });
      } catch(e){ hide(); }
    }, 250);
  });
  inp.addEventListener('blur', ()=>setTimeout(()=>{
    hide();
    if(hid.value === '') inp.value = '';   // pas de sélection : champ vidé (= aucun agent)
  }, 180));
}
document.addEventListener('DOMContentLoaded', ()=>{ ['add','edit','reqlink'].forEach(bindAgentPicker); });
function lineFormCheck(act) {
  const simVierge = document.getElementById(act + '-sim_vierge');
  if (simVierge && simVierge.checked) return true;   // SIM vierge : reste en stock
  return statusFormCheck(act, {
    icon: 'sim', activeValue: 'Active',
    title: 'Activer la ligne ?',
    message: "Cette ligne est affectée à un utilisateur mais son statut est encore <strong>« En Stock (non activée) »</strong>.<br><br>Souhaitez-vous la passer en <strong>« Active »</strong> ?",
    keepLabel: 'Garder en stock', activateLabel: 'Activer la ligne'
  });
}
function deviceFormCheck(act) {
  return statusFormCheck(act, {
    icon: 'phone', activeValue: 'Deployed',
    title: 'Déployer le matériel ?',
    message: "Ce matériel est affecté à un utilisateur mais son statut est encore <strong>« En Stock »</strong>.<br><br>Souhaitez-vous le passer en <strong>« Déployé »</strong> ?",
    keepLabel: 'Garder en stock', activateLabel: 'Déployer le matériel'
  });
}

function togglePersonalDevice(act) {
  const chk     = document.getElementById(act + '-personal_device');
  const wrapper = document.getElementById(act + '-device-wrapper');
  const sel     = document.getElementById(act + '-device_id');
  if (!chk || !wrapper) return;
  if (chk.checked) {
    wrapper.style.opacity = '.4';
    wrapper.style.pointerEvents = 'none';
    if (sel) sel.value = '';
  } else {
    wrapper.style.opacity = '1';
    wrapper.style.pointerEvents = '';
  }
}

function showHistory(data) {
    const c = document.getElementById('history-content');
    if (!data || !data.length) { c.innerHTML = '<span style="color:var(--text3)">Aucun historique disponible.</span>'; }
    else {
        c.innerHTML = '<ul style="list-style:none;padding:0;margin:0;">' + data.map(h => {
            let badge = h.agent_name ? `<span class="badge badge-muted" style="margin-left:8px;font-size:0.7rem"><i class="bi bi-person"></i> ${h.agent_name}</span>` : '';
            return `<li style="padding-bottom:10px;margin-bottom:10px;border-bottom:1px solid var(--border)">
                <strong style="color:var(--primary);font-size:.8rem">${h.dt}</strong>${badge}<br>
                <span style="font-size:.9rem">${h.action_desc}</span><br>
                <span style="font-size:.7rem; color:var(--text3);">Par : ${h.author || 'Système'}</span>
            </li>`;
        }).join('') + '</ul>';
    }
    openModal('modal-history');
}

function openSidebar(){ document.getElementById('sidebar').classList.add('open'); document.getElementById('sidebar-overlay').classList.add('open'); }
function closeSidebar(){ document.getElementById('sidebar').classList.remove('open'); document.getElementById('sidebar-overlay').classList.remove('open'); }

// ARCHIVE MODALS
function openArchiveDevice(id, lineId, lineLabel) {
  document.getElementById('archive-device-id').value = id;
  // Section ligne associée
  const sec = document.getElementById('archive-device-line-section');
  const lbl = document.getElementById('archive-device-line-label');
  const lid = document.getElementById('archive-device-line-id');
  const chk = document.getElementById('archive-device-also-line');
  if (sec) {
    if (lineId) {
      sec.style.display = '';
      if (lbl) lbl.textContent = lineLabel || '';
      if (lid) lid.value = lineId;
    } else {
      sec.style.display = 'none';
      if (lid) lid.value = '';
    }
    if (chk) chk.checked = false;
  }
  // Reset form
  const form = document.querySelector('#modal-archive-device form');
  if (form) { form.querySelector('select[name="archive_reason"]').value = ''; const ta = form.querySelector('textarea'); if(ta) ta.value = ''; }
  openModal('modal-archive-device');
}
function openArchiveLine(id, deviceId, deviceLabel) {
  document.getElementById('archive-line-id').value = id;
  // Section téléphone associé
  const sec = document.getElementById('archive-line-device-section');
  const lbl = document.getElementById('archive-line-device-label');
  const did = document.getElementById('archive-line-device-id');
  const chk = document.getElementById('archive-line-also-device');
  if (sec) {
    if (deviceId) {
      sec.style.display = '';
      if (lbl) lbl.textContent = deviceLabel || '';
      if (did) did.value = deviceId;
    } else {
      sec.style.display = 'none';
      if (did) did.value = '';
    }
    if (chk) chk.checked = false;
  }
  // Reset form
  const form = document.querySelector('#modal-archive-line form');
  if (form) { form.querySelector('select[name="archive_reason"]').value = ''; const ta = form.querySelector('textarea'); if(ta) ta.value = ''; }
  openModal('modal-archive-line');
}

// SIM SWAP
function openSimSwap(lineId, phone, iccid, isEsim, eid) {
  document.getElementById('swap-line-id').value   = lineId;
  document.getElementById('swap-stock-sim-id').value = '';
  document.getElementById('swap-phone').textContent = phone ? phone.replace(/(\d{2})(?=\d)/g,'$1 ').trim() : 'Sans numéro';
  document.getElementById('swap-old-iccid').textContent         = iccid || '—';
  document.getElementById('swap-old-iccid-confirm').textContent = iccid || '—';
  document.getElementById('swap-new-iccid').value = '';
  document.getElementById('swap-new-pin').value   = '';
  document.getElementById('swap-new-puk').value   = '';
  const stockSel = document.getElementById('swap-sim-stock');
  if (stockSel) { stockSel.value = ''; fillSwapFromStock(stockSel); }
  // Champs eSIM : afficher si c'est une eSIM
  const eidRow  = document.getElementById('swap-eid-row');
  const codeRow = document.getElementById('swap-code-row');
  const newEid  = document.getElementById('swap-new-eid');
  const newCode = document.getElementById('swap-new-code');
  if (eidRow)  eidRow.style.display  = isEsim ? '' : 'none';
  if (codeRow) codeRow.style.display = isEsim ? '' : 'none';
  if (newEid)  newEid.value  = '';
  if (newCode) newCode.value = '';
  // Badge eSIM dans le récap
  const phoneBadge = document.getElementById('swap-esim-badge');
  if (phoneBadge) phoneBadge.style.display = isEsim ? 'inline' : 'none';
  document.getElementById('sim-history-panel').style.display = 'none';
  document.getElementById('sim-history-panel').innerHTML = '';
  openModal('modal-sim-swap');
  window._swapLineId = lineId;
}
function fillSwapFromStock(sel) {
  const opt = sel.options[sel.selectedIndex];
  const iccidRow = document.getElementById('swap-iccid-row');
  const sepRow   = document.getElementById('swap-manual-iccid-sep');
  const iccidInp = document.getElementById('swap-new-iccid');

  if (opt.value !== '') {
    // SIM du stock sélectionnée — remplir les champs automatiquement
    iccidInp.value = opt.value;
    document.getElementById('swap-new-pin').value       = opt.dataset.pin || '';
    document.getElementById('swap-new-puk').value       = opt.dataset.puk || '';
    document.getElementById('swap-stock-sim-id').value  = opt.dataset.id || '';
    // Masquer le champ ICCID et le séparateur (déjà rempli depuis le stock)
    iccidInp.required = false;
    if (iccidRow)  iccidRow.style.display  = 'none';
    if (sepRow)    sepRow.style.display    = 'none';
  } else {
    // Pas de sélection — vider et afficher les champs manuels
    iccidInp.value = '';
    document.getElementById('swap-new-pin').value      = '';
    document.getElementById('swap-new-puk').value      = '';
    document.getElementById('swap-stock-sim-id').value = '';
    iccidInp.required = true;
    if (iccidRow)  iccidRow.style.display  = '';
    if (sepRow)    sepRow.style.display    = '';
  }

  // Afficher les champs eSIM si la SIM sélectionnée est une eSIM
  const isEsim = opt.dataset.esim === '1';
  const eidRow  = document.getElementById('swap-eid-row');
  const codeRow = document.getElementById('swap-code-row');
  const badge   = document.getElementById('swap-esim-badge');
  if (eidRow)  eidRow.style.display  = isEsim ? '' : 'none';
  if (codeRow) codeRow.style.display = isEsim ? '' : 'none';
  if (badge)   badge.style.display   = isEsim ? 'inline' : 'none';
}
async function loadSimHistory() {
  const panel = document.getElementById('sim-history-panel');
  panel.innerHTML = '<span style="color:var(--text3);font-size:.85rem;">⏳ Chargement...</span>';
  panel.style.display = 'block';
  try {
    const res  = await fetch('index.php?ajax_sim_history=' + window._swapLineId);
    const rows = await res.json();
    if (!rows.length) { panel.innerHTML = '<span style="color:var(--text3);font-size:.85rem;">Aucun changement de SIM antérieur.</span>'; return; }
    panel.innerHTML = '<table style="width:100%;border-collapse:collapse;font-size:.82rem;">'
      + '<thead><tr style="color:var(--text3);border-bottom:1px solid var(--border);">'
      + '<th style="padding:4px 8px;text-align:left;">Date</th>'
      + '<th style="padding:4px 8px;text-align:left;">Ancien IMEI/ICCID</th>'
      + '<th style="padding:4px 8px;text-align:left;">Nouvel IMEI/ICCID</th>'
      + '<th style="padding:4px 8px;text-align:left;">Motif</th>'
      + '<th style="padding:4px 8px;text-align:left;">Par</th>'
      + '</tr></thead><tbody>'
      + rows.map(r => `<tr style="border-bottom:1px solid var(--border);">
          <td style="padding:5px 8px;color:var(--text2);">${r.dt}</td>
          <td style="padding:5px 8px;font-family:monospace;color:var(--warning);">${r.old_iccid||'—'}</td>
          <td style="padding:5px 8px;font-family:monospace;color:var(--success);">${r.new_iccid||'—'}</td>
          <td style="padding:5px 8px;">${r.reason||'—'}</td>
          <td style="padding:5px 8px;color:var(--text2);">${r.author||'—'}</td>
        </tr>`).join('')
      + '</tbody></table>';
  } catch(e) { panel.innerHTML = '<span style="color:var(--danger);font-size:.85rem;">❌ Erreur de chargement.</span>'; }
}

<?php if(!empty($_GET['open'])): ?>window.addEventListener('DOMContentLoaded', () => {
  openModal(<?=json_encode((string)$_GET['open'])?>);
  <?php if(!empty($_GET['phone'])): /* Création préremplie depuis le rapprochement des factures */ ?>
  const ph = document.getElementById('add-phone_number');
  if (ph) { ph.value = <?=json_encode(formatPhone(simcity_phone_canon((string)$_GET['phone'])))?>; ph.focus(); }
  <?php endif; ?>
});<?php endif; ?>
<?php if(!empty($_GET['open_line'])): ?>
// Ouverture directe de la fiche d'une ligne (lien depuis le tableau de bord)
window.addEventListener('DOMContentLoaded', () => {
  const btn = document.querySelector('.btn-edit[data-line-id="<?=(int)$_GET['open_line']?>"]');
  if (btn) { btn.click(); btn.closest('tr')?.scrollIntoView({block:'center'}); }
});
<?php endif; ?>
</script>
</body>
</html>