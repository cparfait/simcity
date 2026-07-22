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
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f8fafc;min-height:100vh;padding:1rem;}
.card{background:#fff;border-radius:16px;padding:1.5rem;max-width:500px;margin:0 auto;box-shadow:0 4px 20px rgba(0,0,0,.08);}
h2{font-size:1.2rem;color:#1e293b;margin-bottom:.25rem;}
.sub{color:#64748b;font-size:.85rem;margin-bottom:1.5rem;}
.info{background:#f1f5f9;border-radius:8px;padding:1rem;margin-bottom:1.25rem;font-size:.9rem;color:#334155;}
.info strong{display:block;color:#0f172a;font-size:1rem;margin-bottom:.25rem;}
label{display:block;font-size:.8rem;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:.4rem;}
input{width:100%;padding:.75rem;border:1px solid #e2e8f0;border-radius:8px;font-size:1rem;margin-bottom:1rem;}
input:focus{outline:none;border-color:#4f46e5;box-shadow:0 0 0 3px rgba(79,70,229,.25);}
.canvas-wrap{border:2px dashed #cbd5e1;border-radius:8px;background:#fafafa;margin-bottom:.75rem;position:relative;touch-action:none;}
canvas{display:block;width:100%;border-radius:8px;}
.canvas-hint{text-align:center;font-size:.75rem;color:#94a3b8;padding:.35rem;}
.btn-clear{background:none;border:1px solid #e2e8f0;border-radius:6px;padding:.45rem 1rem;font-size:.82rem;color:#64748b;cursor:pointer;margin-bottom:1rem;}
.btn-sign{width:100%;padding:1rem;background:#4f46e5;color:#fff;border:none;border-radius:10px;font-size:1.05rem;font-weight:600;cursor:pointer;box-shadow:0 1px 3px rgba(15,23,42,.12);}
.btn-sign:hover{background:#4338ca;}
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

// Gabarit d'e-mail commun aux demandes (aligné sur celui des bons)
function requestMailShell($title, $inner) {
    return '<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px;">'
         . '<h2 style="color:#4f46e5;">📱 SimCity — ' . $title . '</h2>'
         . $inner
         . '<hr style="border:0;border-top:1px solid #eee;margin:24px 0;"><p style="font-size:12px;color:#999;">Message automatique — merci de ne pas répondre.</p></div>';
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
    $url = baseUrl($pdo) . '?page=valider&token=' . $step['token'];
    $inner = '<p>Bonjour' . ($step['validator_name'] ? ' ' . h($step['validator_name']) : '') . ',</p>'
           . ($isReminder ? '<p style="color:#c2410c;"><strong>Rappel :</strong> cette demande attend votre avis depuis plusieurs jours.</p>' : '')
           . '<p>La demande de téléphone <strong>' . h($req['numero']) . '</strong> (' . h(requestTypeLabel($req['type'])) . ') pour <strong>' . h($req['agent_name']) . '</strong>'
           . ($req['service_name'] ? ' — service ' . h($req['service_name']) : '') . ' attend votre visa <strong>« ' . h($step['label']) . ' »</strong>.</p>'
           . '<p style="margin:28px 0;text-align:center;"><a href="' . h($url) . '" style="background:#4f46e5;color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:bold;">👁️ Examiner et viser la demande</a></p>'
           . '<p style="font-size:13px;color:#666;">Ou copiez ce lien dans votre navigateur :<br><a href="' . h($url) . '">' . h($url) . '</a></p>'
           . '<p style="font-size:13px;color:#666;">Aucun compte n\'est nécessaire : ce lien vous est personnel.</p>';
    $res = smtpSendMail($pdo, $step['validator_email'], ($isReminder ? 'Rappel — ' : '') . "Visa requis — Demande de téléphone {$req['numero']}", requestMailShell('Visa requis', $inner));
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
        requestSendStepEmail($pdo, $req, $next);
        return;
    }
    // Plus d'étape en attente : la demande est validée
    $pdo->prepare("UPDATE requests SET status='validee', current_step=0, closed_at=NOW() WHERE id=?")->execute([(int)$reqId]);
    $pdo->prepare("INSERT INTO history_logs (entity_type, entity_id, action_desc, agent_id, author) VALUES ('request', ?, ?, ?, 'Système')")
        ->execute([(int)$reqId, "✅ Demande {$req['numero']} validée — circuit de visas complet", $req['agent_id'] ?: null]);
    // Pas d'e-mail de suivi au demandeur à chaque étape : il consulte l'avancement
    // via son lien de suivi. Seule la boîte de base (DSI) est notifiée pour agir.
    $notify = trim(getSetting($pdo, 'request_notify_email', ''));
    if ($notify) {
        $adm = baseUrl($pdo) . '?page=requests&view=' . (int)$reqId;
        smtpSendMail($pdo, $notify, "Demande {$req['numero']} validée — à traiter",
            requestMailShell('Demande validée', '<p>La demande <strong>' . h($req['numero']) . '</strong> (' . h($req['agent_name']) . ') a terminé son circuit de validation.</p><p>Vous pouvez attribuer le matériel et générer le bon de remise.</p><p style="font-size:13px;color:#666;"><a href="' . h($adm) . '">Ouvrir la demande dans SimCity</a></p>'));
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

// URL web du logo affiché sur les pages publiques de demande.
// Priorité au logo paramétré (celui des bons PDF), sinon le logo de l'app.
function requestLogoUrl($pdo) {
    $logo = getSetting($pdo, 'pdf_logo_path', '');
    if ($logo && file_exists($logo)) {
        // pdf_logo_path est un chemin serveur relatif au webroot (ex. uploads/…)
        return str_replace('\\', '/', $logo);
    }
    return 'assets/logo.svg';
}

// CSS partagé des pages publiques « demandes » (autonome, mobile).
// Aligné sur le design Sentinelle / la page de connexion SimCity :
// IBM Plex Sans, dégradé navy→bleu, indigo + slate, cartes arrondies.
function requestPublicCss() {
    return ':root{--primary:#4f46e5;--primary-dark:#4338ca;--text:#334155;--text-strong:#0f172a;--text-muted:#64748b;--text-light:#94a3b8;--border:#e2e8f0;--border-strong:#cbd5e1;--bg-soft:#f1f5f9;--page:#eef2f7;--radius:10px;--radius-lg:14px;--font:\'IBM Plex Sans\',-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--font);background:var(--page);min-height:100vh;padding:2rem 1rem;color:var(--text);-webkit-font-smoothing:antialiased;letter-spacing:-.005em;}
.wrap{max-width:640px;margin:0 auto;}
.brand{text-align:center;margin-bottom:1.25rem;background:#fff;border:1px solid var(--border);border-radius:var(--radius-lg);padding:1.15rem;box-shadow:0 1px 3px rgba(15,23,42,.06),0 1px 2px rgba(15,23,42,.04);}
.brand img{height:50px;max-width:240px;object-fit:contain;vertical-align:middle;}
.card{background:#fff;border-radius:var(--radius-lg);border:1px solid var(--border);padding:2rem;margin:0 auto 1.25rem;box-shadow:0 1px 3px rgba(15,23,42,.06),0 1px 2px rgba(15,23,42,.04);}
.card-head{display:flex;align-items:center;gap:.75rem;margin-bottom:.35rem;}
.card-head .ico{width:42px;height:42px;flex-shrink:0;border-radius:11px;background:rgba(79,70,229,.1);color:var(--primary);display:flex;align-items:center;justify-content:center;font-size:1.35rem;}
h2{font-family:var(--font);font-size:1.3rem;font-weight:700;color:var(--text-strong);line-height:1.25;}
.sub{color:var(--text-muted);font-size:.88rem;line-height:1.5;margin-bottom:1.5rem;}
label{display:block;font-size:.74rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.03em;margin:1.1rem 0 .4rem;}
input[type=text],input[type=email],select,textarea{width:100%;padding:.7rem .85rem;border:1px solid var(--border-strong);border-radius:var(--radius);font-size:.95rem;font-family:inherit;background:#fff;color:var(--text);transition:border-color .18s ease,box-shadow .18s ease;}
input:hover:not(:focus),select:hover:not(:focus),textarea:hover:not(:focus){border-color:rgba(79,70,229,.5);}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(79,70,229,.28);}
    input::placeholder,textarea::placeholder{color:var(--text-light);opacity:.75;font-style:italic;}
textarea{resize:vertical;min-height:96px;line-height:1.5;}
.field-hint{font-size:.78rem;color:var(--text-light);margin-top:.35rem;}
.radio-row{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:.15rem;}
.radio-row label{display:inline-flex;align-items:center;gap:.45rem;text-transform:none;letter-spacing:0;font-weight:500;font-size:.9rem;color:var(--text);margin:0;padding:.5rem .9rem;border:1px solid var(--border-strong);border-radius:999px;cursor:pointer;transition:border-color .15s,background-color .15s;}
.radio-row label:hover{border-color:var(--primary);}
.radio-row input{accent-color:var(--primary);width:16px;height:16px;}
.radio-row input:checked+span,.radio-row label:has(input:checked){border-color:var(--primary);background:rgba(79,70,229,.07);color:var(--primary-dark);font-weight:600;}
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
            smtpSendMail($pdo, $email, "Vos demandes de téléphone — liens de suivi",
                requestMailShell('Vos liens de suivi', '<p>Voici les demandes de téléphone en cours associées à votre adresse et leur lien de suivi :</p>' . $items . '<p style="font-size:13px;color:#666;">Ces liens sont personnels — ne les partagez pas.</p>'));
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
            if ($notify) {
                $adm = baseUrl($pdo) . '?page=requests&view=' . $reqId;
                smtpSendMail($pdo, $notify, "Nouvelle demande de téléphone $numero — $agentName",
                    requestMailShell('Nouvelle demande', '<p>Une nouvelle demande de téléphone vient d\'être déposée :</p>'
                    . '<p><strong>' . h($numero) . '</strong> — ' . h(requestTypeLabel($type)) . '<br>Bénéficiaire : <strong>' . h($agentName) . '</strong>' . ($fonction ? ' (' . h($fonction) . ')' : '') . ($agentEmail ? '<br>E-mail : ' . h($agentEmail) : '') . '<br>Service : ' . h($svcRow['name']) . '<br>Demandeur : <strong>' . h($requesterName) . '</strong> (' . h($requesterEmail) . ')</p>'
                    . '<p style="margin:24px 0;text-align:center;"><a href="' . h($adm) . '" style="background:#4f46e5;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:bold;">Qualifier la demande</a></p>'));
            }
            // 2) Accusé de réception au demandeur (l'e-mail qu'il a saisi) : simple
            //    confirmation + lien de suivi. N'intervient pas dans le circuit.
            smtpSendMail($pdo, $requesterEmail, "Demande de téléphone $numero enregistrée",
                requestMailShell('Demande enregistrée', '<p>Bonjour,</p>'
                . '<p>Votre demande de téléphone <strong>' . h($numero) . '</strong> pour <strong>' . h($agentName) . '</strong> a bien été enregistrée.</p>'
                . '<p>Elle va être examinée par la DSI puis suivre le circuit de validation. Vous pouvez suivre son avancement à tout moment :</p>'
                . '<p style="margin:24px 0;text-align:center;"><a href="' . h($suivi) . '" style="background:#4f46e5;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:bold;">📍 Suivre ma demande</a></p>'));

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
<link rel="icon" type="image/svg+xml" href="assets/logo.svg">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
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
        <input type="text" name="requester_name" required placeholder="Prénom Nom" value="<?=h($_POST['requester_name'] ?? '')?>">
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
        <div class="field-hint" style="margin:-.2rem 0 .5rem;">🔎 Commencez à taper le nom : l'annuaire propose l'agent et pré-remplit ses coordonnées (modifiables).</div>
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
<link rel="icon" type="image/svg+xml" href="assets/logo.svg">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
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
                        if ($notify) {
                            $adm = baseUrl($pdo) . '?page=requests&view=' . (int)$req['id'];
                            smtpSendMail($pdo, $notify, "Demande {$req['numero']} refusée",
                                requestMailShell('Demande refusée', '<p>La demande <strong>' . h($req['numero']) . '</strong> (' . h($req['agent_name']) . ') a été refusée au visa « ' . h($step['label']) . ' »' . ($name ? ' par ' . h($name) : '') . '.</p><p>Avis : ' . h($avis) . '</p>'
                                . '<p style="font-size:13px;color:#666;"><a href="' . h($adm) . '">Ouvrir la demande dans SimCity</a></p>'));
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
<link rel="icon" type="image/svg+xml" href="assets/logo.svg">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
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
                <strong><?=h($s['label'])?></strong><?=$s['validator_name'] ? ' — ' . h($s['validator_name']) : ''?> <?=$isMe ? '<span style="color:#4f46e5;font-size:.78rem;">(vous)</span>' : ''?><br>
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
.toolbar button{padding:.5rem 1rem;border-radius:8px;border:1px solid #cbd5e1;background:#4f46e5;color:#fff;font-size:.85rem;cursor:pointer;font-weight:600;}
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
        $headers = "From: =?UTF-8?B?" . base64_encode($fromName) . "?= <$from>\r\n"
                 . "To: <$to>\r\n"
                 . "Subject: =?UTF-8?B?" . base64_encode($subject) . "?=\r\n"
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
        .btn{display:inline-block;margin-top:1rem;padding:.75rem 1.75rem;background:#4f46e5;color:#fff;border:none;border-radius:9px;font-size:.95rem;font-weight:600;cursor:pointer;}
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
                  <a href="'.htmlspecialchars($url).'" style="display:block;margin-top:3px;font-size:.75rem;color:#4f46e5;text-decoration:none;">Signer en ligne</a>';
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
        .toolbar button.tb-primary{background:#4f46e5;border-color:#4f46e5;color:#fff;}
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

// ─── 3c. TÉLÉCHARGEMENT D'UNE SAUVEGARDE STOCKÉE ──────────────
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
    <link rel="icon" type="image/svg+xml" href="assets/logo.svg">
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root{--primary:#4f46e5;--primary-dark:#4338ca;--card:#ffffff;--text:#334155;--text-strong:#0f172a;--text-light:#94a3b8;--border:#e2e8f0;--border-strong:#cbd5e1;--danger:#dc2626;--radius:7px;}
        .login-logo{height:56px;width:56px;object-fit:contain;display:block;margin:0 auto 8px;}
        body{background:linear-gradient(135deg,#0f172a 0%,#1e293b 55%,#1e3a6b 100%);color:var(--text);font-family:'IBM Plex Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:24px;box-sizing:border-box;}
        .login-box{background:var(--card);padding:36px 32px;border-radius:14px;border:1px solid var(--border);width:100%;max-width:400px;box-shadow:0 12px 28px rgba(15,23,42,.35),0 4px 10px rgba(15,23,42,.2);}
        h2{text-align:center;margin-top:0;font-size:1.6rem;font-weight:700;color:var(--text-strong);}
        label{font-size:.82rem;font-weight:600;color:var(--text);}
        input{width:100%;padding:9px 12px;margin-top:5px;background:#fff;border:1px solid var(--border-strong);border-radius:var(--radius);color:var(--text);font-family:inherit;font-size:.9rem;box-sizing:border-box;transition:border-color .18s ease,box-shadow .18s ease;}
        input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(79,70,229,.35);}
        input::placeholder{color:var(--text-light);opacity:.75;font-style:italic;}
        button{width:100%;padding:11px;background:var(--primary);color:#fff;border:1px solid var(--primary);border-radius:var(--radius);font-weight:600;font-size:.95rem;margin-top:1.5rem;cursor:pointer;transition:background-color .18s ease;}
        button:hover{background:var(--primary-dark);}
    </style></head>
    <body>
        <div class="login-box"><img src="assets/logo.svg" alt="SimCity" class="login-logo"><h2>SimCity</h2><p style="text-align:center;opacity:.7;margin-bottom:2rem;font-size:.9rem;">Gestion du Parc Mobile — DSI<?php if(ldap_auth_enabled()) echo '<br><span style="font-size:.78rem;color:var(--text-light);">Comptes locaux ou Active Directory</span>'; ?></p>
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
                $pdo->prepare("INSERT INTO services(name,direction,notes) VALUES(?,?,'')")->execute([$g('name'), $g('direction')]);
                $id = (int)$pdo->lastInsertId(); $label = $g('name'); break;
            case 'model':
                if ($g('brand') === '' || $g('name') === '') throw new Exception('Marque et modèle sont obligatoires.');
                $cat = $g('category') ?: 'Smartphone';
                $pdo->prepare("INSERT INTO models(brand,name,category) VALUES(?,?,?)")->execute([$g('brand'), $g('name'), $cat]);
                $id = (int)$pdo->lastInsertId(); $label = $g('brand').' '.$g('name'); break;
            case 'agent':
                if ($g('last_name') === '') throw new Exception('Le nom est obligatoire.');
                $fn = fmtFirstName($g('first_name')); $ln = fmtLastName($g('last_name'));
                $pdo->prepare("INSERT INTO agents(first_name,last_name,email,service_id) VALUES(?,?,?,?)")
                    ->execute([$fn, $ln, fmtEmail($g('email')), ($g('service_id') !== '' ? (int)$g('service_id') : null)]);
                $id = (int)$pdo->lastInsertId(); $label = trim($ln.' '.$fn); break;
            case 'plan':
                if ($g('name') === '') throw new Exception('Le nom du forfait est obligatoire.');
                $pdo->prepare("INSERT INTO plan_types(name,data_limit,notes,operator_id) VALUES(?,?,'',NULL)")->execute([$g('name'), $g('data_limit')]);
                $id = (int)$pdo->lastInsertId(); $label = $g('name'); break;
            case 'billing':
                if ($g('account_number') === '') throw new Exception('Le numéro de compte est obligatoire.');
                $pdo->prepare("INSERT INTO billing_accounts(account_number,name,notes) VALUES(?,?,'')")->execute([$g('account_number'), $g('name')]);
                $id = (int)$pdo->lastInsertId(); $label = trim($g('account_number').' '.($g('name') !== '' ? '— '.$g('name') : '')); break;
            case 'operator':
                if ($g('name') === '') throw new Exception('Le nom de l\'opérateur est obligatoire.');
                $pdo->prepare("INSERT INTO operators(name,website,notes) VALUES(?,'','')")->execute([$g('name')]);
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
    $stL = $pdo->prepare("SELECT l.id, l.phone_number, l.iccid, l.archived,
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
            'link'=>'?page=lines&tab='.($r['archived']?'archive':'active').'&q='.urlencode($r['phone_number']?:$r['iccid'])];
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
        $lr = $pdo->query("SELECT l.id, l.phone_number, l.iccid, l.archived,
            IFNULL(a.first_name,'') as fn, IFNULL(a.last_name,'') as ln
            FROM mobile_lines l LEFT JOIN agents a ON l.agent_id=a.id WHERE l.id=$lineId")->fetch();
        if (!$lr) continue;
        $num = $lr['phone_number'] ? formatPhone($lr['phone_number']) : 'SIM Vierge';
        $results[] = ['type'=>'Ligne','title'=>$num.($lr['archived']?' 🗄️':''),
            'subtitle'=>'📋 Trouvé via historique — Agent actuel : '.trim($lr['fn'].' '.$lr['ln']?:'Aucun'),
            'link'=>'?page=lines&tab='.($lr['archived']?'archive':'active').'&q='.urlencode($lr['phone_number']?:$lr['iccid'])];
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
        foreach($att as $a) echo "<li style='margin-bottom:5px;'><a href='{$a['file_path']}' target='_blank' style='color:var(--info); text-decoration:none;'>".h($a['file_name'])."</a></li>";
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
                } else {
                    $typeLbl = $b['type'] === 'remise' ? 'remise' : 'restitution';
                    $url     = baseUrl($pdo) . '?page=sign&token=' . $b['token'];
                    $expFmt  = $b['expires_at'] ? date('d/m/Y', strtotime($b['expires_at'])) : null;
                    $html = '<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px;">'
                          . '<h2 style="color:#4f46e5;">📱 SimCity — Signature requise</h2>'
                          . '<p>Bonjour ' . h($b['first_name']) . ',</p>'
                          . '<p>Le bon de <strong>' . $typeLbl . ' de matériel</strong> n° <strong>' . h($b['numero']) . '</strong> vous attend pour signature électronique.</p>'
                          . '<p style="margin:28px 0;text-align:center;"><a href="' . h($url) . '" style="background:#4f46e5;color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:bold;">✍️ Signer le bon</a></p>'
                          . '<p style="font-size:13px;color:#666;">Ou copiez ce lien dans votre navigateur :<br><a href="' . h($url) . '">' . h($url) . '</a></p>'
                          . ($expFmt ? '<p style="font-size:13px;color:#666;">Ce lien est valable jusqu\'au <strong>' . $expFmt . '</strong>.</p>' : '')
                          . '<hr style="border:0;border-top:1px solid #eee;margin:24px 0;"><p style="font-size:12px;color:#999;">Message automatique — merci de ne pas répondre.</p></div>';
                    $res = smtpSendMail($pdo, $b['email'], "Signature requise — Bon de $typeLbl {$b['numero']}", $html);
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
        } elseif ($ent === 'import') {
            // Importation CSV — super-admin uniquement (l'outil peut purger la base)
            if (empty($_SESSION['is_admin'])) {
                flash('error', 'Accès refusé — réservé aux super-administrateurs.');
            } elseif ($act !== 'run') {
                flash('error', 'Action inconnue.');
            } else {
                $purge = !empty($d['truncate']);
                $err   = simcity_import_validate($_FILES['file_data'] ?? []);
                if ($purge && ($d['confirm_purge'] ?? '') !== 'PURGER') {
                    flash('error', 'Tapez PURGER dans le champ de confirmation pour activer la purge.');
                } elseif ($err !== '') {
                    flash('error', $err);
                } else {
                    // L'import écrit beaucoup et la purge fait du DDL (auto-commit
                    // MySQL) : on sort de la transaction globale, comme la restauration.
                    if ($pdo->inTransaction()) $pdo->commit();
                    try {
                        // Filet de sécurité avant une purge : l'opération est irréversible.
                        $safety = '';
                        if ($purge) {
                            try { $safety = simcity_backup_to_disk($pdo); } catch (Throwable $e) { $safety = ''; }
                            simcity_import_purge($pdo);
                        }
                        $st = simcity_import_csv($pdo, $_FILES['file_data']['tmp_name']);
                        $resume = "{$st['lines']} ligne(s), {$st['devices']} matériel(s), {$st['agents']} utilisateur(s), "
                                . "{$st['services']} service(s), {$st['models']} modèle(s), {$st['plans']} forfait(s), "
                                . "{$st['operators']} opérateur(s), {$st['billings']} compte(s) de facturation";
                        $prefix = $purge
                            ? 'Base purgée' . ($safety !== '' ? " (sauvegarde de sécurité : $safety)" : '') . ', puis import terminé — '
                            : 'Import terminé — ';
                        flash('success', $prefix . $resume . '.');
                    } catch (Throwable $e) {
                        $detail = (defined('APP_DEBUG') && APP_DEBUG) ? ' — ' . $e->getMessage() : '';
                        flash('error', "L'importation a échoué$detail. Les lignes déjà traitées ont été conservées.");
                    }
                    header('Location: index.php?page=refs&tab=settings&sub=maintenance'); exit;
                }
            }
        } elseif ($ent === 'db_reset') {
            // Réinitialisation complète — super-admin uniquement
            if (empty($_SESSION['is_admin'])) { flash('error', 'Accès refusé.'); }
            elseif (($d['confirm_word'] ?? '') !== 'SUPPRIMER') { flash('error', 'Mot de confirmation incorrect.'); }
            else {
                // Le DROP TABLE (DDL) commite implicitement : on sort proprement de la transaction
                if ($pdo->inTransaction()) $pdo->commit();
                $pdo->exec("SET FOREIGN_KEY_CHECKS = 0");
                $pdo->exec("DROP TABLE IF EXISTS `request_steps`,`requests`,`bons`,`signatures`,`sign_tokens`,`sim_history`,`attachments`,`mobile_lines`,`devices`,`history_logs`,`agents`,`billing_accounts`,`plan_types`,`operators`,`models`,`services`,`settings`,`users`");
                $pdo->exec("SET FOREIGN_KEY_CHECKS = 1");
                session_destroy();
                header('Location: install.php'); exit;
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
        } elseif ($ent === 'smtp_test') {
            // Envoi d'un e-mail de test avec la configuration SMTP enregistrée
            $to = fmtEmail(trim($d['test_email'] ?? ''));
            if ($to === '' || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
                flash('error', "Renseignez une adresse e-mail de destination valide pour le test.");
            } else {
                $inner = '<p>Ceci est un e-mail de test envoyé depuis <strong>SimCity</strong> pour vérifier la configuration SMTP.</p>'
                       . '<p>Si vous recevez ce message, l\'envoi d\'e-mails fonctionne correctement.</p>';
                $res = smtpSendMail($pdo, $to, 'Test SMTP — SimCity', requestMailShell('E-mail de test', $inner));
                if ($res === true) {
                    flash('success', "📧 E-mail de test envoyé à $to — vérifiez la boîte de réception (et les indésirables).");
                } else {
                    flash('error', "Échec de l'envoi : $res");
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
                $pdo->prepare("INSERT INTO mobile_lines(phone_number,iccid,pin,puk,agent_id,billing_id,plan_id,service_id,device_id,activation_date,options_details,status,notes,personal_device,sim_vierge,esim,eid,activation_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")->execute([$phoneNum,S($d,'iccid'),S($d,'pin'),S($d,'puk'),$agt,$bil,$pln,$svc,$dev,NV($d,'activation_date'),S($d,'options_details'),$statusVal,S($d,'notes'),!empty($d['personal_device'])?1:0,$simVierge,$isEsim,NV($d,'eid'),NV($d,'activation_code')]);
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
                $pdo->prepare("UPDATE mobile_lines SET phone_number=?,iccid=?,pin=?,puk=?,agent_id=?,billing_id=?,plan_id=?,service_id=?,device_id=?,activation_date=?,options_details=?,status=?,notes=?,personal_device=?,sim_vierge=?,esim=?,eid=?,activation_code=? WHERE id=?")->execute([$phoneNum,S($d,'iccid'),S($d,'pin'),S($d,'puk'),$agt,$bil,$pln,$svc,$dev,NV($d,'activation_date'),S($d,'options_details'),$statusVal,S($d,'notes'),!empty($d['personal_device'])?1:0,$simVierge,$isEsim,NV($d,'eid'),NV($d,'activation_code'),$id]);
                
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
        if (!in_array($ent, ['attachment', 'bon', 'bulk', 'settings', 'admin', 'admin_signature', 'quick_assign', 'backup', 'import', 'ldap_test', 'smtp_test'])) flash('success', 'Opération réussie.');
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

$pageTitles = ['dashboard' => 'Tableau de bord', 'lines' => 'Gestion des Lignes & SIM', 'devices' => 'Parc Matériel & Terminaux', 'refs' => 'Référentiels & Utilisateurs', 'settings' => 'Paramètres', 'history' => 'Historique des Bons de Remise', 'requests' => 'Demandes de téléphone', 'stats' => 'Statistiques'];
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

      <?php if($cLinesStk <= $threshSim || $cDevStk <= $threshDevice || $alertSuspended > 0 || $bonsExpired > 0 || $bonsExpSoon > 0 || $reqToQualify > 0 || $reqValidated > 0 || $reqStalled > 0): ?>
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
              <li><strong>Lignes Suspendues :</strong> <span style="color:var(--warning);font-weight:bold;"><?=$alertSuspended?></span> ligne(s) hors service (pensez à les résilier si inactives).</li>
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
            <td><a href="?page=pdf_bon&bon_id=<?=$pb['id']?>" target="_blank" class="btn-icon" title="Voir / imprimer / envoyer" style="text-decoration:none;">🖨️</a></td>
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
          <thead><tr><th>N°</th><th>Agent</th><th>Service</th><th>Statut</th><th>Étape en cours</th><th></th></tr></thead>
          <tbody>
          <?php foreach($pendingReqs as $pr): [$plbl, $pcls] = requestStatusInfo($pr['status']);
              $stalled = ($pr['status'] === 'en_validation' && $pr['last_contact'] && strtotime($pr['last_contact']) < time() - $reqDays * 86400); ?>
          <tr>
            <td><a href="?page=requests&view=<?=$pr['id']?>" class="cell-link" style="font-family:var(--font-mono);font-weight:700;color:var(--primary);font-size:.85rem;"><?=h($pr['numero'])?></a></td>
            <td><strong><?=h($pr['agent_name'])?></strong></td>
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
              <div class="card-header" style="display:flex;align-items:center;justify-content:space-between;gap:1rem;"><span><i class="bi bi-phone"></i> Répartition par marque</span><a href="?page=devices" class="card-see-all">Voir tout <i class="bi bi-arrow-right"></i></a></div>
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
              <td><a href="?page=lines&open_line=<?=$r['line_id']?>" class="cell-link" style="font-family:var(--font-mono);color:var(--primary);font-size:1.05rem;font-weight:700;" title="Ouvrir la fiche de la ligne"><?=formatPhone($r['phone_number'])?></a></td>
              <td><?php if($r['agent_id']): ?><span class="cell-link" onclick="viewAgent(<?=$r['agent_id']?>, '<?=h(addslashes($r['first_name'].' '.$r['last_name']))?>')" title="Ouvrir la fiche utilisateur"><?=h($r['first_name'].' '.$r['last_name'])?></span><?php else: ?><span class="muted">—</span><?php endif; ?></td>
              <td><span class="badge badge-muted"><?=h($r['plan_type']?:'Non défini')?></span></td>
              <td><?=statusBadge($r['status'])?></td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>

    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Chaque graphique est indépendant : un canvas absent (aucune donnée →
        // message affiché à la place) n'empêche pas l'autre de s'initialiser.
        const elBrand = document.getElementById('chartBrand');
        if(elBrand){
            new Chart(elBrand, {
                type: 'doughnut',
                data: {
                    labels: <?php echo json_encode($brands); ?>,
                    datasets: [{
                        data: <?php echo json_encode($bCounts); ?>,
                        backgroundColor: ['#4f46e5', '#2563eb', '#7c3aed', '#d97706', '#059669', '#dc2626'],
                        borderWidth: 0
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } } }
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
                        backgroundColor: '#4f46e5',
                        borderRadius: 5
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, grid: { color: 'rgba(148,163,184,0.18)' }, ticks: { color: '#94a3b8' } }, x: { ticks: { color: '#94a3b8' } } }, plugins: { legend: { display: false } } }
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
    $isArchive = ($tab === 'archive'); $isStock = ($tab === 'stock');
    $where = "l.archived=" . ($isArchive ? "1" : "0");
    if ($isStock) $where .= " AND l.status='Stock'"; elseif (!$isArchive) $where .= " AND l.status!='Stock'";

    $lines = $pdo->query("SELECT l.id, l.phone_number, l.iccid, l.pin, l.puk, l.agent_id, l.billing_id, l.plan_id, l.service_id, l.device_id, l.activation_date, l.options_details, l.status, l.notes, l.archived, l.created_at, IFNULL(l.personal_device,0) as personal_device, IFNULL(l.sim_vierge,0) as sim_vierge, IFNULL(l.esim,0) as esim, l.eid, l.activation_code, a.first_name, a.last_name, s.name as service_name, b.account_number, p.name as plan_name, IFNULL(o.name,'') as operator_name, d.imei, d.serial_number, m.brand, m.name as model_name FROM mobile_lines l LEFT JOIN agents a ON l.agent_id=a.id LEFT JOIN services s ON l.service_id=s.id LEFT JOIN billing_accounts b ON l.billing_id=b.id LEFT JOIN plan_types p ON l.plan_id=p.id LEFT JOIN operators o ON p.operator_id=o.id LEFT JOIN devices d ON l.device_id=d.id LEFT JOIN models m ON d.model_id=m.id WHERE $where ORDER BY l.created_at DESC")->fetchAll();
    
    $agents = $pdo->query("SELECT id, first_name, last_name, service_id FROM agents WHERE archived=0 ORDER BY last_name, first_name")->fetchAll();
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
        <a href="?page=lines&tab=active" class="tab-btn <?=$tab==='active'?'active':''?>"><i class="bi bi-telephone"></i> Lignes Actives & Suspendues</a>
        <a href="?page=lines&tab=stock" class="tab-btn <?=$tab==='stock'?'active':''?>"><i class="bi bi-box-seam"></i> Stock (SIM Vierges)</a>
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
          <td><strong class="cell-link" onclick="this.closest('tr').querySelector('.btn-edit').click()" title="Ouvrir la fiche de la ligne" style="font-family:var(--font-mono);font-size:1.05rem;color:var(--primary)"><?= !empty($l['sim_vierge']) ? '<span style="color:var(--text3);font-style:italic;font-family:var(--font);">Sans numéro</span>' : formatPhone($l['phone_number']) ?></strong><br>
          <?php if(!empty($l['sim_vierge'])): ?><span class="badge" style="background:rgba(245,158,11,.15);color:var(--warning);font-size:.7rem;"><i class="bi bi-box-seam"></i> SIM Vierge</span>
          <?php elseif(!empty($l['esim'])): ?><span class="badge" style="background:rgba(139,92,246,.15);color:#a78bfa;font-size:.7rem;"><i class="bi bi-sim"></i> eSIM</span>
          <?php endif; ?>
          <code class="ref" title="ICCID"><?=h($l['iccid']?:'Pas de SIM')?></code><?php if(!empty($l['eid'])): ?><br><span class="muted" style="font-size:.72rem;">EID: <?=h($l['eid'])?></span><?php endif; ?>
          <br><span class="muted">PIN: <?=h($l['pin']?:'-')?> | PUK: <?=h($l['puk']?:'-')?></span></td>
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
                <?php if($l['agent_id']): ?>
                <a href="index.php?page=pdf_bon&agent_id=<?=$l['agent_id']?>" target="_blank" class="btn-icon" title="Voir / générer le bon de remise" style="text-decoration:none;">🖨️</a>
                <?php endif; ?>
                <button class="btn-icon" title="Changer la SIM (garder le numéro)" style="color:var(--warning)"
                    onclick="openSimSwap(<?=$l['id']?>, '<?=h($l['phone_number'])?>', '<?=h($l['iccid'])?>', <?=!empty($l['esim'])?'true':'false'?>, '<?=h($l['eid']?:'')?>')">🔄</button>
                <button type="button" class="btn-icon btn-del" title="Résilier / Archiver" onclick="openArchiveLine(<?=$l['id']?>, <?=(int)$l['device_id']?>, <?=json_encode($l['device_id'] ? ($l['brand'].' '.$l['model_name'].' — S/N: '.($l['serial_number']?:($l['imei']?:'—'))) : '')?>)"><i class="bi bi-archive"></i></button>
            <?php else: ?>
                <button class="btn-icon" title="Historique" onclick='showHistory(<?=json_encode($hist, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>)'><i class="bi bi-clock-history"></i></button>
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
        <div class="form-group"><label>Utilisateur affecté</label><div class="qa-row"><select name="agent_id" id="<?=$act?>-agent_id" onchange="syncServiceFromAgent(this,'<?=$act?>')"><option value="">-- Sélectionner dans le référentiel --</option><?php foreach($agents as $a): ?><option value="<?=$a['id']?>" data-service="<?=(int)$a['service_id']?>"><?=h($a['last_name'].' '.$a['first_name'])?></option><?php endforeach; ?></select><button type="button" class="btn-quickadd" onclick="quickAddOpen('agent','<?=$act?>-agent_id')" title="Ajouter un utilisateur"><i class="bi bi-plus-lg"></i></button></div></div>
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
    $agents = $pdo->query("SELECT id, first_name, last_name, service_id FROM agents WHERE archived=0 ORDER BY last_name, first_name")->fetchAll();
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
          <div class="qa-row">
          <select name="agent_id" id="<?=$act?>-agent_id" onchange="syncServiceFromAgent(this,'<?=$act?>')"><option value="">-- Aucun --</option>
          <?php foreach($agents as $a): ?><option value="<?=$a['id']?>" data-service="<?=(int)$a['service_id']?>"><?=h($a['last_name'].' '.$a['first_name'])?></option><?php endforeach; ?></select>
          <button type="button" class="btn-quickadd" onclick="quickAddOpen('agent','<?=$act?>-agent_id')" title="Ajouter un utilisateur"><i class="bi bi-plus-lg"></i></button>
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
    <?php if($tab !== 'settings'):
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
    <div class="page-header">
      <button class="btn-primary" onclick="openModal('modal-add-<?=$ent?>')"><i class="bi bi-plus-lg"></i> <?=h($addLabels[$tab] ?? 'Ajouter')?></button>
    </div>
    <?php endif; ?>

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
    <div style="display:flex; gap:8px; margin-bottom:1.5rem; flex-wrap:wrap;">
      <?php foreach($subMenu as $sk => $slabel): ?>
      <a href="?page=refs&tab=settings&sub=<?=$sk?>" class="tab-btn <?=$settingsSub===$sk?'active':''?>" style="border-radius:8px;"><?=$slabel?></a>
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
          <div style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:center;">
            <input type="email" name="test_email" placeholder="destinataire@exemple.fr" required value="<?=h($smtpTestTo)?>" style="flex:1;min-width:220px;">
            <button type="submit" class="btn-secondary">📧 Envoyer un e-mail de test</button>
          </div>
          <small style="color:var(--text3);">Utilise la configuration <strong>enregistrée</strong> (enregistrez d'abord vos modifications).</small>
        </form>
      </div>

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
            tr.innerHTML = '<td style="color:var(--text3);">＋</td>'
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
    <!-- Bloc import CSV — reprise d'inventaire depuis un export -->
    <div class="card">
      <div class="card-header"><i class="bi bi-filetype-csv"></i> Importation CSV</div>
      <form method="post" enctype="multipart/form-data" style="padding:1.5rem;"
            onsubmit="return !document.getElementById('imp-trunc').checked || confirm('Vider TOUTE la base avant l\'import ? Cette opération est irréversible.')">
        <input type="hidden" name="<?=CSRF_TOKEN_NAME?>" value="<?=h($CSRF_TOKEN)?>">
        <input type="hidden" name="_entity" value="import">
        <input type="hidden" name="_action" value="run">

        <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
          Reprise d'inventaire depuis un export CSV : lignes, cartes SIM, matériels, utilisateurs,
          services, modèles, forfaits et opérateurs sont créés en une passe.
          Les doublons (numéro de ligne, IMEI) sont ignorés, l'import est donc rejouable sans risque de duplicatas.
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
          <button type="submit" class="btn-primary" style="display:inline-flex;align-items:center;gap:6px;"><i class="bi bi-upload"></i> Lancer l'importation</button>
        </div>
      </form>
    </div>

    <!-- Bloc sauvegarde / restauration — super-admin uniquement -->
    <div class="card" style="margin-top:1.5rem;">
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
            Toutes les tables seront supprimées et vous serez redirigé vers <code>install.php</code> pour recréer la structure.<br><br>
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
    <div class="search-bar-wrap">
      <div class="search-bar"><span class="search-bar-icon"><i class="bi bi-search"></i></span><input type="text" placeholder="Filtrer..." oninput="tableSearch(this,'tbody-refs','count')"></div>
      <div class="search-count" id="count"></div>
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
            <div class="form-group"><label>Chef de service (visa)</label><input type="text" name="chef_name" id="<?=$act?>-chef_name" placeholder="Prénom Nom"></div>
            <div class="form-group"><label>E-mail du chef de service</label><input type="email" name="chef_email" id="<?=$act?>-chef_email" placeholder="chef@collectivite.fr"></div>
            <div class="form-group"><label>D.G.A. de secteur (visa)</label><input type="text" name="dga_name" id="<?=$act?>-dga_name" placeholder="Prénom Nom"></div>
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

    // ── Couleurs de cycle pour les paires ──
    $pairBorderColors = ['#059669','#4f46e5','#d97706','#7c3aed','#ec4899','#2563eb'];

    $now = time();
    function bonStatusHtml(array $b, int $now): string {
        if ($b['status'] === 'signed')    return '<span style="background:rgba(5,150,105,.12);color:var(--success);font-size:.72rem;font-weight:700;padding:.15rem .5rem;border-radius:999px;white-space:nowrap;">✅ Signé</span>';
        if ($b['status'] === 'cancelled') return '<span style="background:rgba(148,163,184,.1);color:#94a3b8;font-size:.72rem;font-weight:700;padding:.15rem .5rem;border-radius:999px;white-space:nowrap;">🚫 Annulé</span>';
        if ($b['expires_at'] && strtotime($b['expires_at']) < $now) return '<span style="background:rgba(217,119,6,.12);color:var(--warning);font-size:.72rem;font-weight:700;padding:.15rem .5rem;border-radius:999px;white-space:nowrap;">⏰ Expiré</span>';
        return '<span style="background:rgba(37,99,235,.12);color:var(--info);font-size:.72rem;font-weight:700;padding:.15rem .5rem;border-radius:999px;white-space:nowrap;">⏳ En attente</span>';
    }
    ?>

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
        $borderColor = $pairBorderColors[$pi % count($pairBorderColors)];
        $agentName = trim($pair['agent_name']);
    ?>
    <div class="history-pair-card" data-search="<?=h(strtolower($agentName.' '.$pair['service_name'].' '.($pair['phone_numbers']??'').' '.($pair['remise']['dsi_name']??'').' '.($pair['restitution']['dsi_name']??'').' '.($pair['remise']['numero']??'').' '.($pair['restitution']['numero']??'')))?>" style="background:var(--card);border:1px solid var(--border);border-left:4px solid <?=$borderColor?>;border-radius:var(--radius);margin-bottom:1rem;overflow:hidden;">
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
        </div>
        <?php if($pair['phone_numbers']): ?>
        <div style="font-family:var(--font-mono);font-size:.85rem;color:var(--primary);font-weight:600;">
          📞 <?=h(implode(' / ', array_map('formatPhone', explode(' / ', $pair['phone_numbers']))))?></div>
        <?php endif; ?>
        <?php $printBon = $pair['remise'] ?: $pair['restitution']; if($printBon): ?>
        <a href="index.php?page=pdf_bon&bon_id=<?=$printBon['id']?>" target="_blank" class="btn-icon" title="Voir / imprimer ce bon" style="text-decoration:none;font-size:.8rem;">🖨️</a>
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
    function historySearch(q) {
      q = q.toLowerCase().trim();
      const cards = document.querySelectorAll('.history-pair-card');
      let visible = 0;
      cards.forEach(c => {
        const match = !q || c.dataset.search.includes(q);
        c.style.display = match ? '' : 'none';
        if (match) visible++;
      });
      const el = document.getElementById('count-history');
      if (el) el.textContent = q ? visible + ' résultat(s)' : '';
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
            $agents = $pdo->query("SELECT id, first_name, last_name, service_id FROM agents WHERE archived=0 ORDER BY last_name, first_name")->fetchAll();
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
          <a href="?page=pdf_demande&id=<?=$viewId?>" target="_blank" class="btn-icon" title="Récapitulatif imprimable (pièce justificative)" style="text-decoration:none;">🖨️</a>
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
            <select name="agent_id" style="flex:1;">
              <option value="">— Aucun agent lié —</option>
              <?php foreach ($agents as $a): ?>
              <option value="<?=$a['id']?>" <?=(int)$req['agent_id'] === (int)$a['id'] ? 'selected' : ''?>><?=h(trim($a['last_name'] . ' ' . $a['first_name']))?></option>
              <?php endforeach; ?>
            </select>
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
              <td style="color:var(--text3);"><?=$i + 1?></td>
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
            <button type="submit" class="btn-primary" <?=$smtpConfigured ? '' : 'title="SMTP non configuré : le lien devra être transmis manuellement"'?>
              onclick="return confirm('Lancer le circuit de validation ? Le premier valideur recevra immédiatement le lien par e-mail.')">🚀 Lancer le circuit</button>
            <?php if (!$smtpConfigured): ?><span style="color:var(--warning);font-size:.8rem;">⚠️ SMTP non configuré — <a href="?page=refs&tab=settings&sub=email" style="color:var(--primary);">Paramètres → Envoi d'e-mails</a></span><?php endif; ?>
          </div>
        </form>
        <script>
        function circuitAddRow(step) {
          const tb = document.querySelector('#circuit-table tbody');
          const tr = document.createElement('tr');
          tr.innerHTML = '<td style="color:var(--text3);">＋</td>'
            + '<td><input type="text" name="step_label[]" placeholder="Libellé du visa"></td>'
            + '<td style="position:relative;"><input type="text" class="circuit-name" name="step_name[]" placeholder="Prénom Nom" autocomplete="off"><div class="adp-box circuit-suggest"></div></td>'
            + '<td><input type="email" class="circuit-email" name="step_email[]" placeholder="valideur@collectivite.fr"></td>'
            + '<td><button type="button" class="btn-icon btn-del" onclick="this.closest(\'tr\').remove()"><i class="bi bi-x-lg"></i></button></td>';
          if (step) {
            tr.querySelector('[name="step_label[]"]').value = step.label || '';
            tr.querySelector('[name="step_name[]"]').value  = step.name  || '';
            tr.querySelector('[name="step_email[]"]').value = step.email || '';
          }
          tb.appendChild(tr);
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
        <thead><tr><th>N°</th><th>Déposée le</th><th>Agent</th><th>Service</th><th>Type</th><th>Statut</th><th>Avancement</th><th>Actions</th></tr></thead>
        <tbody id="tbody-requests">
        <?php if (!$reqs): ?><tr><td colspan="8" class="empty-cell"><?=$reqClosed ? 'Aucune demande terminée pour l\'instant.' : 'Aucune demande en cours. Diffusez le lien du formulaire public ci-dessus.'?></td></tr><?php endif; ?>
        <?php foreach ($reqs as $r): [$lbl, $cls] = requestStatusInfo($r['status']); ?>
        <tr style="<?=in_array($r['status'], ['refusee', 'annulee'], true) ? 'opacity:.6;' : ''?>">
          <td><a href="?page=requests&view=<?=$r['id']?>" class="cell-link" style="font-family:var(--font-mono);font-weight:700;color:var(--primary);"><?=h($r['numero'])?></a></td>
          <td class="muted"><?=h($r['created_fmt'])?></td>
          <td><strong><?=h($r['agent_name'])?></strong><?=$r['agent_id'] ? '' : ' <span class="muted" style="font-size:.72rem;" title="Non rattachée au référentiel">⚠️</span>'?></td>
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
    $statBrand   = $pdo->query("SELECT m.brand AS k, COUNT(d.id) AS c FROM devices d JOIN models m ON d.model_id=m.id WHERE d.archived=0 GROUP BY m.brand ORDER BY c DESC")->fetchAll();
    $devStatusMap = ['Deployed'=>'Déployé', 'Stock'=>'En stock', 'Repair'=>'Réparation', 'HS'=>'HS / Rebut', 'Lost'=>'Perdu / Volé'];
    $statDevStat = $pdo->query("SELECT status AS k, COUNT(*) AS c FROM devices WHERE archived=0 GROUP BY status ORDER BY c DESC")->fetchAll();
    $statOper    = $pdo->query("SELECT IFNULL(o.name,'Sans opérateur') AS k, COUNT(l.id) AS c FROM mobile_lines l LEFT JOIN plan_types p ON l.plan_id=p.id LEFT JOIN operators o ON p.operator_id=o.id WHERE l.archived=0 AND l.sim_vierge=0 GROUP BY o.name ORDER BY c DESC")->fetchAll();
    $statPlan    = $pdo->query("SELECT IFNULL(p.name,'Sans forfait') AS k, COUNT(l.id) AS c FROM mobile_lines l LEFT JOIN plan_types p ON l.plan_id=p.id WHERE l.archived=0 AND l.sim_vierge=0 GROUP BY p.name ORDER BY c DESC LIMIT 8")->fetchAll();
    $sEsim    = (int)$pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived=0 AND esim=1")->fetchColumn();
    $sPhysSim = (int)$pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived=0 AND esim=0 AND sim_vierge=0")->fetchColumn();
    $sByod    = (int)$pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived=0 AND personal_device=1")->fetchColumn();

    // ── 2. Par service ──
    $statSvc = $pdo->query("SELECT s.name AS k,
            (SELECT COUNT(*) FROM mobile_lines l WHERE l.service_id=s.id AND l.archived=0) AS lignes,
            (SELECT COUNT(*) FROM devices d WHERE d.service_id=s.id AND d.archived=0)      AS mats
        FROM services s HAVING lignes+mats > 0 ORDER BY lignes+mats DESC LIMIT 10")->fetchAll();

    // ── 3. Demandes de téléphone ──
    $statReqMonth  = $pdo->query("SELECT DATE_FORMAT(created_at,'%Y-%m') AS k, COUNT(*) AS c FROM requests WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH) GROUP BY k ORDER BY k")->fetchAll();
    $reqStatusMap  = ['a_qualifier'=>'À qualifier','en_validation'=>'En validation','validee'=>'Validée','livree'=>'Livrée','refusee'=>'Refusée','annulee'=>'Annulée'];
    $statReqStatus = $pdo->query("SELECT status AS k, COUNT(*) AS c FROM requests GROUP BY status")->fetchAll();
    $statReqType   = $pdo->query("SELECT type AS k, COUNT(*) AS c FROM requests GROUP BY type")->fetchAll();
    $statReqMotif  = $pdo->query("SELECT replace_motif AS k, COUNT(*) AS c FROM requests WHERE replace_device=1 AND replace_motif IS NOT NULL AND replace_motif<>'' GROUP BY replace_motif ORDER BY c DESC")->fetchAll();
    $sReqValidated = (int)$pdo->query("SELECT COUNT(*) FROM requests WHERE status IN ('validee','livree')")->fetchColumn();
    $sReqRefused   = (int)$pdo->query("SELECT COUNT(*) FROM requests WHERE status='refusee'")->fetchColumn();
    $sReqAvgDays   = $pdo->query("SELECT ROUND(AVG(DATEDIFF(closed_at, launched_at)),1) FROM requests WHERE status IN ('validee','livree') AND launched_at IS NOT NULL AND closed_at IS NOT NULL")->fetchColumn();

    // ── 4. Incidents & renouvellement ──
    // Matériels archivés par motif (extrait des journaux « Archivé — Motif : X »)
    $archLogs = $pdo->query("SELECT action_desc FROM history_logs WHERE entity_type='device' AND action_desc LIKE '%Motif :%'")->fetchAll(PDO::FETCH_COLUMN);
    $motifCounts = [];
    foreach ($archLogs as $desc) {
        if (preg_match('/Motif\s*:\s*([^—\-]+)/u', $desc, $mm)) { $mo = trim($mm[1]); if ($mo !== '') $motifCounts[$mo] = ($motifCounts[$mo] ?? 0) + 1; }
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
    $statSimReason = $pdo->query("SELECT IFNULL(NULLIF(reason,''),'Non précisé') AS k, COUNT(*) AS c FROM sim_history GROUP BY reason ORDER BY c DESC LIMIT 8")->fetchAll();

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
        <?php $chartCard('Demandes par mois (12 mois)', 'calendar3', 'stReqMonth', (bool)$statReqMonth); ?>
        <?php $chartCard('Répartition par statut', 'pie-chart', 'stReqStatus', (bool)$statReqStatus); ?>
        <?php $chartCard('Par type de demande', 'tags', 'stReqType', (bool)$statReqType); ?>
        <?php $chartCard('Motifs de remplacement', 'exclamation-triangle', 'stReqMotif', (bool)$statReqMotif, 'Aucun renouvellement avec motif.'); ?>
      </div>

      <!-- 4. INCIDENTS & RENOUVELLEMENT -->
      <h3 style="font-size:1rem;color:var(--text-strong);margin-top:.5rem;"><i class="bi bi-tools"></i> Incidents &amp; renouvellement</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;">
        <?php $chartCard('Matériels archivés par motif', 'trash3', 'stArch', (bool)$motifCounts, 'Aucun matériel archivé.'); ?>
        <?php $chartCard('Vieillissement du parc (matériels actifs)', 'hourglass-split', 'stAge', array_sum($ageBuckets) > 0); ?>
        <?php $chartCard('Changements de SIM par motif', 'sim', 'stSim', (bool)$statSimReason, 'Aucun changement de SIM.'); ?>
      </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
      const PAL = ['#4f46e5','#2563eb','#7c3aed','#d97706','#059669','#dc2626','#0891b2','#db2777','#65a30d','#ea580c'];
      function doughnut(id, labels, data){ const el=document.getElementById(id); if(!el||!labels.length)return;
        new Chart(el,{type:'doughnut',data:{labels,datasets:[{data,backgroundColor:PAL,borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'#94a3b8',boxWidth:12,padding:10}}}}}); }
      function bars(id, labels, datasets, horizontal){ const el=document.getElementById(id); if(!el||!labels.length)return;
        new Chart(el,{type:'bar',data:{labels,datasets},options:{indexAxis:horizontal?'y':'x',responsive:true,maintainAspectRatio:false,scales:{x:{beginAtZero:true,ticks:{color:'#94a3b8',precision:0},grid:{color:'rgba(148,163,184,.15)'}},y:{beginAtZero:true,ticks:{color:'#94a3b8',precision:0},grid:{color:'rgba(148,163,184,.15)'}}},plugins:{legend:{display:datasets.length>1,labels:{color:'#94a3b8'}}}}}); }

      // Parc & stock
      doughnut('stBrand', <?=json_encode($col($statBrand,'k'))?>, <?=json_encode(array_map('intval',$col($statBrand,'c')))?>);
      doughnut('stDevStat', <?=json_encode(array_map(fn($k)=>$devStatusMap[$k]??$k, $col($statDevStat,'k')))?>, <?=json_encode(array_map('intval',$col($statDevStat,'c')))?>);
      bars('stOper', <?=json_encode($col($statOper,'k'))?>, [{label:'Lignes',data:<?=json_encode(array_map('intval',$col($statOper,'c')))?>,backgroundColor:'#2563eb',borderRadius:4}]);
      bars('stPlan', <?=json_encode($col($statPlan,'k'))?>, [{label:'Lignes',data:<?=json_encode(array_map('intval',$col($statPlan,'c')))?>,backgroundColor:'#7c3aed',borderRadius:4}], true);

      // Par service (barres groupées)
      bars('stSvc', <?=json_encode($svcNames)?>, [
        {label:'Lignes',   data:<?=json_encode($svcLines)?>, backgroundColor:'#4f46e5', borderRadius:4},
        {label:'Matériels',data:<?=json_encode($svcMats)?>,  backgroundColor:'#7c3aed', borderRadius:4}
      ]);

      // Demandes
      bars('stReqMonth', <?=json_encode($col($statReqMonth,'k'))?>, [{label:'Demandes',data:<?=json_encode(array_map('intval',$col($statReqMonth,'c')))?>,backgroundColor:'#d97706',borderRadius:4}]);
      doughnut('stReqStatus', <?=json_encode(array_map(fn($k)=>$reqStatusMap[$k]??$k, $col($statReqStatus,'k')))?>, <?=json_encode(array_map('intval',$col($statReqStatus,'c')))?>);
      doughnut('stReqType', <?=json_encode(array_map(fn($k)=>$k==='renouvellement'?'Renouvellement':'Attribution', $col($statReqType,'k')))?>, <?=json_encode(array_map('intval',$col($statReqType,'c')))?>);
      bars('stReqMotif', <?=json_encode($col($statReqMotif,'k'))?>, [{label:'Demandes',data:<?=json_encode(array_map('intval',$col($statReqMotif,'c')))?>,backgroundColor:'#dc2626',borderRadius:4}]);

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
<link rel="icon" type="image/svg+xml" href="assets/logo.svg">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
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
.content{padding:2rem;flex:1;max-width:1400px;margin:0 auto;width:100%;}
.page-header{display:flex;align-items:center;justify-content:flex-end;margin-bottom:1.5rem;}
.page-title-txt{font-family:var(--font-display);font-weight:700;font-size:1.4rem;color:var(--text-strong);}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius-lg);margin-bottom:1.5rem;break-inside:avoid;box-shadow:var(--shadow);}
.card-header{padding:.85rem 1.5rem .85rem 2.15rem;border-bottom:1px solid var(--border);background:rgba(79,70,229,.03);font-family:var(--font-display);font-weight:700;font-size:.9rem;color:var(--text);position:relative;}
.card-header::before{content:'';position:absolute;left:1.5rem;top:50%;transform:translateY(-50%);width:4px;height:1.05em;border-radius:3px;background:var(--primary);}

.data-table{width:100%;border-collapse:collapse}
.data-table th{padding:.75rem 1.25rem;text-align:left;font-size:.68rem;font-weight:700;letter-spacing:.06em;color:var(--text2);text-transform:uppercase;background:var(--card2);border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer;user-select:none;transition:color 0.15s;}
.data-table th:hover{color:var(--primary);}
.data-table th.sorted{color:var(--primary);font-weight:700;}

.data-table td{padding:.8rem 1.25rem;border-bottom:1px solid var(--border);font-size:.875rem;line-height:1.4} .data-table tbody tr{transition:background-color .12s ease} .data-table tbody tr:hover{background:var(--bg3)}
.empty-cell{text-align:center;color:var(--text3);padding:3rem!important;font-style:italic} .muted{color:var(--text2)!important;font-size:.82rem;}
.search-bar-wrap{margin-bottom:1rem;} .search-bar{display:flex;align-items:center;gap:.6rem;background:var(--card);border:1px solid var(--border2);border-radius:var(--radius-sm);padding:.55rem .9rem; transition:border-color .2s, box-shadow .2s; }
[data-theme="dark"] .search-bar{background:var(--bg3)}
.search-bar:focus-within { border-color:var(--primary); box-shadow:var(--ring); }
.search-bar-icon{font-size:1rem;opacity:.5;flex-shrink:0;} .search-bar input{flex:1;background:none;border:none;outline:none;color:var(--text);font-size:.9rem;} .search-count{font-size:.75rem;color:var(--text3);margin-top:.3rem;}
.badge{display:inline-block;padding:.2rem .65rem;border-radius:999px;font-size:.72rem;font-weight:600;white-space:nowrap;line-height:1.4;}
.badge-success{background:var(--success-dim);color:#065f46;} .badge-danger{background:var(--danger-dim);color:#991b1b;} .badge-warning{background:var(--warning-dim);color:#92400e;} .badge-info{background:var(--info-dim);color:#1e40af;} .badge-muted{background:var(--bg3);color:var(--text2);}
[data-theme="dark"] .badge-success{color:#6ee7b7} [data-theme="dark"] .badge-danger{color:#fca5a5} [data-theme="dark"] .badge-warning{color:#fcd34d} [data-theme="dark"] .badge-info{color:#93c5fd}
.btn-primary{background:var(--primary);border:1px solid var(--primary);border-radius:var(--radius-sm);padding:.6rem 1.4rem;color:#fff;font-weight:500;font-size:.85rem;cursor:pointer;transition:all .18s ease;} .btn-primary:hover{background:var(--primary-dark);border-color:var(--primary-dark);box-shadow:var(--shadow);} .btn-primary:active{transform:translateY(1px);}
.btn-secondary{background:var(--card);border:1px solid var(--border2);border-radius:var(--radius-sm);padding:.6rem 1.25rem;color:var(--text2);font-size:.85rem;cursor:pointer;transition:all .18s ease;} .btn-secondary:hover{border-color:var(--primary);color:var(--text-strong)}
.btn-icon{background:none;border:none;cursor:pointer;font-size:1rem;padding:.3rem .5rem;border-radius:var(--radius-sm);color:var(--text2);transition:all .15s;} .btn-edit:hover{background:var(--primary-dim);color:var(--primary)} .btn-del:hover{background:var(--danger-dim);color:var(--danger)}
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
.kpi-blue::before{background:#4f46e5;}
.kpi-violet::before{background:#7c3aed;}
.kpi-green::before{background:#059669;}
.kpi-icon{font-size:2rem;} .kpi-val{font-family:var(--font-mono);font-size:1.7rem;font-weight:600;line-height:1.1;color:var(--text-strong);letter-spacing:-.01em;} .kpi-label{font-size:.74rem;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;}
.kpi-main{display:flex;align-items:center;gap:1rem;flex:1;min-width:0;text-decoration:none;color:inherit;}
.kpi-info{display:flex;flex-direction:column;min-width:0;}
.kpi-sub{font-size:.75rem;color:var(--text2);margin-top:.15rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.kpi-add{flex-shrink:0;display:inline-flex;align-items:center;gap:.35rem;padding:.45rem .85rem;border-radius:999px;background:var(--primary-dim);color:var(--primary);font-size:.76rem;font-weight:600;text-decoration:none;white-space:nowrap;transition:background-color .15s,color .15s;}
.kpi-add:hover{background:var(--primary);color:#fff;}
.shortcut-btn{display:flex;flex-direction:column;gap:.35rem;padding:1.25rem;border-radius:var(--radius);border:1px solid var(--border);text-decoration:none;transition:border-color .2s;} .shortcut-btn:hover{border-color:var(--primary);}
.shortcut-label{font-weight:700;color:var(--text-strong)} .shortcut-in{background:rgba(5,150,105,.07);} .shortcut-order{background:rgba(79,70,229,.07);} .shortcut-resa{background:rgba(37,99,235,.07);}
.tab-btn{padding:.6rem 1.2rem;border:1px solid transparent;border-radius:var(--radius-sm) var(--radius-sm) 0 0;text-decoration:none;color:var(--text2);font-weight:600;font-size:.9rem;} .tab-btn.active{background:var(--card);border-color:var(--border);border-bottom-color:var(--card);color:var(--primary);margin-bottom:-2px;z-index:2;}
@media(max-width:900px){.sidebar{transform:translateX(-100%);transition:transform .25s ease;box-shadow:var(--shadow-lg)}.sidebar.open{transform:translateX(0)}.main{margin-left:0}.btn-hamburger{display:inline-flex}}
a{color:inherit;text-decoration:none} a:hover{color:var(--primary)}
/* Ajout rapide (+) : select accolé à un bouton d'ajout d'entité liée */
.qa-row{display:flex;gap:.5rem;align-items:stretch}
.qa-row select{flex:1;min-width:0}
.btn-quickadd{flex-shrink:0;width:42px;display:inline-flex;align-items:center;justify-content:center;background:var(--primary-dim);color:var(--primary);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:1rem;transition:background-color .15s,color .15s}
.btn-quickadd:hover{background:var(--primary);color:#fff}
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
    <img src="assets/logo.svg" alt="" class="logo-icon">
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
    <a href="?page=refs&tab=services" class="nav-item <?=($navRefsTab!=='' && $navRefsTab!=='agents')?'active':''?>"><i class="bi bi-gear nav-icon"></i><span class="nav-label">Référentiels & Comptes</span></a>
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
  const tbody = document.getElementById(tbodyId); const count = document.getElementById(countId);
  if (!tbody) return;
  const rows  = Array.from(tbody.querySelectorAll('tr')); const words = q.split(/\s+/).filter(Boolean);
  let visible = 0;
  
  rows.forEach(function(tr) {
    if (tr.querySelector('td.empty-cell')) return;
    const txt = tr.textContent.toLowerCase(); const txtNoSpaces = txt.replace(/\s+/g, '');
    const matchWords = (!words.length || words.every(function(w) { return txt.includes(w); }));
    const matchNoSpace = qNoSpaces.length > 0 && txtNoSpaces.includes(qNoSpaces);
    const match = matchWords || matchNoSpace;
    tr.style.display = match ? '' : 'none';
    if (match) visible++;
  });
  
  if (count) {
    if (!q) count.textContent = '';
    else if (visible === 0) count.textContent = 'Aucun résultat.';
    else count.textContent = visible + ' résultat(s) trouvé(s)';
  }
}

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
const QA_CONFIG = {
  service:  { title:'Ajouter un service',  icon:'building',  fields:[{name:'name',label:'Nom du service',required:true}] },
  model:    { title:'Ajouter un modèle',   icon:'phone',     fields:[{name:'brand',label:'Marque',required:true},{name:'name',label:'Modèle',required:true},{name:'category',label:'Catégorie',type:'select',options:['Smartphone','Tablette','Clé 4G','Modem','Autre']}] },
  agent:    { title:'Ajouter un utilisateur', icon:'person', fields:[{name:'first_name',label:'Prénom'},{name:'last_name',label:'Nom',required:true}] },
  plan:     { title:'Ajouter un forfait',  icon:'globe2',    fields:[{name:'name',label:'Nom du forfait',required:true},{name:'data_limit',label:'Enveloppe data (ex : 100 Go)'}] },
  billing:  { title:'Ajouter un compte de facturation', icon:'cash-coin', fields:[{name:'account_number',label:'N° de compte',required:true},{name:'name',label:'Nom / Entité'}] },
  operator: { title:'Ajouter un opérateur',icon:'broadcast', fields:[{name:'name',label:"Nom de l'opérateur",required:true}] },
};
let _qaEntity=null, _qaTarget=null;
function qaError(msg){ const b=document.getElementById('qa-error'); if(b){ b.textContent=msg||''; b.style.display=msg?'block':'none'; } }
function quickAddOpen(entity, targetSelectId){
  const cfg = QA_CONFIG[entity]; if(!cfg) return;
  _qaEntity = entity; _qaTarget = targetSelectId;
  document.getElementById('qa-title').innerHTML = '<i class="bi bi-'+(cfg.icon||'plus-lg')+'"></i> ' + cfg.title;
  qaError('');
  const wrap = document.getElementById('qa-fields');
  wrap.innerHTML = cfg.fields.map(f => {
    const req = f.required ? ' <span style="color:var(--danger)">*</span>' : '';
    let input;
    if(f.type === 'select'){
      input = '<select data-qa="'+f.name+'">' + f.options.map(o=>'<option value="'+o+'">'+o+'</option>').join('') + '</select>';
    } else {
      input = '<input type="text" data-qa="'+f.name+'"'+(f.required?' data-req="1"':'')+'>';
    }
    return '<div class="form-group"><label>'+f.label+req+'</label>'+input+'</div>';
  }).join('');
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
        const opt = document.createElement('option');
        opt.value = j.id; opt.textContent = j.label; opt.selected = true;
        sel.appendChild(opt);
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
document.addEventListener('DOMContentLoaded', ()=>{ bindAgentAd('add'); bindAgentAd('edit'); });

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
        const label = '📱 (Actuellement assigné) ' + (data.brand||'') + ' ' + (data.model_name||'') + ' — S/N: ' + (data.serial_number || data.imei || data.device_id);
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
// Auto-attribution du service : sélectionner un utilisateur pré-remplit le
// champ « Service / Direction » avec le service de cet agent (modifiable).
function syncServiceFromAgent(sel, act) {
  if (!sel.value) return;   // « Aucun » agent : on ne modifie pas le service
  const svc = sel.selectedOptions[0] ? sel.selectedOptions[0].getAttribute('data-service') : '';
  const svcSel = document.getElementById(act + '-service_id');
  if (svcSel) svcSel.value = (svc && svc !== '0') ? svc : '';
}
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

<?php if(!empty($_GET['open'])): ?>window.addEventListener('DOMContentLoaded', () => openModal('<?=h($_GET['open'])?>'));<?php endif; ?>
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