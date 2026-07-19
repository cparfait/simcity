<?php
// ============================================================
//  SimCity v5.0 – Flotte Mobile, Zéro Papier & Sécurité
// ============================================================
ob_start();

// ─── Configuration centralisée ────────────────────────────────
require_once __DIR__ . '/config.php';

// ─── Affichage des erreurs selon l'environnement ──────────────
if (defined('APP_DEBUG') && APP_DEBUG) {
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
} else {
    ini_set('display_errors', 0);
    error_reporting(0);
}

// ─── Session sécurisée ────────────────────────────────────────
session_name(SESSION_NAME);
ini_set('session.cookie_httponly', 1);   // Inaccessible au JS
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
// Cookie sécurisé activé automatiquement dès que le site est servi en HTTPS
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
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
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `" . DB_NAME . "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    $pdo->exec("USE `" . DB_NAME . "`");
} catch (Exception $e) { die("<div style='color:#ef4444;padding:3rem;font-family:sans-serif'>Erreur DB : impossible de se connecter.</div>"); }

// ─── 2. CREATION ET MISE A JOUR DES TABLES ────────────────────
try {
    require_once __DIR__ . '/schema.php';
} catch (Exception $e) { die("Erreur SQL de création : " . $e->getMessage()); }


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
        $signerName = htmlspecialchars(trim($_POST['signer_name'] ?? ''), ENT_QUOTES);
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
input:focus{outline:none;border-color:#4361ee;box-shadow:0 0 0 3px rgba(67,97,238,.15);}
.canvas-wrap{border:2px dashed #cbd5e1;border-radius:8px;background:#fafafa;margin-bottom:.75rem;position:relative;touch-action:none;}
canvas{display:block;width:100%;border-radius:8px;}
.canvas-hint{text-align:center;font-size:.75rem;color:#94a3b8;padding:.35rem;}
.btn-clear{background:none;border:1px solid #e2e8f0;border-radius:6px;padding:.45rem 1rem;font-size:.82rem;color:#64748b;cursor:pointer;margin-bottom:1rem;}
.btn-sign{width:100%;padding:1rem;background:linear-gradient(135deg,#4361ee,#3a86ff);color:#fff;border:none;border-radius:10px;font-size:1.05rem;font-weight:600;cursor:pointer;box-shadow:0 4px 15px rgba(67,97,238,.3);}
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

// ─── 3. GENERATION PDF (BON DE REMISE) ────────────────────────
function formatPhone($phone) { $val = preg_replace('/[^0-9]/', '', (string)$phone); return $val ? implode(' ', str_split($val, 2)) : ''; }
function baseUrl($pdo = null) {
    if ($pdo) {
        $custom = getSetting($pdo, 'site_url', '');
        if ($custom) return rtrim($custom, '/') . '/index.php';
    }
    $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
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
    $devices = $pdo->query("SELECT DISTINCT d.id as device_id, d.imei, d.serial_number, d.inventory_label, m.brand, m.name FROM devices d LEFT JOIN models m ON d.model_id=m.id WHERE (d.agent_id=$agentId OR d.id IN (SELECT device_id FROM mobile_lines WHERE agent_id=$agentId AND device_id IS NOT NULL)) AND d.archived=0 ORDER BY d.id")->fetchAll();
    return [
        'agent'   => ['name' => trim(($agt['first_name'] ?? '') . ' ' . ($agt['last_name'] ?? '')), 'service' => $agt['service_name'] ?? '', 'email' => $agt['email'] ?? ''],
        'devices' => $devices,
        'lines'   => $lines,
    ];
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
    $pdo->prepare("INSERT INTO bons (numero, type, agent_id, parent_id, items, status, token, expires_at, created_by, dsi_name, dsi_signature_data) VALUES (?,?,?,?,?,'pending',?,?,?,?,?)")
        ->execute([bonNumero($pdo, $type), $type, (int)$agentId, $parentId, json_encode($items, JSON_UNESCAPED_UNICODE), $token, $expires, $_SESSION['username'] ?? 'admin', $dsiName, $dsiSig]);
    return (int)$pdo->lastInsertId();
}

// ─── Envoi d'e-mail via SMTP (aucune dépendance externe) ──────
// Retourne true en cas de succès, sinon un message d'erreur lisible.
function smtpSendMail($pdo, $to, $subject, $htmlBody) {
    $host     = trim(getSetting($pdo, 'smtp_host', ''));
    $port     = (int)getSetting($pdo, 'smtp_port', 587);
    $secure   = strtolower(trim(getSetting($pdo, 'smtp_secure', 'tls')));   // tls | ssl | none
    $user     = getSetting($pdo, 'smtp_user', '');
    $pass     = getSetting($pdo, 'smtp_pass', '');
    $from     = trim(getSetting($pdo, 'smtp_from', '')) ?: $user;
    $fromName = getSetting($pdo, 'smtp_from_name', 'SimCity');
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
        .btn{display:inline-block;margin-top:1rem;padding:.75rem 1.75rem;background:#4361ee;color:#fff;border:none;border-radius:9px;font-size:.95rem;font-weight:600;cursor:pointer;}
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
                  <a href="'.htmlspecialchars($url).'" style="display:block;margin-top:3px;font-size:.75rem;color:#4361ee;text-decoration:none;">Signer en ligne</a>';
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
        .toolbar button.tb-primary{background:#4361ee;border-color:#4361ee;color:#fff;}
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
            $smtpConfigured = trim(getSetting($pdo, 'smtp_host', '')) !== '';
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
    echo "-- ============================================================\n";
    echo "-- SimCity v" . (defined('APP_VERSION') ? APP_VERSION : '1.0') . " — Sauvegarde de la base `" . DB_NAME . "`\n";
    echo "-- Générée le " . date('d/m/Y à H:i:s') . " par " . ($_SESSION['username'] ?? '?') . "\n";
    echo "-- Restauration : mysql -u root -p " . DB_NAME . " < ce_fichier.sql\n";
    echo "-- ============================================================\n\n";
    echo "SET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\n\n";
    foreach ($pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN) as $table) {
        $create = $pdo->query("SHOW CREATE TABLE `$table`")->fetch();
        echo "-- ── Table `$table` ──\n";
        echo "DROP TABLE IF EXISTS `$table`;\n" . $create['Create Table'] . ";\n\n";
        $rows = $pdo->query("SELECT * FROM `$table`");
        while ($row = $rows->fetch(PDO::FETCH_ASSOC)) {
            $cols = '`' . implode('`,`', array_keys($row)) . '`';
            $vals = implode(',', array_map(fn($v) => $v === null ? 'NULL' : $pdo->quote((string)$v), array_values($row)));
            echo "INSERT INTO `$table` ($cols) VALUES ($vals);\n";
        }
        echo "\n";
    }
    echo "SET FOREIGN_KEY_CHECKS=1;\n-- Fin de la sauvegarde\n";
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

// ── Connexion avec protection anti-brute-force (en base) ──────
// Le compteur est stocké en base (par compte ET par IP) : impossible de le
// contourner en jetant son cookie de session.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $loginUser = trim($_POST['username'] ?? '');
    $loginIp   = $_SERVER['REMOTE_ADDR'] ?? '';

    // Purge des tentatives anciennes (> 24 h)
    $pdo->exec("DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 1 DAY)");

    // Verrouillage : 5 échecs sur le même compte ou la même IP en 15 minutes
    $st = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE (username=? OR ip=?) AND attempted_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
    $st->execute([$loginUser, $loginIp]);
    if ($st->fetchColumn() >= 5) {
        $login_error = "Trop de tentatives échouées. Réessayez dans quelques minutes.";
    } else {
        $st = $pdo->prepare("SELECT id, username, password, active, IFNULL(first_name,'') as first_name, IFNULL(last_name,'') as last_name, IFNULL(is_admin,0) as is_admin FROM users WHERE username=?");
        $st->execute([$loginUser]);
        $u = $st->fetch();
        if ($u && password_verify($_POST['password'] ?? '', $u['password'])) {
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

// ── Page de login ─────────────────────────────────────────────
if (!isset($_SESSION['user_id'])) {
    ?>
    <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connexion – SimCity</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;700&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root{--bg:#0f1420;--card:#1a2235;--primary:#4361ee;--text:#f0f4ff;--border:rgba(255,255,255,.1);--danger:#ef4444;}
        body{background:var(--bg);color:var(--text);font-family:'DM Sans',sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
        .login-box{background:var(--card);padding:2.5rem;border-radius:12px;border:1px solid var(--border);width:100%;max-width:400px;box-shadow:0 10px 40px rgba(0,0,0,.5);}
        h2{font-family:'Outfit',sans-serif;text-align:center;margin-top:0;font-size:1.8rem;}
        input{width:100%;padding:10px 15px;margin-top:5px;background:rgba(0,0,0,.2);border:1px solid var(--border);border-radius:6px;color:#fff;font-family:inherit;box-sizing:border-box;}
        input:focus{outline:none;border-color:var(--primary);}
        button{width:100%;padding:12px;background:var(--primary);color:#fff;border:none;border-radius:6px;font-weight:600;font-size:1rem;margin-top:1.5rem;cursor:pointer;}
    </style></head>
    <body>
        <div class="login-box"><h2>📱 SimCity</h2><p style="text-align:center;opacity:.7;margin-bottom:2rem;font-size:.9rem;">Gestion du Parc Mobile — DSI</p>
            <?php if(isset($login_error)) echo "<div style='color:var(--danger);text-align:center;margin-bottom:1rem;'>".h($login_error)."</div>"; ?>
            <form method="post" autocomplete="off">
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
    $smtpConfigured = trim(getSetting($pdo, 'smtp_host', '')) !== '';
    $lastRemise = $pdo->prepare("SELECT * FROM bons WHERE agent_id=? AND type='remise' AND status!='cancelled' ORDER BY created_at DESC, id DESC LIMIT 1");
    $lastRemise->execute([$id]); $lastRemise = $lastRemise->fetch();
    $lastRestit = null;
    if ($lastRemise) {
        $st = $pdo->prepare("SELECT * FROM bons WHERE parent_id=? AND type='restitution' AND status!='cancelled' ORDER BY created_at DESC, id DESC LIMIT 1");
        $st->execute([$lastRemise['id']]); $lastRestit = $st->fetch();
    }
    $hasPendingBons = (int)$pdo->query("SELECT COUNT(*) FROM bons WHERE agent_id=$id AND status='pending'")->fetchColumn();

    // Cycle clôturé : la restitution signée couvre tous les équipements de la
    // remise → il n'y a plus de « bon actuel », la paire vit dans l'historique.
    $bonItemIdsF = function($b) {
        if (empty($b['items'])) return null;
        $it = json_decode($b['items'], true);
        $ids = [];
        foreach (($it['devices'] ?? []) as $d) if (!empty($d['device_id'])) $ids[] = 'd' . $d['device_id'];
        foreach (($it['lines'] ?? []) as $l) if (!empty($l['line_id'])) $ids[] = 'l' . $l['line_id'];
        return $ids;
    };
    $cycleClosed = false;
    if ($lastRemise && $lastRestit && $lastRestit['status'] === 'signed') {
        $rIds = $bonItemIdsF($lastRemise);
        $tIds = $bonItemIdsF($lastRestit);
        // Bons migrés sans snapshot : une restitution signée clôture le cycle
        $cycleClosed = ($rIds === null || $tIds === null) ? true : !array_diff($rIds, $tIds);
    }

    echo "<div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:1.5rem; flex-wrap:wrap; gap:.75rem;'>";
    echo "<div style='display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;'>";
    echo "<form method='post' action='index.php' target='_blank' style='display:inline;padding:0;margin:0;'>
        <input type='hidden' name='_entity' value='bon'>
        <input type='hidden' name='_action' value='generate_remise'>
        <input type='hidden' name='agent_id' value='$id'>
        <input type='hidden' name='" . CSRF_TOKEN_NAME . "' value='" . h($CSRF_TOKEN) . "'>
        <button type='submit' class='btn-primary' style='display:inline-flex; align-items:center; gap:5px; box-shadow: 0 4px 10px rgba(67, 97, 238, 0.3);'>📄 Générer le bon de remise</button>
    </form>";
    if ($lastRemise && !$cycleClosed) {
        echo "<a href='?page=pdf_bon&bon_id={$lastRemise['id']}' target='_blank' class='btn-secondary' style='text-decoration:none;display:inline-flex;align-items:center;gap:5px;'>🖨️ Voir le bon actuel</a>";
    }
    echo "</div>";
    // Statut des bons du dernier cycle
    echo "<div style='display:flex;flex-direction:column;gap:4px;font-size:.8rem;'>";
    if ($cycleClosed) {
        $dt = date('d/m/Y H:i', strtotime($lastRestit['signed_at']));
        echo "<span style='color:var(--text3);'>📦 Matériel restitué — cycle " . h($lastRemise['numero']) . " clôturé le $dt</span>";
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
    // Placée en tête de fiche, avec les autres actions sur les bons.
    $signedRemise = $pdo->prepare("SELECT id, numero FROM bons WHERE agent_id=? AND type='remise' AND status='signed' ORDER BY signed_at DESC, id DESC LIMIT 1");
    $signedRemise->execute([$id]); $signedRemise = $signedRemise->fetch();
    if ($signedRemise && $hasDotation && empty($agt['archived'])) {
        echo "<details style='margin-bottom:1.25rem;background:rgba(245,158,11,.05);border:1px solid rgba(245,158,11,.25);border-radius:8px;padding:.6rem .9rem;'>
            <summary style='cursor:pointer;font-size:.85rem;color:var(--warning);font-weight:600;'>📤 Générer un bon de restitution — choisir les équipements restitués</summary>
            <div class='muted' style='font-size:.78rem;margin:.6rem 0;'>Cochez les équipements restitués (restitution partielle possible). Le bon sera lié au bon de remise " . h($signedRemise['numero']) . ". À la signature, les équipements cochés retournent automatiquement en stock.</div>
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
    echo "<div style='background:var(--bg3); padding:1rem; border-radius:var(--radius-sm); margin-bottom:1.5rem;'><h4 style='color:var(--text); margin-bottom:10px;'>📧 Coordonnées</h4><div><strong>Email :</strong> " . h($agt['email']?:'Non renseigné') . "</div><div><strong>Service :</strong> " . h($agt['service_name']?:'Aucun') . "</div></div>";
    
    echo "<h4 style='color:var(--primary); margin-bottom:10px; border-bottom:1px solid var(--border); padding-bottom:5px;'>📞 Lignes attribuées</h4>";
    if(!$lines) echo "<div class='muted' style='margin-bottom:1rem;'>Aucune ligne active.</div>";
    foreach($lines as $l) {
        $byodBadge = !empty($l['personal_device']) ? "<span class='badge' style='background:rgba(56,189,248,.15);color:var(--info);margin-left:6px;'>📲 Tél. perso (BYOD)</span>" : '';
        $esimBadge = !empty($l['esim']) ? "<span class='badge' style='background:rgba(139,92,246,.15);color:#a78bfa;margin-left:6px;'>📲 eSIM</span>" : '';
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

    echo "<h4 style='color:var(--primary); margin-bottom:10px; margin-top:1.5rem; border-bottom:1px solid var(--border); padding-bottom:5px;'>📱 Matériels attribués</h4>";
    $hasAnything = $devices || $byodLines;
    if(!$hasAnything) echo "<div class='muted'>Aucun matériel.</div>";
    foreach($devices as $d) { echo "<div style='background:var(--card2); border:1px solid var(--border); padding:10px; border-radius:8px; margin-bottom:10px;'><strong>".h($d['brand'].' '.$d['name'])."</strong> ".statusBadge($d['status'])."<br><span class='muted'>IMEI: ".h($d['imei'])."</span></div>"; }
    foreach($byodLines as $l) {
        echo "<div style='background:rgba(56,189,248,.07); border:1px solid rgba(56,189,248,.25); padding:10px; border-radius:8px; margin-bottom:10px;'>
                <strong style='color:var(--info);'>📲 Téléphone personnel (BYOD)</strong><br>
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
    
    echo "<h4 style='color:var(--text); margin-bottom:10px;'>📎 Pièces jointes</h4>";
    echo "<form method='post' enctype='multipart/form-data' style='display:flex;gap:10px;margin-bottom:1rem;padding:0;'><input type='hidden' name='_entity' value='attachment'><input type='hidden' name='agent_id' value='$id'><input type='hidden' name='" . CSRF_TOKEN_NAME . "' value='" . h($CSRF_TOKEN) . "'><input type='file' name='file' required style='padding:5px; background:var(--bg3); color:var(--text); border:1px solid var(--border); border-radius:4px; flex:1;'><button type='submit' class='btn-primary' style='padding:5px 10px'>Uploader</button></form>";
    if($att) {
        echo "<ul style='padding-left:1.5rem; margin-bottom:2rem; color:var(--text);'>";
        foreach($att as $a) echo "<li style='margin-bottom:5px;'><a href='{$a['file_path']}' target='_blank' style='color:var(--info); text-decoration:none;'>".h($a['file_name'])."</a></li>";
        echo "</ul>";
    } else { echo "<div class='muted' style='margin-bottom:2rem;'>Aucun document.</div>"; }

    echo "<h4 style='color:var(--text); margin-bottom:1rem;'>🕒 Journal des affectations</h4>";
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
        echo "<h4 style='color:var(--primary); margin-bottom:1rem; border-bottom:1px solid var(--border); padding-bottom:5px;'>📋 Historique des bons de remise / restitution</h4>";

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
                    $badge = "<span style='background:rgba(16,185,129,.15);color:var(--success);font-size:.7rem;font-weight:600;padding:.1rem .45rem;border-radius:999px;'>✅ Signé</span>";
                } elseif ($b['status'] === 'cancelled') {
                    $badge = "<span style='background:rgba(148,163,184,.12);color:var(--text3);font-size:.7rem;font-weight:600;padding:.1rem .45rem;border-radius:999px;' title='" . h($b['cancel_reason'] ?: '') . "'>🚫 Annulé</span>";
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
                    echo "<button type='button' class='btn-icon' style='padding:0 .2rem;font-size:.85rem;' title='Copier le lien de signature' onclick=\"copySignLink(this, '" . h($signUrl) . "')\">🔗</button>";
                    if ($smtpConfigured && !empty($agt['email'])) {
                        echo "<form method='post' action='index.php' target='_blank' style='display:inline;margin:0;padding:0;'>
                            <input type='hidden' name='_entity' value='bon'>
                            <input type='hidden' name='_action' value='send_mail'>
                            <input type='hidden' name='bon_id' value='{$b['id']}'>
                            <input type='hidden' name='" . CSRF_TOKEN_NAME . "' value='" . h($CSRF_TOKEN) . "'>
                            <button type='submit' class='btn-icon' style='padding:0 .2rem;font-size:.85rem;' title='Envoyer le lien de signature à " . h($agt['email']) . "'>📧</button>
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
                        $destPath = UPLOAD_DIR . time() . '_' . $safeName;
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
            // Configuration SMTP (envoi des liens de signature)
            if (isset($d['smtp_host'])) {
                foreach (['smtp_host','smtp_port','smtp_user','smtp_from','smtp_from_name'] as $key) {
                    $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key=?")->execute([trim($d[$key] ?? ''), $key]);
                }
                $sec = in_array($d['smtp_secure'] ?? '', ['tls','ssl','none'], true) ? $d['smtp_secure'] : 'tls';
                $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key='smtp_secure'")->execute([$sec]);
                // Mot de passe : conservé si le champ est laissé vide
                if (($d['smtp_pass'] ?? '') !== '') {
                    $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key='smtp_pass'")->execute([$d['smtp_pass']]);
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
                // SVG retiré : il peut contenir du JavaScript (XSS)
                $allowedLogoMime = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
                if ($_FILES['pdf_logo']['size'] > UPLOAD_MAX_BYTES) {
                    flash('error', 'Logo trop volumineux (max 1 Mo).');
                } elseif (!in_array($mime, $allowedLogoMime, true)) {
                    flash('error', 'Format non autorisé. Utilisez PNG, JPG, GIF ou WEBP.');
                } else {
                    if (!is_dir(UPLOAD_DIR)) mkdir(UPLOAD_DIR, 0755, true);
                    $ext  = pathinfo($_FILES['pdf_logo']['name'], PATHINFO_EXTENSION);
                    $dest = UPLOAD_DIR . 'pdf_logo_' . time() . '.' . strtolower($ext);
                    // Supprimer l'ancien logo
                    $oldLogo = getSetting($pdo, 'pdf_logo_path', '');
                    if ($oldLogo && file_exists($oldLogo)) @unlink($oldLogo);
                    if (move_uploaded_file($_FILES['pdf_logo']['tmp_name'], $dest)) {
                        $pdo->prepare("UPDATE settings SET setting_value=? WHERE setting_key='pdf_logo_path'")->execute([$dest]);
                    }
                }
            }
            flash('success', 'Paramètres enregistrés.');
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
                $st = $pdo->prepare("SELECT id FROM bons WHERE agent_id=? AND type='remise' AND status='signed' ORDER BY signed_at DESC, id DESC LIMIT 1");
                $st->execute([$agentId]);
                $parentId = (int)$st->fetchColumn();
                if (!$agentId || !$parentId) {
                    flash('error', 'Impossible : aucun bon de remise signé pour cet agent.');
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
                          . '<h2 style="color:#4361ee;">📱 SimCity — Signature requise</h2>'
                          . '<p>Bonjour ' . h($b['first_name']) . ',</p>'
                          . '<p>Le bon de <strong>' . $typeLbl . ' de matériel</strong> n° <strong>' . h($b['numero']) . '</strong> vous attend pour signature électronique.</p>'
                          . '<p style="margin:28px 0;text-align:center;"><a href="' . h($url) . '" style="background:#4361ee;color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:bold;">✍️ Signer le bon</a></p>'
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
        } elseif ($ent === 'db_reset') {
            // Réinitialisation complète — super-admin uniquement
            if (empty($_SESSION['is_admin'])) { flash('error', 'Accès refusé.'); }
            elseif (($d['confirm_word'] ?? '') !== 'SUPPRIMER') { flash('error', 'Mot de confirmation incorrect.'); }
            else {
                // Le DROP TABLE (DDL) commite implicitement : on sort proprement de la transaction
                if ($pdo->inTransaction()) $pdo->commit();
                $pdo->exec("SET FOREIGN_KEY_CHECKS = 0");
                $pdo->exec("DROP TABLE IF EXISTS `bons`,`signatures`,`sign_tokens`,`sim_history`,`attachments`,`mobile_lines`,`devices`,`history_logs`,`agents`,`billing_accounts`,`plan_types`,`operators`,`models`,`services`,`settings`,`users`");
                $pdo->exec("SET FOREIGN_KEY_CHECKS = 1");
                session_destroy();
                header('Location: install.php'); exit;
            }
        } elseif ($ent === 'service') {
            if ($act === 'add') $pdo->prepare("INSERT INTO services(name,direction,notes)VALUES(?,?,?)")->execute([S($d,'name'),S($d,'direction'),S($d,'notes')]);
            elseif ($act === 'edit') $pdo->prepare("UPDATE services SET name=?,direction=?,notes=? WHERE id=?")->execute([S($d,'name'),S($d,'direction'),S($d,'notes'),$id]);
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
        } elseif ($ent === 'admin') {
            $isAdminVal = !empty($_SESSION['is_admin']) ? (!empty($d['is_admin']) ? 1 : 0) : null;
            if ($act === 'add') {
                $pdo->prepare("INSERT INTO users(username, password, first_name, last_name, email, is_admin) VALUES(?,?,?,?,?,?)")->execute([S($d,'username'), password_hash(S($d,'password'), PASSWORD_DEFAULT), NV($d,'first_name'), NV($d,'last_name'), NV($d,'email'), $isAdminVal ?? 0]);
                logHistory($pdo, 'admin', $pdo->lastInsertId(), "Création de l'administrateur ".S($d,'username'));
            } elseif ($act === 'edit') {
                $isAdminSet = $isAdminVal !== null ? ', is_admin=?' : '';
                $params = [S($d,'username'), NV($d,'first_name'), NV($d,'last_name'), NV($d,'email')];
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
            } elseif ($act === 'disable') {
                // Empêcher la désactivation de son propre compte
                if ($id === (int)$_SESSION['user_id']) {
                    flash('error', 'Vous ne pouvez pas désactiver votre propre compte.');
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
                if ($id === (int)$_SESSION['user_id']) {
                    flash('error', 'Vous ne pouvez pas supprimer votre propre compte.');
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
                $pdo->prepare("INSERT INTO agents(first_name,last_name,email,service_id)VALUES(?,?,?,?)")->execute([S($d,'first_name'),S($d,'last_name'),NV($d,'email'),IV($d,'service_id')]);
                logHistory($pdo, 'agent', $pdo->lastInsertId(), "Création de la fiche utilisateur");
            } elseif ($act === 'edit') {
                $pdo->prepare("UPDATE agents SET first_name=?,last_name=?,email=?,service_id=? WHERE id=?")->execute([S($d,'first_name'),S($d,'last_name'),NV($d,'email'),IV($d,'service_id'),$id]);
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
                $line = $pdo->query("SELECT id, device_id FROM mobile_lines WHERE id=$lid AND archived=0 AND agent_id IS NULL AND sim_vierge=0")->fetch();
                if (!$line) { $qaError = "Cette ligne n'est plus disponible en stock."; }
                else {
                    $pdo->prepare("UPDATE mobile_lines SET agent_id=?, service_id=?, status='Active' WHERE id=?")->execute([$agentId, $agtRow['service_id'], $lid]);
                    $agtName = getAgentName($pdo, $agentId);
                    logHistory($pdo, 'line', $lid, "Ligne/SIM attribuée à $agtName", $agentId);
                    if ($line['device_id']) {
                        $pdo->prepare("UPDATE devices SET status='Deployed', agent_id=?, service_id=? WHERE id=?")->execute([$agentId, $agtRow['service_id'], $line['device_id']]);
                        logHistory($pdo, 'device', $line['device_id'], "Déployé et associé à la ligne", $agentId);
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
        if (!in_array($ent, ['attachment', 'bon', 'bulk', 'settings', 'admin_signature', 'quick_assign'])) flash('success', 'Opération réussie.');
        if ($pdo->inTransaction()) $pdo->commit();

    } catch (Exception $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        $detail = (defined('APP_DEBUG') && APP_DEBUG) ? ' — ' . $e->getMessage() : '';
        flash('error', "L'opération a échoué et a été annulée (aucune donnée modifiée)$detail.");
    }
    $redirect = 'index.php?page=' . ($_GET['page'] ?? 'dashboard'); if(isset($_GET['tab'])) $redirect .= '&tab='.$_GET['tab']; header('Location: ' . $redirect); exit;
}

// ─── 7. ROUTAGE & VUES ────────────────────────────────────────
$page = preg_replace('/[^a-z_]/', '', $_GET['page'] ?? 'dashboard');
$tab = preg_replace('/[^a-z_]/', '', $_GET['tab'] ?? 'active');

$pageTitles = ['dashboard' => 'Tableau de bord', 'lines' => 'Gestion des Lignes & SIM', 'devices' => 'Parc Matériel & Terminaux', 'refs' => 'Référentiels & Utilisateurs', 'settings' => 'Paramètres', 'history' => 'Historique des Bons de Remise'];
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
    
    $recent = $pdo->query("SELECT l.phone_number, a.first_name, a.last_name, p.name as plan_type, l.status FROM mobile_lines l LEFT JOIN agents a ON l.agent_id = a.id LEFT JOIN plan_types p ON l.plan_id = p.id WHERE l.archived=0 ORDER BY l.created_at DESC LIMIT 5")->fetchAll();

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
    ?>
    <div class="dashboard-grid">
        
      <div style="position:relative; margin-bottom: 1rem;">
        <div class="search-bar" style="background: var(--card); border: 2px solid var(--primary-dim); box-shadow: var(--shadow);">
          <span class="search-bar-icon" style="color:var(--primary)">🔍</span>
          <input type="text" id="dash-search" placeholder="Recherche globale : N° de ligne, IMEI, ICCID, Utilisateur..." oninput="doGlobalSearch(this.value)" autocomplete="off" style="font-size: 1rem; padding: .5rem;">
          <button class="search-bar-clear" id="dash-clear" onclick="document.getElementById('dash-search').value=''; doGlobalSearch('');" style="display:none; font-size:1.2rem;">✕</button>
        </div>
        <div id="dash-search-results" style="display:none; position:absolute; top:100%; left:0; right:0; background:var(--card); border:1px solid var(--border); border-radius:var(--radius); margin-top:.5rem; overflow:hidden; box-shadow:var(--shadow-lg); z-index:100;"></div>
      </div>

      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1rem">
        <a href="?page=lines&open=modal-add-line" class="shortcut-btn shortcut-order"><span class="shortcut-icon">💳</span><span class="shortcut-label">Nouvelle Ligne</span><span class="shortcut-sub">Créer abonnement ou SIM</span></a>
        <a href="?page=devices&open=modal-add-device" class="shortcut-btn shortcut-in"><span class="shortcut-icon">📱</span><span class="shortcut-label">Nouveau Matériel</span><span class="shortcut-sub">Ajouter un téléphone en stock</span></a>
        <a href="?page=refs&tab=agents" class="shortcut-btn shortcut-resa"><span class="shortcut-icon">👤</span><span class="shortcut-label">Nouvel Utilisateur</span><span class="shortcut-sub">Créer un agent pour attribution</span></a>
      </div>

      <?php if($cLinesStk <= $threshSim || $cDevStk <= $threshDevice || $alertSuspended > 0 || $bonsExpired > 0 || $bonsExpSoon > 0): ?>
      <div style="background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.3);padding:1.25rem;border-radius:var(--radius);margin-bottom:1.5rem;">
          <h4 style="color:var(--danger);margin-bottom:10px;display:flex;align-items:center;gap:8px;">⚠️ Points d'attention immédiats</h4>
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
          </ul>
      </div>
      <?php endif; ?>

      <div class="kpi-row">
        <a href="?page=lines&tab=active" class="kpi-card kpi-blue" style="text-decoration:none">
          <div class="kpi-icon">📞</div><div class="kpi-info"><span class="kpi-val"><?=h($cLinesAct)?></span><span class="kpi-label">Lignes Actives</span></div>
          <div class="kpi-sub"><?=$cLinesStk?> SIM vierge<?=($cLinesStk > 1 ? 's' : '')?> en stock</div>
        </a>
        <a href="?page=devices&tab=active" class="kpi-card kpi-violet" style="text-decoration:none">
          <div class="kpi-icon">📱</div><div class="kpi-info"><span class="kpi-val"><?=h($cDevDep)?></span><span class="kpi-label">Mobiles Déployés</span></div>
          <div class="kpi-sub"><?=$cDevStk?> <?=($cDevStk > 1 ? 'terminaux' : 'terminal')?> en stock</div>
        </a>
        <a href="?page=refs&tab=agents" class="kpi-card kpi-green" style="text-decoration:none">
          <div class="kpi-icon">🏢</div><div class="kpi-info"><span class="kpi-val"><?=$pdo->query("SELECT COUNT(*) FROM agents WHERE archived=0")->fetchColumn()?></span><span class="kpi-label">Utilisateurs</span></div>
        </a>
      </div>

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

      <div style="display:grid; grid-template-columns: 1fr 1fr; gap:1.5rem; margin-top:1rem; margin-bottom:1rem;">
          <div class="card" style="margin-bottom:0;">
              <div class="card-header">📱 Répartition par marque</div>
              <div style="padding:1rem; height:250px;"><canvas id="chartBrand"></canvas></div>
          </div>
          <div class="card" style="margin-bottom:0;">
              <div class="card-header">🏢 Top 5 Services (Lignes actives)</div>
              <div style="padding:1rem; height:250px;"><canvas id="chartSvc"></canvas></div>
          </div>
      </div>

      <div class="card" style="margin-top:1rem">
        <div class="card-header"><span class="card-title">📞 Dernières lignes enregistrées</span></div>
        <table class="data-table">
          <thead><tr><th>Numéro</th><th>Utilisateur</th><th>Forfait</th><th>Statut</th></tr></thead>
          <tbody>
            <?php if(empty($recent)): ?><tr><td colspan="4" class="empty-cell">Aucune ligne récente</td></tr><?php endif; ?>
            <?php foreach($recent as $r): ?>
            <tr>
              <td><strong style="font-family:var(--font-mono);color:var(--primary);font-size:1.05rem"><?=formatPhone($r['phone_number'])?></strong></td>
              <td><?=h($r['first_name'].' '.$r['last_name'])?></td>
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
        if(document.getElementById('chartBrand')){
            new Chart(document.getElementById('chartBrand'), {
                type: 'doughnut',
                data: {
                    labels: <?php echo json_encode($brands); ?>,
                    datasets: [{
                        data: <?php echo json_encode($bCounts); ?>,
                        backgroundColor: ['#4361ee', '#3a86ff', '#7b2d8b', '#f59e0b', '#10b981', '#ef4444'],
                        borderWidth: 0
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } } }
            });

            new Chart(document.getElementById('chartSvc'), {
                type: 'bar',
                data: {
                    labels: <?php echo json_encode($svcs); ?>,
                    datasets: [{
                        label: 'Nombre de lignes',
                        data: <?php echo json_encode($sCounts); ?>,
                        backgroundColor: '#4361ee',
                        borderRadius: 5
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } }, x: { ticks: { color: '#94a3b8' } } }, plugins: { legend: { display: false } } }
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
                    if(r.type === 'Ligne') badge = `<span class="badge" style="background:var(--success-dim);color:var(--success)">📞 Ligne</span>`;
                    if(r.type === 'Matériel') badge = `<span class="badge" style="background:var(--primary-dim);color:var(--primary)">📱 Matériel</span>`;
                    if(r.type === 'Agent') badge = `<span class="badge" style="background:var(--info-dim);color:var(--info)">👤 Agent</span>`;
                    
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
    
    $agents = $pdo->query("SELECT id, first_name, last_name FROM agents WHERE archived=0 ORDER BY last_name, first_name")->fetchAll();
    $services = $pdo->query("SELECT id, name FROM services ORDER BY name")->fetchAll();
    $plans = $pdo->query("SELECT p.id, p.name, IFNULL(o.name,'') as operator_name FROM plan_types p LEFT JOIN operators o ON p.operator_id=o.id ORDER BY o.name, p.name")->fetchAll();
    $billings = $pdo->query("SELECT id, account_number, name FROM billing_accounts ORDER BY name")->fetchAll();
    $devices = $pdo->query("SELECT d.id, d.imei, d.serial_number, m.brand, m.name FROM devices d LEFT JOIN models m ON d.model_id=m.id WHERE d.archived=0 AND d.status='Stock' ORDER BY m.brand, m.name")->fetchAll();
    // Toutes les SIM en stock (pour le swap) — vierges ET numérotées non affectées
    $simStock = $pdo->query("SELECT id, iccid, pin, puk, IFNULL(esim,0) as esim FROM mobile_lines WHERE archived=0 AND sim_vierge=1 ORDER BY iccid")->fetchAll();
    ?>
    <div class="page-header">
      <span class="page-title-txt">💳 Inventaire des Lignes & Cartes SIM</span>
      <?php if(!$isArchive): ?><button class="btn-primary" onclick="openModal('modal-add-line')">+ Ajouter une Ligne / SIM</button><?php endif; ?>
    </div>

    <div style="display:flex; gap:10px; margin-bottom:1rem; border-bottom:2px solid var(--border)">
        <a href="?page=lines&tab=active" class="tab-btn <?=$tab==='active'?'active':''?>">📞 Lignes Actives & Suspendues</a>
        <a href="?page=lines&tab=stock" class="tab-btn <?=$tab==='stock'?'active':''?>">📦 Stock (SIM Vierges)</a>
        <a href="?page=lines&tab=archive" class="tab-btn <?=$tab==='archive'?'active':''?>">🗄️ Lignes Résiliées (Archives)</a>
    </div>

    <div class="search-bar-wrap">
      <div class="search-bar">
        <span class="search-bar-icon">🔍</span>
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
        <button type="button" class="btn-secondary" style="padding:.45rem .75rem;font-size:.88rem;" onclick="clearBulk('line')">✕ Annuler</button>
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
          <td><strong style="font-family:var(--font-mono);font-size:1.05rem;color:var(--primary)"><?= !empty($l['sim_vierge']) ? '<span style="color:var(--text3);font-style:italic;font-family:var(--font);">Sans numéro</span>' : formatPhone($l['phone_number']) ?></strong><br>
          <?php if(!empty($l['sim_vierge'])): ?><span class="badge" style="background:rgba(245,158,11,.15);color:var(--warning);font-size:.7rem;">📦 SIM Vierge</span>
          <?php elseif(!empty($l['esim'])): ?><span class="badge" style="background:rgba(139,92,246,.15);color:#a78bfa;font-size:.7rem;">📲 eSIM</span>
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
            <br><span class="muted">🏢 <?=h($l['service_name']?:'Aucun service')?></span>
          </td>
          <td>CF: <strong class="muted"><?=h($l['account_number']?:'-')?></strong><br>
            <?php if($l['operator_name']): ?><span class="muted" style="font-size:.72rem;">📡 <?=h($l['operator_name'])?></span><br><?php endif; ?>
            <span class="badge badge-muted"><?=h($l['plan_name']?:'Aucun forfait')?></span>
          </td>
          <td>
            <?php if(!empty($l['personal_device'])): ?>
                <span class="badge" style="background:rgba(56,189,248,.15);color:var(--info);">📲 Téléphone perso</span>
            <?php elseif($l['imei']): ?>
                <strong><?=h($l['brand'].' '.$l['model_name'])?></strong><br><span class="muted">IMEI: <?=h($l['imei'])?></span>
            <?php elseif($l['status'] === 'Active'): ?>
                <span class="badge" style="background:rgba(245,158,11,.15);color:var(--warning);font-size:0.75rem;">⚠️ En attente de mobile</span>
            <?php else: ?>
                <span class="muted">Aucun appareil</span>
            <?php endif; ?>
          </td>
          <td><?=statusBadge($l['status'])?></td>
          <td class="actions">
            <?php $hist = fetchEntityHistory($pdo, 'line', $l['id']); ?>
            <?php if(!$isArchive): ?>
                <button class="btn-icon btn-edit" title="Modifier" onclick='openEditModal(<?=json_encode($l, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>,"line")'>✏️</button>
                <button class="btn-icon" title="Historique" onclick='showHistory(<?=json_encode($hist, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>)'>🕒</button>
                <?php if($l['agent_id']): ?>
                <a href="index.php?page=pdf_bon&agent_id=<?=$l['agent_id']?>" target="_blank" class="btn-icon" title="Voir / générer le bon de remise" style="text-decoration:none;">🖨️</a>
                <?php endif; ?>
                <button class="btn-icon" title="Changer la SIM (garder le numéro)" style="color:var(--warning)"
                    onclick="openSimSwap(<?=$l['id']?>, '<?=h($l['phone_number'])?>', '<?=h($l['iccid'])?>', <?=!empty($l['esim'])?'true':'false'?>, '<?=h($l['eid']?:'')?>')">🔄</button>
                <button type="button" class="btn-icon btn-del" title="Résilier / Archiver" onclick="openArchiveLine(<?=$l['id']?>, <?=(int)$l['device_id']?>, <?=json_encode($l['device_id'] ? ($l['brand'].' '.$l['model_name'].' — S/N: '.($l['serial_number']?:($l['imei']?:'—'))) : '')?>)">🗄️</button>
            <?php else: ?>
                <button class="btn-icon" title="Historique" onclick='showHistory(<?=json_encode($hist, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>)'>🕒</button>
                <form method="post" style="display:inline"><input type="hidden" name="_entity" value="line"><input type="hidden" name="_action" value="restore"><input type="hidden" name="_id" value="<?=$l['id']?>"><button type="submit" class="btn-icon" title="Restaurer" style="color:var(--success)">♻️</button></form>
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>

    <?php foreach(['add'=>'Nouvelle Ligne / SIM', 'edit'=>'Modifier'] as $act => $title): ?>
    <div class="modal-overlay" id="modal-<?=$act?>-line">
      <div class="modal modal-lg"><div class="modal-header"><h3><?=$title?></h3><button type="button" class="modal-close" onclick="closeModal('modal-<?=$act?>-line')">✕</button></div>
      <form method="post" onsubmit="return lineFormCheck('<?=$act?>')"><input type="hidden" name="_entity" value="line"><input type="hidden" name="_action" value="<?=$act?>"><?php if($act==='edit') echo '<input type="hidden" name="_id" id="edit-id-line">'; ?>
      <div class="form-grid">
        <div class="form-group"><label>Numéro de Ligne</label>
          <div id="<?=$act?>-phone-wrapper"><input type="text" name="phone_number" id="<?=$act?>-phone_number" placeholder="06 xx xx xx xx"></div>
          <?php if($act === 'add'): ?>
          <label style="display:flex;align-items:center;gap:.5rem;margin-top:.5rem;cursor:pointer;">
            <input type="checkbox" name="sim_vierge" id="<?=$act?>-sim_vierge" value="1"
              onchange="toggleSimVierge('<?=$act?>')"
              style="width:15px;height:15px;accent-color:var(--warning);cursor:pointer;flex-shrink:0;">
            <span style="font-size:.83rem;color:var(--warning);font-weight:600;">📦 SIM vierge</span>
            <span style="font-size:.78rem;color:var(--text3);">— pas de numéro pour le moment</span>
          </label>
          <?php endif; ?>
        </div>
        <div class="form-group"><label>Utilisateur affecté</label><select name="agent_id" id="<?=$act?>-agent_id"><option value="">-- Sélectionner dans le référentiel --</option><?php foreach($agents as $a): ?><option value="<?=$a['id']?>"><?=h($a['last_name'].' '.$a['first_name'])?></option><?php endforeach; ?></select></div>
        <div class="form-group"><label>Compte de Facturation</label><select name="billing_id" id="<?=$act?>-billing_id"><option value="">-- Sélectionner --</option><?php foreach($billings as $b): ?><option value="<?=$b['id']?>"><?=h($b['account_number'].' - '.$b['name'])?></option><?php endforeach; ?></select></div>
        <div class="form-group"><label>Forfait</label><select name="plan_id" id="<?=$act?>-plan_id"><option value="">-- Sélectionner --</option><?php foreach($plans as $p): ?><option value="<?=$p['id']?>"><?= $p['operator_name'] ? h($p['operator_name']).' — ' : '' ?><?=h($p['name'])?></option><?php endforeach; ?></select></div>
        <div class="form-group"><label>Service / Direction</label><select name="service_id" id="<?=$act?>-service_id"><option value="">-- Sélectionner --</option><?php foreach($services as $s): ?><option value="<?=$s['id']?>"><?=h($s['name'])?></option><?php endforeach; ?></select></div>
        <div class="form-group"><label>Statut de la ligne</label>
          <div id="<?=$act?>-status-wrapper" style="position:relative;">
            <select name="status" id="<?=$act?>-status"><option value="Active">Active</option><option value="Stock">En Stock (Non activée)</option><option value="Suspended">Suspendue</option></select>
          </div>
        </div>
        <div class="form-group form-full"><label style="color:var(--primary)">💳 Informations SIM</label><hr style="border:0;border-top:1px solid var(--border);margin-top:-5px"></div>
        <div class="form-group form-full">
          <label style="display:flex;align-items:center;gap:.5rem;cursor:pointer;">
            <input type="checkbox" name="esim" id="<?=$act?>-esim" value="1"
              onchange="toggleEsim('<?=$act?>')"
              style="width:15px;height:15px;accent-color:#a78bfa;cursor:pointer;flex-shrink:0;">
            <span style="font-size:.83rem;color:#a78bfa;font-weight:600;">📲 eSIM</span>
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
        <div class="form-group form-full"><label style="color:var(--primary)">📱 Matériel & Notes</label><hr style="border:0;border-top:1px solid var(--border);margin-top:-5px"></div>
        <div class="form-group form-full">
          <label style="display:flex;align-items:center;gap:.6rem;cursor:pointer;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.7rem 1rem;">
            <input type="checkbox" name="personal_device" id="<?=$act?>-personal_device" value="1"
              onchange="togglePersonalDevice('<?=$act?>')"
              style="width:16px;height:16px;accent-color:var(--info);cursor:pointer;flex-shrink:0;">
            <span>
              <strong style="color:var(--info);">📲 Téléphone personnel</strong>
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
        <h3>🔄 Changement de Carte SIM</h3>
        <button type="button" class="modal-close" onclick="closeModal('modal-sim-swap')">✕</button>
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
              <span id="swap-esim-badge" style="display:none;background:rgba(139,92,246,.15);color:#a78bfa;font-size:.72rem;font-weight:600;padding:.15rem .5rem;border-radius:999px;margin-left:8px;">📲 eSIM</span>
            </div>
            <span style="font-size:.82rem;color:var(--text2);">SIM actuelle : <code id="swap-old-iccid" style="color:var(--warning)"></code></span>
          </div>
        </div>

        <!-- Bouton pour voir l'historique SIM de cette ligne -->
        <div style="text-align:right;margin-bottom:1.25rem;">
          <button type="button" onclick="loadSimHistory()" style="background:none;border:none;color:var(--primary);font-size:.83rem;cursor:pointer;text-decoration:underline;">📋 Voir l'historique des SIM précédentes</button>
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
          <button type="submit" class="btn-primary">🔄 Confirmer le changement</button>
        </div>
      </form></div>
    </div>

    <!-- Modal archivage ligne -->
    <div class="modal-overlay" id="modal-archive-line">
      <div class="modal" style="max-width:480px;">
        <div class="modal-header"><h3>🗄️ Archiver / Résilier une ligne</h3><button type="button" class="modal-close" onclick="closeModal('modal-archive-line')">✕</button></div>
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
            <button type="submit" class="btn-primary" style="background:var(--danger);box-shadow:none;">🗄️ Archiver</button>
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
    $agents = $pdo->query("SELECT id, first_name, last_name FROM agents WHERE archived=0 ORDER BY last_name, first_name")->fetchAll();
    $services = $pdo->query("SELECT id, name FROM services ORDER BY name")->fetchAll();
    ?>
    <div class="page-header">
      <span class="page-title-txt">📱 Parc Matériel Physique</span>
      <?php if(!$isArchive): ?><button class="btn-primary" onclick="openModal('modal-add-device')">+ Ajouter un équipement</button><?php endif; ?>
    </div>

    <div style="display:flex; gap:10px; margin-bottom:1rem; border-bottom:2px solid var(--border)">
        <a href="?page=devices&tab=active" class="tab-btn <?=$tab==='active'?'active':''?>">📱 Matériels Déployés / Réparation</a>
        <a href="?page=devices&tab=stock" class="tab-btn <?=$tab==='stock'?'active':''?>">📦 Stock (Disponibles)</a>
        <a href="?page=devices&tab=archive" class="tab-btn <?=$tab==='archive'?'active':''?>">🗄️ Archives (Perdus / Cassés)</a>
    </div>

    <div class="search-bar-wrap">
      <div class="search-bar"><span class="search-bar-icon">🔍</span><input type="text" placeholder="Rechercher IMEI, Modèle, Agent..." oninput="tableSearch(this,'tbody-dev','count')"></div>
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
        <button type="button" class="btn-secondary" style="padding:.45rem .75rem;font-size:.88rem;" onclick="clearBulk('device')">✕ Annuler</button>
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
          <td>IMEI: <code class="ref"><?=h($d['imei'])?></code><br><span class="muted">S/N: <?=h($d['serial_number']?:'-')?></span><?php if($d['inventory_label']): ?><br><span class="badge badge-muted" style="font-size:.68rem;">🏷️ <?=h($d['inventory_label'])?></span><?php endif; ?></td>
          <td><strong><?=h($d['first_name'].' '.$d['last_name']?:'Non affecté')?></strong><br><span class="muted">🏢 <?=h($d['service_name']?:'-')?></span></td>
          <td><?=statusBadge($d['status'])?></td>
          <td><?=$d['purchase_date']?date('d/m/Y',strtotime($d['purchase_date'])):'-'?></td>
          <td class="actions">
            <?php $hist = fetchEntityHistory($pdo, 'device', $d['id']); ?>
            <?php if(!$isArchive): ?>
                <button class="btn-icon btn-edit" title="Modifier" onclick='openEditModal(<?=json_encode($d, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>,"device")'>✏️</button>
                <button class="btn-icon" title="Historique de ce matériel" onclick='showHistory(<?=json_encode($hist, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>)'>🕒</button>
                <button type="button" class="btn-icon btn-del" title="Archiver (Casse, Perte...)" onclick="openArchiveDevice(<?=$d['id']?>, <?=(int)$d['line_id']?>, <?=json_encode($d['line_id'] ? formatPhone($d['line_phone']) : '')?>)">🗄️</button>
            <?php else: ?>
                <button class="btn-icon" title="Historique de ce matériel" onclick='showHistory(<?=json_encode($hist, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>)'>🕒</button>
                <form method="post" style="display:inline"><input type="hidden" name="_entity" value="device"><input type="hidden" name="_action" value="restore"><input type="hidden" name="_id" value="<?=$d['id']?>"><button type="submit" class="btn-icon" title="Restaurer au Stock" style="color:var(--success)">♻️</button></form>
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
        <div class="modal-header"><h3>🗄️ Archiver un matériel</h3><button type="button" class="modal-close" onclick="closeModal('modal-archive-device')">✕</button></div>
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
            <button type="submit" class="btn-primary" style="background:var(--danger);box-shadow:none;">🗄️ Archiver</button>
          </div>
        </form>
      </div>
    </div>

    <?php foreach(['add'=>'Ajouter', 'edit'=>'Modifier'] as $act => $title): ?>
    <div class="modal-overlay" id="modal-<?=$act?>-device">
      <div class="modal"><div class="modal-header"><h3><?=$title?> un Matériel</h3><button type="button" class="modal-close" onclick="closeModal('modal-<?=$act?>-device')">✕</button></div>
      <form method="post"><input type="hidden" name="_entity" value="device"><input type="hidden" name="_action" value="<?=$act?>"><?php if($act==='edit') echo '<input type="hidden" name="_id" id="edit-id-device">'; ?>
      <div class="form-grid">
        <div class="form-group form-full"><label>Modèle *</label>
          <select name="model_id" id="<?=$act?>-model_id" required><option value="">-- Choisir le modèle --</option>
          <?php foreach($models as $m): ?><option value="<?=$m['id']?>"><?=h($m['brand'].' '.$m['name'])?></option><?php endforeach; ?></select>
        </div>
        <div class="form-group"><label>IMEI 1 *</label><input type="text" name="imei" id="<?=$act?>-imei" required></div>
        <div class="form-group"><label>IMEI 2</label><input type="text" name="imei2" id="<?=$act?>-imei2"></div>
        <div class="form-group"><label>Numéro de série</label><input type="text" name="serial_number" id="<?=$act?>-serial_number"></div>
        <div class="form-group"><label>🏷️ Libellé d'inventaire</label><input type="text" name="inventory_label" id="<?=$act?>-inventory_label" placeholder="Ex: MOB-0042, IT-2024-001..."></div>
        <div class="form-group"><label>Date d'achat</label><input type="date" name="purchase_date" id="<?=$act?>-purchase_date"></div>
        <div class="form-group"><label>Statut</label>
          <select name="status" id="<?=$act?>-status"><option value="Stock">En Stock</option><option value="Deployed">Déployé</option><option value="Repair">En réparation</option></select>
        </div>
        <div class="form-group"><label>Utilisateur (Agent)</label>
          <select name="agent_id" id="<?=$act?>-agent_id"><option value="">-- Aucun --</option>
          <?php foreach($agents as $a): ?><option value="<?=$a['id']?>"><?=h($a['last_name'].' '.$a['first_name'])?></option><?php endforeach; ?></select>
        </div>
        <div class="form-group form-full"><label>Service</label>
          <select name="service_id" id="<?=$act?>-service_id"><option value="">-- Sélectionner --</option>
          <?php foreach($services as $s): ?><option value="<?=$s['id']?>"><?=h($s['name'])?></option><?php endforeach; ?></select>
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
    $tabs = ['agents'=>'👤 Utilisateurs', 'services'=>'🏢 Services', 'models'=>'📋 Modèles', 'plans'=>'🌐 Forfaits', 'operators'=>'📡 Opérateurs', 'billing'=>'💶 Facturation', 'admins'=>'🔐 Comptes Admin', 'settings'=>'⚙️ Paramètres'];
    
    if ($tab === 'agents') {
        $data = $pdo->query("SELECT a.*, s.name as service_name FROM agents a LEFT JOIN services s ON a.service_id=s.id ORDER BY a.archived ASC, a.last_name, a.first_name")->fetchAll();
        $cols = ['Nom'=>'last_name', 'Prénom'=>'first_name', 'Email'=>'email', 'Service'=>'service_name']; $ent = 'agent';
    } elseif ($tab === 'services') {
        $data = $pdo->query("SELECT * FROM services ORDER BY name")->fetchAll();
        $cols = ['Nom'=>'name', 'Direction'=>'direction', 'Notes'=>'notes']; $ent = 'service';
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
        $data = $pdo->query("SELECT id, username, active, IFNULL(first_name,'') as first_name, IFNULL(last_name,'') as last_name, IFNULL(email,'') as email, DATE_FORMAT(created_at, '%d/%m/%Y %H:%i') as created_at FROM users ORDER BY active DESC, last_name, first_name, username")->fetchAll();
        $cols = ['Identifiant'=>'username', 'Nom'=>'last_name', 'Prénom'=>'first_name', 'Email'=>'email', 'Créé le'=>'created_at']; $ent = 'admin';
        // Visa DSI de chaque compte (une signature par admin)
        $sigMap = $pdo->query("SELECT id, signature_data FROM users WHERE signature_data IS NOT NULL AND signature_data != ''")->fetchAll(PDO::FETCH_KEY_PAIR);
    } elseif ($tab === 'settings') {
        $allSettings = $pdo->query("SELECT * FROM settings ORDER BY id")->fetchAll();
        $ent = 'settings';
    }
    ?>
    <div class="page-header">
      <span class="page-title-txt">⚙️ Référentiels & Paramètres</span>
      <?php if($tab !== 'settings'): ?>
      <button class="btn-primary" onclick="openModal('modal-add-<?=$ent?>')">+ Ajouter (<?=$tabs[$tab]?>)</button>
      <?php endif; ?>
    </div>

    <div style="display:flex; gap:10px; margin-bottom:1rem; border-bottom:2px solid var(--border); overflow-x:auto;">
        <?php foreach($tabs as $k => $label): ?><a href="?page=refs&tab=<?=$k?>" class="tab-btn <?=$tab===$k?'active':''?>"><?=$label?></a><?php endforeach; ?>
    </div>

    <?php if($tab === 'settings'): 
        $currentLogo = getSetting($pdo, 'pdf_logo_path', '');
    ?>
    <!-- ── ONGLET PARAMÈTRES ───────────────────────────────────── -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;align-items:start;">
    <div style="display:flex;flex-direction:column;gap:1.5rem;">

      <!-- Bloc logo -->
      <div class="card">
        <div class="card-header">🖼️ Logo des bons de remise PDF</div>
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
            <button type="submit" class="btn-primary">💾 Enregistrer</button>
          </div>
        </form>
      </div>

      <!-- Bloc URL du site -->
      <?php $currentSiteUrl = getSetting($pdo, 'site_url', ''); ?>
      <div class="card">
        <div class="card-header">🔗 URL publique du site</div>
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
            <button type="submit" class="btn-primary">💾 Enregistrer</button>
          </div>
        </form>
      </div>

      <!-- Bloc SMTP -->
      <div class="card">
        <div class="card-header">📧 Envoi d'e-mails (liens de signature)</div>
        <form method="post" style="padding:1.5rem;">
          <input type="hidden" name="_entity" value="settings">
          <input type="hidden" name="_action" value="save">
          <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
            Permet d'envoyer le lien de signature d'un bon directement à l'agent (bouton 📧).<br>
            Laissez le serveur vide pour désactiver l'envoi d'e-mails.
          </p>
          <div class="form-grid">
            <div class="form-group"><label>Serveur SMTP</label><input type="text" name="smtp_host" value="<?=h(getSetting($pdo,'smtp_host',''))?>" placeholder="smtp.monentreprise.fr"></div>
            <div class="form-group"><label>Port</label><input type="number" name="smtp_port" value="<?=h(getSetting($pdo,'smtp_port','587'))?>" min="1" max="65535"></div>
            <div class="form-group"><label>Chiffrement</label>
              <?php $smtpSec = getSetting($pdo,'smtp_secure','tls'); ?>
              <select name="smtp_secure">
                <option value="tls" <?=$smtpSec==='tls'?'selected':''?>>STARTTLS (port 587)</option>
                <option value="ssl" <?=$smtpSec==='ssl'?'selected':''?>>SSL/TLS (port 465)</option>
                <option value="none" <?=$smtpSec==='none'?'selected':''?>>Aucun (interne uniquement)</option>
              </select>
            </div>
            <div class="form-group"><label>Identifiant</label><input type="text" name="smtp_user" value="<?=h(getSetting($pdo,'smtp_user',''))?>" autocomplete="off" placeholder="Vide si serveur sans authentification"></div>
            <div class="form-group"><label>Mot de passe <span style="font-weight:400;text-transform:none;">(vide = inchangé)</span></label><input type="password" name="smtp_pass" value="" autocomplete="new-password"></div>
            <div class="form-group"><label>Adresse expéditrice</label><input type="email" name="smtp_from" value="<?=h(getSetting($pdo,'smtp_from',''))?>" placeholder="dsi@monentreprise.fr"></div>
            <div class="form-group form-full"><label>Nom de l'expéditeur</label><input type="text" name="smtp_from_name" value="<?=h(getSetting($pdo,'smtp_from_name','SimCity — DSI'))?>"></div>
          </div>
          <div style="padding-top:1rem;border-top:1px solid var(--border);margin-top:1rem;">
            <button type="submit" class="btn-primary">💾 Enregistrer</button>
          </div>
        </form>
      </div>

      </div><!-- fin colonne gauche -->

      <div style="display:flex;flex-direction:column;gap:1.5rem;"><!-- colonne droite -->

      <!-- Bloc seuils -->
      <div class="card">
        <div class="card-header">🔔 Seuils d'alerte Stock</div>
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
            <button type="submit" class="btn-primary">💾 Enregistrer les seuils</button>
          </div>
        </form>
      </div>

      </div><!-- fin colonne droite -->

    </div><!-- fin grille paramètres -->

    <?php if(!empty($_SESSION['is_admin'])): ?>
    <!-- Bloc sauvegarde — super-admin uniquement -->
    <div class="card" style="margin-top:1.5rem;">
      <div class="card-header">💾 Sauvegarde de la base de données</div>
      <div style="padding:1.5rem;">
        <p style="color:var(--text2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6;">
          Télécharge un fichier <strong>.sql</strong> complet (structure + toutes les données : lignes, matériels, agents, bons signés, historique…)
          à copier sur une <strong>clé USB</strong> ou un partage réseau.<br>
          <strong>Restauration :</strong> <code style="font-family:var(--font-mono);font-size:.8rem;">mysql -u root -p simcity_db &lt; simcity_sauvegarde_XXXX.sql</code>
          (ou via phpMyAdmin → Importer).
        </p>
        <a href="?page=backup_sql" class="btn-primary" style="text-decoration:none;display:inline-flex;align-items:center;gap:6px;">💾 Télécharger la sauvegarde (.sql)</a>
        <p style="font-size:.78rem;color:var(--text3);margin-top:.9rem;">
          💡 Pensez-y avant chaque mise à jour de l'application, et régulièrement (le fichier contient aussi les signatures électroniques).
        </p>
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
          <h3 style="color:var(--danger);">⚠️ Confirmer la réinitialisation</h3>
          <button type="button" class="modal-close" onclick="closeModal('modal-db-reset')">✕</button>
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
    <div class="search-bar-wrap">
      <div class="search-bar"><span class="search-bar-icon">🔍</span><input type="text" placeholder="Filtrer..." oninput="tableSearch(this,'tbody-refs','count')"></div>
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
                <?=h($row[$k])?> <span class="badge badge-danger" style="font-size:.65rem;">🗄️ Parti</span>
              <?php elseif($name==='Identifiant' && $tab==='admins'): ?>
                <?=h($row[$k])?>
                <?php if(empty($row['active'])): ?>
                  <span class="badge badge-warning" style="font-size:.65rem;margin-left:4px;">🔒 Désactivé</span>
                <?php elseif($row['id'] === (int)$_SESSION['user_id']): ?>
                  <span class="badge badge-info" style="font-size:.65rem;margin-left:4px;">👤 Vous</span>
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
                <button class="btn-icon" title="Voir la Fiche Utilisateur" style="color:var(--primary)" onclick="viewAgent(<?=$row['id']?>, '<?=h($row['first_name'].' '.$row['last_name'])?>')">👁️</button>
                <?php if(empty($row['archived'])): ?>
                    <button class="btn-icon btn-edit" title="Modifier" onclick='openEditModal(<?=json_encode($row, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>,"<?=$ent?>")'>✏️</button>
                    <form method="post" style="display:inline" onsubmit="return confirm('Archiver cet agent ? Son téléphone retournera en stock et sa ligne sera libérée automatiquement.')">
                        <input type="hidden" name="_entity" value="agent">
                        <input type="hidden" name="_action" value="archive">
                        <input type="hidden" name="_id" value="<?=$row['id']?>">
                        <button type="submit" class="btn-icon btn-del" title="Archiver (Départ de la société)">🗄️</button>
                    </form>
                <?php else: ?>
                    <form method="post" style="display:inline" onsubmit="return confirm('Restaurer cet agent dans la liste active ?')">
                        <input type="hidden" name="_entity" value="agent">
                        <input type="hidden" name="_action" value="restore">
                        <input type="hidden" name="_id" value="<?=$row['id']?>">
                        <button type="submit" class="btn-icon" title="Restaurer (Retour dans la société)" style="color:var(--success)">♻️</button>
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
                            <button type="submit" class="btn-icon" title="Désactiver ce compte" style="color:var(--warning)">🔒</button>
                        </form>
                    <?php else: ?>
                        <form method="post" style="display:inline" onsubmit="return confirm('Réactiver le compte « <?=h($row['username']) ?> » ?')">
                            <input type="hidden" name="_entity" value="admin">
                            <input type="hidden" name="_action" value="enable">
                            <input type="hidden" name="_id" value="<?=$row['id']?>">
                            <button type="submit" class="btn-icon" title="Réactiver ce compte" style="color:var(--success)">🔓</button>
                        </form>
                    <?php endif; ?>
                    </span>
                <?php endif; ?>
                <?php if($isSelf || !empty($_SESSION['is_admin'])): ?>
                    <button class="btn-icon" title="<?=$isSelf ? 'Ma signature (visa DSI)' : 'Signature (visa DSI) de ce compte'?>" style="color:var(--primary)"
                      onclick='openSigModal(<?=$row['id']?>, <?=json_encode(trim($row['first_name'].' '.$row['last_name']) ?: $row['username'], JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>, <?=json_encode($sigMap[$row['id']] ?? '', JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>)'>✍️</button>
                <?php endif; ?>
                <button class="btn-icon btn-edit" title="Modifier" onclick='openEditModal(<?=json_encode($row, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>,"<?=$ent?>")'>✏️</button>
                <?php if(!$isSelf): ?>
                    <form method="post" style="display:inline" onsubmit="return confirm('Supprimer définitivement le compte « <?=h($row['username']) ?> » ?')">
                        <input type="hidden" name="_entity" value="admin">
                        <input type="hidden" name="_action" value="delete">
                        <input type="hidden" name="_id" value="<?=$row['id']?>">
                        <button type="submit" class="btn-icon btn-del" title="Supprimer ce compte">🗑️</button>
                    </form>
                <?php endif; ?>
            <?php else: ?>
            <button class="btn-icon btn-edit" title="Modifier" onclick='openEditModal(<?=json_encode($row, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT)?>,"<?=$ent?>")'>✏️</button>
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
          <h3>✍️ Signature (visa DSI) — <span id="sig-admin-name"></span></h3>
          <button type="button" class="modal-close" onclick="closeModal('modal-signature')">✕</button>
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
              onclick="return confirm('Supprimer cette signature ?')">🗑️ Supprimer cette signature</button>
          </div>
          <label style="margin-bottom:.4rem;" id="sig-canvas-label">Dessiner la signature</label>
          <div style="border:2px dashed var(--border2);border-radius:8px;background:#fff;touch-action:none;">
            <canvas id="dsiSigCanvas" height="140" style="display:block;width:100%;border-radius:8px;"></canvas>
          </div>
          <div class="modal-footer" style="margin-top:1rem;">
            <button type="button" class="btn-secondary" onclick="dsiSigClear()">🗑️ Effacer le cadre</button>
            <button type="submit" class="btn-primary" id="dsi-sig-save" disabled>💾 Enregistrer la signature</button>
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
      <div class="modal"><div class="modal-header"><h3><?=$title?></h3><button type="button" class="modal-close" onclick="closeModal('modal-<?=$act?>-<?=$ent?>')">✕</button></div>
      <form method="post"><input type="hidden" name="_entity" value="<?=$ent?>"><input type="hidden" name="_action" value="<?=$act?>"><?php if($act==='edit') echo '<input type="hidden" name="_id" id="edit-id-'.$ent.'">'; ?>
      <div class="form-grid">
        <?php if ($ent === 'agent'): $svcs=$pdo->query("SELECT id,name FROM services")->fetchAll(); ?>
            <div class="form-group"><label>Nom *</label><input type="text" name="last_name" id="<?=$act?>-last_name" required></div>
            <div class="form-group"><label>Prénom *</label><input type="text" name="first_name" id="<?=$act?>-first_name" required></div>
            <div class="form-group form-full"><label>Adresse e-mail</label><input type="email" name="email" id="<?=$act?>-email"></div>
            <div class="form-group form-full"><label>Service / Direction</label><select name="service_id" id="<?=$act?>-service_id"><option value="">-- Aucun --</option><?php foreach($svcs as $s): ?><option value="<?=$s['id']?>"><?=h($s['name'])?></option><?php endforeach; ?></select></div>
        <?php elseif ($ent === 'service'): ?>
            <div class="form-group"><label>Nom</label><input type="text" name="name" id="<?=$act?>-name" required></div>
            <div class="form-group"><label>Direction</label><input type="text" name="direction" id="<?=$act?>-direction"></div>
            <div class="form-group form-full"><label>Notes</label><textarea name="notes" id="<?=$act?>-notes" rows="2"></textarea></div>
        <?php elseif ($ent === 'model'): ?>
            <div class="form-group"><label>Marque</label><input type="text" name="brand" id="<?=$act?>-brand" required></div>
            <div class="form-group"><label>Modèle</label><input type="text" name="name" id="<?=$act?>-name" required></div>
            <div class="form-group form-full"><label>Catégorie</label><select name="category" id="<?=$act?>-category"><option>Smartphone</option><option>Tablette</option><option>Borne 4G</option></select></div>
        <?php elseif ($ent === 'plan'): ?>
            <div class="form-group form-full"><label>Opérateur *</label>
              <select name="operator_id" id="<?=$act?>-operator_id" required>
                <option value="">-- Sélectionner un opérateur --</option>
                <?php foreach(($operators??[]) as $op): ?><option value="<?=$op['id']?>"><?=h($op['name'])?></option><?php endforeach; ?>
              </select>
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
    $pairBorderColors = ['#10b981','#4361ee','#f59e0b','#8b5cf6','#ec4899','#38bdf8'];

    $now = time();
    function bonStatusHtml(array $b, int $now): string {
        if ($b['status'] === 'signed')    return '<span style="background:rgba(16,185,129,.15);color:#10b981;font-size:.72rem;font-weight:700;padding:.15rem .5rem;border-radius:999px;white-space:nowrap;">✅ Signé</span>';
        if ($b['status'] === 'cancelled') return '<span style="background:rgba(148,163,184,.1);color:#94a3b8;font-size:.72rem;font-weight:700;padding:.15rem .5rem;border-radius:999px;white-space:nowrap;">🚫 Annulé</span>';
        if ($b['expires_at'] && strtotime($b['expires_at']) < $now) return '<span style="background:rgba(245,158,11,.15);color:#f59e0b;font-size:.72rem;font-weight:700;padding:.15rem .5rem;border-radius:999px;white-space:nowrap;">⏰ Expiré</span>';
        return '<span style="background:rgba(56,189,248,.15);color:#38bdf8;font-size:.72rem;font-weight:700;padding:.15rem .5rem;border-radius:999px;white-space:nowrap;">⏳ En attente</span>';
    }
    ?>
    <div class="page-header">
      <span class="page-title-txt">📋 Historique des Bons de Remise</span>
    </div>

    <div class="search-bar-wrap">
      <div class="search-bar"><span class="search-bar-icon">🔍</span>
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
          <span style="font-size:.8rem;color:var(--text3);">🏢 <?=h($pair['service_name'])?></span>
          <?php if($pair['agent_archived']): ?><span style="background:rgba(245,158,11,.15);color:var(--warning);font-size:.68rem;font-weight:600;padding:.1rem .4rem;border-radius:999px;">🗄️ Parti</span><?php endif; ?>
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
        <?php foreach(['remise'=>['📥','Bon de Remise','#10b981','rgba(16,185,129,.06)'],'restitution'=>['📤','Bon de Restitution','#f59e0b','rgba(245,158,11,.06)']] as $btype=>[$icon,$label,$color,$bg]):
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

$content = ob_get_clean();
?>

<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title><?=h($pageTitles[$page]??'SimCity')?> – SimCity</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=DM+Sans:ital,wght@0,400;0,500;1,400&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script>(function(){ if (localStorage.getItem('pm_theme') === 'light') document.documentElement.setAttribute('data-theme','light'); })();</script>
<style>
/* CSS UNIFIÉ MINIFIÉ */
:root{--bg:#080b14;--bg2:#0f1420;--bg3:#141928;--card:#111827;--card2:#1a2235;--border:rgba(255,255,255,.07);--border2:rgba(67,97,238,.25);--primary:#4361ee;--primary-dim:rgba(67,97,238,.15);--primary-glow:rgba(67,97,238,.4);--success:#10b981;--success-dim:rgba(16,185,129,.15);--danger:#ef4444;--danger-dim:rgba(239,68,68,.15);--warning:#f59e0b;--info:#38bdf8;--info-dim:rgba(56,189,248,.15);--text:#f0f4ff;--text2:#94a3b8;--text3:#4b5563;--sidebar-w:255px;--topbar-h:64px;--radius:12px;--radius-sm:8px;--font:'DM Sans',sans-serif;--font-display:'Outfit',sans-serif;--font-mono:'JetBrains Mono',monospace;}
[data-theme="light"]{--bg:#f0f2f7;--bg2:#ffffff;--bg3:#e8ebf2;--card:#ffffff;--card2:#f4f6fb;--border:rgba(0,0,0,.09);--border2:rgba(0,48,135,.25);--primary:#003087;--primary-dim:rgba(0,48,135,.1);--primary-glow:rgba(0,48,135,.3);--success:#0a7c55;--success-dim:rgba(10,124,85,.12);--danger:#c8102e;--danger-dim:rgba(200,16,46,.12);--warning:#d97706;--info:#0077b6;--info-dim:rgba(0,119,182,.12);--text:#0d1b3e;--text2:#3d5080;--text3:#8a9abf;}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0} body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:15px;}
::-webkit-scrollbar{width:6px;height:6px} ::-webkit-scrollbar-track{background:var(--bg2)} ::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px} ::-webkit-scrollbar-thumb:hover{background:var(--primary)}
.app{display:flex;min-height:100vh}
.sidebar{width:var(--sidebar-w);height:100vh;position:fixed;left:0;top:0;z-index:100;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden;}
.sidebar-logo{padding:1.5rem 1.5rem 1rem;display:flex;align-items:center;gap:.75rem;border-bottom:1px solid var(--border);}
.sidebar-logo .logo-icon{font-size:1.8rem;filter:drop-shadow(0 0 8px var(--primary-glow))}
.sidebar-logo .logo-text{font-family:var(--font-display);font-weight:800;font-size:1.2rem;}
.sidebar-section{padding:.75rem 1rem .25rem;font-size:.68rem;color:var(--text3);font-weight:600;text-transform:uppercase;letter-spacing:.1em;}
.sidebar-nav{flex:1;padding:.5rem;overflow-y:auto;}
.nav-item{display:flex;align-items:center;gap:.75rem;padding:.65rem 1rem;border-radius:var(--radius-sm);color:var(--text2);text-decoration:none;font-size:.88rem;font-weight:500;transition:all .2s;}
.nav-item:hover{background:var(--primary-dim);color:var(--text)} .nav-item.active{background:var(--primary-dim);color:var(--primary)}
.nav-icon{font-size:1.1rem;width:24px;text-align:center} .btn-hamburger{display:none;background:none;border:none;color:var(--text2);font-size:1.4rem;padding:.25rem;cursor:pointer}
.main{margin-left:var(--sidebar-w);flex:1;display:flex;flex-direction:column;min-width:0}
.topbar{height:var(--topbar-h);background:var(--bg2);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 1.5rem;gap:1rem;position:sticky;top:0;z-index:50;}
.topbar-title{font-family:var(--font-display);font-weight:700;font-size:1.1rem;flex:1}
.btn-theme{background:var(--card2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text2);font-size:.88rem;padding:.3rem .65rem;cursor:pointer}
.content{padding:2rem;flex:1;max-width:1400px;margin:0 auto;width:100%;}
.page-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;}
.page-title-txt{font-family:var(--font-display);font-weight:700;font-size:1.4rem;}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:1.5rem;}
.card-header{padding:1rem 1.5rem;border-bottom:1px solid var(--border);font-family:var(--font-display);font-weight:600;font-size:.95rem;color:var(--text2);}

.data-table{width:100%;border-collapse:collapse} 
.data-table th{padding:.85rem 1.25rem;text-align:left;font-size:.75rem;font-weight:600;color:var(--text3);text-transform:uppercase;border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer;user-select:none;transition:color 0.15s;}
.data-table th:hover{color:var(--primary);}
.data-table th.sorted{color:var(--primary);font-weight:700;}

.data-table td{padding:.85rem 1.25rem;border-bottom:1px solid var(--border);font-size:.88rem} .data-table tbody tr:hover{background:rgba(255,255,255,.02)}
.empty-cell{text-align:center;color:var(--text3);padding:3rem!important;font-style:italic} .muted{color:var(--text2)!important;font-size:.82rem;}
.search-bar-wrap{margin-bottom:1rem;} .search-bar{display:flex;align-items:center;gap:.6rem;background:var(--card2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.55rem .9rem; transition:border-color .2s; }
.search-bar:focus-within { border-color:var(--primary); box-shadow:0 0 0 3px var(--primary-dim); }
.search-bar-icon{font-size:1rem;opacity:.5;flex-shrink:0;} .search-bar input{flex:1;background:none;border:none;outline:none;color:var(--text);font-size:.9rem;} .search-count{font-size:.75rem;color:var(--text3);margin-top:.3rem;}
.badge{display:inline-block;padding:.2rem .65rem;border-radius:999px;font-size:.72rem;font-weight:600;white-space:nowrap;} .badge-success{background:var(--success-dim);color:#6ee7b7;} .badge-danger{background:var(--danger-dim);color:#fca5a5;} .badge-warning{background:rgba(245,158,11,.15);color:var(--warning);} .badge-info{background:var(--info-dim);color:var(--info);} .badge-muted{background:rgba(255,255,255,.06);color:var(--text2);}
.btn-primary{background:linear-gradient(135deg,var(--primary),#3a86ff);border:none;border-radius:var(--radius-sm);padding:.65rem 1.5rem;color:#fff;font-weight:600;cursor:pointer;box-shadow: 0 4px 15px var(--primary-glow); transition:all .2s;} .btn-primary:hover{transform:translateY(-1px);box-shadow: 0 6px 20px var(--primary-glow);}
.btn-secondary{background:var(--card2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.65rem 1.25rem;color:var(--text2);cursor:pointer;} .btn-secondary:hover{border-color:var(--primary);color:var(--text)}
.btn-icon{background:none;border:none;cursor:pointer;font-size:1rem;padding:.3rem .5rem;border-radius:var(--radius-sm);color:var(--text2);transition:all .15s;} .btn-edit:hover{background:var(--primary-dim);color:var(--primary)} .btn-del:hover{background:var(--danger-dim);color:var(--danger)}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:1.25rem;} .form-group{display:flex;flex-direction:column;gap:.4rem;} .form-full{grid-column:1/-1;}
label{font-size:.78rem;font-weight:600;color:var(--text3);text-transform:uppercase;} input,select,textarea{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.7rem 1rem;color:var(--text);width:100%;}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-dim);}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:1000;align-items:center;justify-content:center;padding:1rem;backdrop-filter:blur(4px)} .modal-overlay.open{display:flex;animation:fadeIn .2s ease;}
.modal{background:var(--card);border:1px solid var(--border2);border-radius:var(--radius);width:100%;max-width:580px;max-height:90vh;overflow-y:auto;box-shadow:var(--shadow-lg);animation:slideUp .25s ease;} .modal-lg{max-width:700px;}
@keyframes fadeIn{from{opacity:0}to{opacity:1}} @keyframes slideUp{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}
.modal-header{padding:1.25rem 1.5rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;position:sticky;top:0;background:var(--card);z-index:1} .modal-close{background:none;border:none;color:var(--text3);font-size:1.1rem;cursor:pointer} .modal-close:hover{color:var(--text);}
.modal form{padding:1.5rem;} .modal-footer{display:flex;justify-content:flex-end;gap:.75rem;padding-top:1.25rem;border-top:1px solid var(--border);margin-top:1.25rem}
.dashboard-grid{display:flex;flex-direction:column;gap:1.5rem;} .kpi-row{display:grid;grid-template-columns:repeat(3,1fr);gap:1.25rem;}
.kpi-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem 1.5rem;display:flex;align-items:center;gap:1rem;position:relative;overflow:hidden;cursor:pointer;transition:transform .2s;}
.kpi-card::before{content:'';position:absolute;inset:0;opacity:.04;} .kpi-card:hover{transform:translateY(-2px);}
.kpi-blue{border-color:rgba(67,97,238,.3);} .kpi-blue::before{background:radial-gradient(circle at 100% 0,#4361ee,transparent 60%);}
.kpi-violet{border-color:rgba(123,45,139,.3);} .kpi-violet::before{background:radial-gradient(circle at 100% 0,#7b2d8b,transparent 60%);}
.kpi-green{border-color:rgba(16,185,129,.3);} .kpi-green::before{background:radial-gradient(circle at 100% 0,#10b981,transparent 60%);}
.kpi-icon{font-size:2rem;} .kpi-val{font-family:var(--font-display);font-size:2rem;font-weight:800;line-height:1.1;} .kpi-label{font-size:.78rem;color:var(--text2);text-transform:uppercase;}
.shortcut-btn{display:flex;flex-direction:column;gap:.35rem;padding:1.25rem;border-radius:var(--radius);border:1px solid var(--border);text-decoration:none;transition:border-color .2s;} .shortcut-btn:hover{border-color:var(--primary);}
.shortcut-label{font-weight:700;color:var(--text)} .shortcut-in{background:rgba(16,185,129,.08);} .shortcut-order{background:rgba(67,97,238,.08);} .shortcut-resa{background:rgba(56,189,248,.08);}
.tab-btn{padding:.6rem 1.2rem;border:1px solid transparent;border-radius:var(--radius-sm) var(--radius-sm) 0 0;text-decoration:none;color:var(--text2);font-weight:600;font-size:.9rem;} .tab-btn.active{background:var(--card);border-color:var(--border);border-bottom-color:var(--card);color:var(--primary);margin-bottom:-2px;z-index:2;}
@media(max-width:900px){.sidebar{transform:translateX(-100%)}.sidebar.open{transform:translateX(0)}.main{margin-left:0}.btn-hamburger{display:block}}
[data-theme="light"] .data-table tbody tr:hover{background:rgba(0,48,135,.04)} [data-theme="light"] .btn-primary{background:linear-gradient(135deg,#003087,#1a53c5)} [data-theme="light"] .tab-btn.active{background:#fff;border-color:var(--border);border-bottom-color:#fff;}
</style>
</head>
<body>
<div class="app">
<div class="sidebar-overlay" id="sidebar-overlay" onclick="closeSidebar()"></div>
<aside class="sidebar" id="sidebar">
  <div class="sidebar-logo">
    <span class="logo-icon">📱</span>
    <div><div class="logo-text">SimCity</div><div class="logo-ver">v<?=defined('APP_VERSION') ? APP_VERSION : '1.0'?></div></div>
  </div>
  <nav class="sidebar-nav">
    <div class="sidebar-section">Principal</div>
    <a href="?page=dashboard" class="nav-item <?=$page==='dashboard'?'active':''?>"><span class="nav-icon">🏠</span><span class="nav-label">Tableau de bord</span></a>
    
    <div class="sidebar-section">Parc & Stocks</div>
    <a href="?page=lines" class="nav-item <?=$page==='lines'?'active':''?>"><span class="nav-icon">💳</span><span class="nav-label">Lignes & SIM</span></a>
    <a href="?page=devices" class="nav-item <?=$page==='devices'?'active':''?>"><span class="nav-icon">📱</span><span class="nav-label">Matériels (Mobiles)</span></a>
    
    <div class="sidebar-section">Outils</div>
    <a href="?page=history" class="nav-item <?=$page==='history'?'active':''?>"><span class="nav-icon">📋</span><span class="nav-label">Historique des bons</span></a>
    <a href="?page=refs" class="nav-item <?=$page==='refs'?'active':''?>"><span class="nav-icon">⚙️</span><span class="nav-label">Référentiels & Comptes</span></a>
    <?php
    $navOperators = $pdo->query("SELECT name, website FROM operators WHERE website IS NOT NULL AND website != '' ORDER BY name")->fetchAll();
    foreach($navOperators as $op): ?>
    <a href="<?=h($op['website'])?>" target="_blank" class="nav-item"><span class="nav-icon">🌐</span><span class="nav-label"><?=h($op['name'])?></span></a>
    <?php endforeach; ?>
  </nav>
  <div style="margin-top:auto; padding:1rem;">
    <a href="?action=logout" class="nav-item" style="color:var(--danger); border: 1px solid var(--danger-dim);"><span class="nav-icon">🚪</span><span class="nav-label">Déconnexion</span></a>
  </div>
</aside>

<main class="main">
  <div class="topbar">
    <button class="btn-hamburger" onclick="openSidebar()">☰</button>
    <span class="topbar-title"><?=h($pageTitles[$page]??'Accueil')?></span>
    <div class="topbar-right">
        <span style="font-size:0.8rem; color:var(--text3); margin-right:10px;">Connecté(e): <strong style="color:var(--primary)"><?php
            $adminDisplay = $_SESSION['username'];
            if (!empty($_SESSION['admin_fullname'])) $adminDisplay = $_SESSION['admin_fullname'];
            echo h($adminDisplay);
        ?></strong></span>
        <button class="btn-theme" onclick="toggleTheme()">🌙 Sombre</button>
    </div>
  </div>
  <?php $flashes=getFlashes(); if($flashes): ?><div style="padding:1rem 2rem 0"><?php foreach($flashes as $f): ?><div style="padding:.85rem;border-radius:8px;margin-bottom:1rem;<?=($f['type']??'')==='error' ? 'background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.3)' : 'background:var(--success-dim);color:#10b981;border:1px solid rgba(16,185,129,.3)'?>"><?=(($f['type']??'')==='error'?'⚠️ ':'')?><?=h($f['msg'])?></div><?php endforeach; ?></div><?php endif; ?>
  <div class="content"><?=$content?></div>
</main>
</div>

<div class="modal-overlay" id="modal-history">
  <div class="modal"><div class="modal-header"><h3>🕒 Historique des affectations</h3><button type="button" class="modal-close" onclick="closeModal('modal-history')">✕</button></div>
  <div style="padding:1.5rem;" id="history-content"></div>
  </div>
</div>

<div class="modal-overlay" id="modal-view-agent">
  <div class="modal modal-lg" style="max-width:900px">
    <div class="modal-header"><h3 id="agent-view-title">👤 Fiche Utilisateur</h3><button type="button" class="modal-close" onclick="closeModal('modal-view-agent')">✕</button></div>
    <div id="agent-view-content" style="padding:1.5rem; max-height: 70vh; overflow-y:auto;"></div>
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

    // Injecter aussi dans les modals/fiches chargées dynamiquement via fetch
    const _origFetch = window.fetch;
    window._csrfToken = token;
    window._csrfName  = tokenName;
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
function applyTheme(t){ document.documentElement.setAttribute('data-theme',t==='light'?'light':''); localStorage.setItem('pm_theme',t); }
function toggleTheme(){ applyTheme((localStorage.getItem('pm_theme')||'dark')==='dark'?'light':'dark'); }
applyTheme(localStorage.getItem('pm_theme')||'dark');

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
      if(th.textContent.trim() === 'Actions') { th.style.cursor = 'default'; return; }
      th.title = 'Cliquez pour trier'; let sortOrder = 1;

      th.addEventListener('click', () => {
        const rows = Array.from(tbody.querySelectorAll('tr'));
        if (rows.length === 0 || rows[0].querySelector('.empty-cell')) return;

        sortOrder = sortOrder === 1 ? -1 : 1;
        headers.forEach(h => { h.innerHTML = h.innerHTML.replace(' ↑', '').replace(' ↓', ''); h.classList.remove('sorted'); });
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
  // Restaure la case is_admin pour les comptes admin
  if(ent === 'admin') {
    const chkAdmin = document.getElementById('edit-is_admin');
    if(chkAdmin) chkAdmin.checked = (data.is_admin == 1 || data.is_admin === '1');
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

// À l'enregistrement d'une ligne : un utilisateur est affecté mais le statut
// est resté « En Stock » → proposer de passer la ligne en « Active ».
function lineFormCheck(act) {
  const agentSel  = document.getElementById(act + '-agent_id');
  const statusSel = document.getElementById(act + '-status');
  const simVierge = document.getElementById(act + '-sim_vierge');
  if (simVierge && simVierge.checked) return true;   // SIM vierge : reste en stock
  if (agentSel && statusSel && agentSel.value !== '' && statusSel.value === 'Stock') {
    if (confirm("Cette ligne est affectée à un utilisateur mais son statut est « En Stock (Non activée) ».\n\nPasser la ligne en « Active » ?")) {
      statusSel.value = 'Active';
    }
  }
  return true;
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
            let badge = h.agent_name ? `<span class="badge badge-muted" style="margin-left:8px;font-size:0.7rem">👤 ${h.agent_name}</span>` : '';
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
</script>
</body>
</html>