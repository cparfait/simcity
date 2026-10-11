<?php
// ============================================================
//  SimCity — API JSON en lecture seule pour chatIA (bibliothèque)
//
//  Utilisée par api.php (point d'entrée) et par Référentiels et
//  Paramètres → Paramètres → API chatIA. Aucune écriture dans le
//  parc : seules les tables rate_limits (limite de débit) et settings
//  (dernier appel) sont touchées.
//
//  Données transmises — liste blanche, colonne par colonne :
//    - ligne : numéro, statut, agent (nom, prénom, service), service,
//      opérateur, forfait, compte de facturation, type de SIM, ICCID*,
//      terminal associé, date d'activation ;
//    - terminal : modèle, catégorie, statut, IMEI*, n° de série*,
//      n° d'inventaire*, enrôlement MDM ;
//    - bon : numéro, type, statut, dates.
//    (*) seulement si « identifiants techniques » est coché.
//  JAMAIS : codes PIN/PUK (1 et 2), RIO, code d'activation eSIM, EID,
//  e-mails, notes libres, signatures, jetons de signature, factures.
//  Les requêtes ne SÉLECTIONNENT même pas ces colonnes : une erreur de
//  mise en forme ne peut pas les faire fuiter.
// ============================================================

require_once __DIR__ . '/lib_format.php';

const SIMCITY_API_VERSION = 1;
const SIMCITY_API_RESSOURCES = ['etat', 'ligne', 'agent', 'stock', 'synthese'];

// Réglages (table settings) — clé => [valeur par défaut, libellé]. Repris
// par schema.php pour les créer à l'installation.
const SIMCITY_API_SETTINGS = [
    'api_chatia_enabled'     => ['0',   "API chatIA — accès en lecture seule activé (0/1)"],
    'api_chatia_key_hash'    => ['',    "API chatIA — empreinte SHA-256 de la clé (la clé n'est jamais stockée)"],
    'api_chatia_key_hint'    => ['',    "API chatIA — 4 derniers caractères de la clé (repère)"],
    'api_chatia_key_date'    => ['',    "API chatIA — date de génération de la clé"],
    'api_chatia_key_by'      => ['',    "API chatIA — compte qui a généré la clé"],
    'api_chatia_rate'        => ['120', "API chatIA — appels maximum par minute et par adresse"],
    'api_chatia_ip_allow'    => ['',    "API chatIA — adresses autorisées (IP ou CIDR, vide = toutes)"],
    'api_chatia_identifiers' => ['1',   "API chatIA — transmettre ICCID, IMEI, n° de série et d'inventaire (0/1)"],
    'api_chatia_last_call'   => ['',    "API chatIA — dernier appel accepté (date|adresse|ressource)"],
];

// Garde-fou contre le moissonnage par mots de passe : au-delà de N échecs
// d'authentification en M minutes depuis une adresse, tout est refusé.
const SIMCITY_API_REFUS_MAX     = 20;
const SIMCITY_API_REFUS_MINUTES = 15;
const SIMCITY_API_LIGNES_MAX    = 500;
const SIMCITY_API_AGENTS_MAX    = 10;

// ─────────────────────────────────────────────────────────────
// Libellés
// ─────────────────────────────────────────────────────────────

/** Libellé d'un statut de ligne ou de matériel (mêmes mots que l'interface). */
function simcity_api_statut_libelle(?string $s): string {
    $map = ['Stock' => 'En Stock / Dispo', 'Deployed' => 'Déployé / Actif', 'Repair' => 'Réparation', 'HS' => 'Casse / Rebus',
            'Lost' => 'Perdu / Volé', 'Active' => 'Active', 'Suspended' => 'Suspendue', 'Resiliated' => 'Résiliée'];
    return $map[(string)$s] ?? (string)$s;
}

/** [code, libellé] du statut d'un bon (expiration calculée comme dans l'interface). */
function simcity_api_bon_statut(array $b, ?int $now = null): array {
    $now = $now ?? time();
    if (($b['status'] ?? '') === 'signed')    return ['signe', 'Signé'];
    if (($b['status'] ?? '') === 'cancelled') return ['annule', 'Annulé'];
    if (!empty($b['expires_at']) && strtotime((string)$b['expires_at']) < $now) return ['expire', 'Lien de signature expiré'];
    return ['en_attente', 'En attente de signature'];
}

// ─────────────────────────────────────────────────────────────
// Authentification et filtrage des appelants
// ─────────────────────────────────────────────────────────────

/** Clé présentée dans « Authorization: Bearer … » ; '' si absente.
 *  Apache en CGI/FPM ne transmet pas l'en-tête Authorization à PHP : le
 *  .htaccess le recopie dans HTTP_AUTHORIZATION, et getallheaders() sert de
 *  repli (module Apache, serveur intégré de PHP). */
function simcity_api_bearer(array $server, array $headers = []): string {
    $brut = (string)($server['HTTP_AUTHORIZATION'] ?? $server['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
    if ($brut === '') {
        foreach ($headers as $nom => $valeur) {
            if (strcasecmp((string)$nom, 'Authorization') === 0) { $brut = (string)$valeur; break; }
        }
    }
    if (!preg_match('/^\s*Bearer\s+([A-Za-z0-9._~+\/=-]{16,200})\s*$/i', $brut, $m)) return '';
    return $m[1];
}

/** Empreinte stockée d'une clé : la clé elle-même n'est jamais enregistrée
 *  (ni en base, ni dans les sauvegardes SQL). Clé aléatoire de 256 bits :
 *  un SHA-256 simple suffit, aucun dictionnaire ne s'applique. */
function simcity_api_key_hash(string $cle): string {
    return hash('sha256', $cle);
}

/** Comparaison à temps constant de la clé présentée avec l'empreinte stockée. */
function simcity_api_key_valid(string $empreinte, string $cle): bool {
    if ($empreinte === '' || $cle === '') return false;
    return hash_equals($empreinte, simcity_api_key_hash($cle));
}

/** Nouvelle clé : 32 octets aléatoires, en hexadécimal (64 caractères). */
function simcity_api_key_new(): string {
    return bin2hex(random_bytes(32));
}

/** L'adresse $ip appartient-elle au réseau $cidr (« 10.0.0.0/8 », « ::1/128 »,
 *  ou une adresse seule) ? IPv4 et IPv6, sans extension. */
function simcity_api_cidr_match(string $ip, string $cidr): bool {
    $cidr = trim($cidr);
    if ($cidr === '') return false;
    [$reseau, $prefixe] = array_pad(explode('/', $cidr, 2), 2, null);
    $a = @inet_pton(trim($ip)); $b = @inet_pton(trim($reseau));
    if ($a === false || $b === false || strlen($a) !== strlen($b)) return false;
    $bits = strlen($a) * 8;
    $p = ($prefixe === null || $prefixe === '') ? $bits : (ctype_digit($prefixe) ? (int)$prefixe : -1);
    if ($p < 0 || $p > $bits) return false;
    $octets = intdiv($p, 8); $reste = $p % 8;
    if ($octets && substr($a, 0, $octets) !== substr($b, 0, $octets)) return false;
    if ($reste) {
        $masque = chr((0xFF << (8 - $reste)) & 0xFF);
        if ((ord($a[$octets]) & ord($masque)) !== (ord($b[$octets]) & ord($masque))) return false;
    }
    return true;
}

/** Liste d'adresses saisie dans l'interface (virgules, espaces, retours à la
 *  ligne) → [entrées valides, entrées refusées]. */
function simcity_api_ip_list_parse(string $brut): array {
    $ok = []; $ko = [];
    foreach (preg_split('/[\s,;]+/', trim($brut), -1, PREG_SPLIT_NO_EMPTY) as $e) {
        [$adr, $pre] = array_pad(explode('/', $e, 2), 2, null);
        $v = filter_var($adr, FILTER_VALIDATE_IP);
        $max = ($v !== false && strpos($adr, ':') !== false) ? 128 : 32;
        if ($v !== false && ($pre === null || (ctype_digit($pre) && (int)$pre <= $max))) $ok[] = $e;
        else $ko[] = $e;
    }
    return [array_values(array_unique($ok)), $ko];
}

/** Liste vide = toutes les adresses ; sinon l'appelant doit y figurer. */
function simcity_api_ip_allowed(string $ip, string $liste): bool {
    [$entrees] = simcity_api_ip_list_parse($liste);
    if (!$entrees) return trim($liste) === '';
    foreach ($entrees as $e) if (simcity_api_cidr_match($ip, $e)) return true;
    return false;
}

/** Réglages effectifs de l'API (valeurs par défaut si la ligne manque :
 *  base pas encore migrée par index.php). */
function simcity_api_settings(PDO $pdo): array {
    $vals = [];
    foreach (SIMCITY_API_SETTINGS as $k => [$def]) $vals[$k] = $def;
    try {
        $cles = array_keys(SIMCITY_API_SETTINGS);
        $st = $pdo->prepare("SELECT setting_key, setting_value FROM settings WHERE setting_key IN ("
                            . implode(',', array_fill(0, count($cles), '?')) . ")");
        $st->execute($cles);
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
            if (array_key_exists($r['setting_key'], $vals)) $vals[$r['setting_key']] = (string)$r['setting_value'];
        }
    } catch (Throwable $e) {
        // Table absente : API considérée comme désactivée (valeurs par défaut).
    }
    return [
        'enabled'     => $vals['api_chatia_enabled'] === '1',
        'key_hash'    => strtolower(trim($vals['api_chatia_key_hash'])),
        'key_hint'    => $vals['api_chatia_key_hint'],
        'key_date'    => $vals['api_chatia_key_date'],
        'key_by'      => $vals['api_chatia_key_by'],
        'rate'        => max(1, min(1000, (int)$vals['api_chatia_rate'] ?: 120)),
        'ip_allow'    => $vals['api_chatia_ip_allow'],
        'identifiers' => $vals['api_chatia_identifiers'] !== '0',
        'last_call'   => $vals['api_chatia_last_call'],
    ];
}

/** Enregistre un réglage de l'API (crée la ligne si besoin). */
function simcity_api_setting_set(PDO $pdo, string $key, string $value): void {
    $label = SIMCITY_API_SETTINGS[$key][1] ?? $key;
    $pdo->prepare("INSERT INTO settings (setting_key, setting_value, label) VALUES (?,?,?)
                   ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)")->execute([$key, $value, $label]);
}

// ─────────────────────────────────────────────────────────────
// Limite de débit — table rate_limits (seaux propres à l'API : les
// appels de chatIA ne verrouillent ni la connexion ni le formulaire public)
// ─────────────────────────────────────────────────────────────

function simcity_api_rate_count(PDO $pdo, string $bucket, string $ip, int $minutes): int {
    try {
        $st = $pdo->prepare("SELECT COUNT(*) FROM rate_limits WHERE bucket=? AND ip=? AND hit_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)");
        $st->execute([$bucket, $ip, $minutes]);
        return (int)$st->fetchColumn();
    } catch (Throwable $e) {
        return 0;   // table absente : ne pas casser l'API pour un compteur
    }
}

function simcity_api_rate_hit(PDO $pdo, string $bucket, string $ip): void {
    try {
        $pdo->prepare("INSERT INTO rate_limits (bucket, ip) VALUES (?,?)")->execute([$bucket, $ip]);
        // Purge opportuniste, comme publicRateAllow() : au-delà de 24 h les
        // lignes ne servent plus (ni à la limite, ni aux compteurs affichés).
        if (random_int(1, 50) === 1) $pdo->exec("DELETE FROM rate_limits WHERE hit_at < DATE_SUB(NOW(), INTERVAL 1 DAY)");
    } catch (Throwable $e) {
    }
}

/** Compteurs affichés dans Paramètres → API chatIA : appels acceptés
 *  et refusés sur 24 h, toutes adresses confondues. */
function simcity_api_usage(PDO $pdo): array {
    $out = ['acceptes' => 0, 'refuses' => 0];
    try {
        $st = $pdo->query("SELECT bucket, COUNT(*) n FROM rate_limits
                           WHERE bucket IN ('api_chatia','api_chatia_refus') AND hit_at > DATE_SUB(NOW(), INTERVAL 1 DAY) GROUP BY bucket");
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
            $out[$r['bucket'] === 'api_chatia' ? 'acceptes' : 'refuses'] = (int)$r['n'];
        }
    } catch (Throwable $e) {
    }
    return $out;
}

// ─────────────────────────────────────────────────────────────
// Mise en forme (liste blanche) — fonctions pures, testées sans base
// ─────────────────────────────────────────────────────────────

function simcity_api_txt($v): ?string {
    $v = trim((string)($v ?? ''));
    return $v === '' ? null : $v;
}

/** Terminal (matériel) : modèle, statut, enrôlement MDM ; identifiants
 *  techniques seulement si $ids. Clés du tableau source préfixées « d_ ». */
function simcity_api_terminal_vue(array $r, bool $ids): ?array {
    if (empty($r['d_id'])) return null;
    $t = [
        'modele'         => simcity_api_txt(trim(($r['d_brand'] ?? '') . ' ' . ($r['d_model'] ?? ''))),
        'categorie'      => simcity_api_txt($r['d_category'] ?? null),
        'statut'         => simcity_api_txt($r['d_status'] ?? null),
        'statut_libelle' => simcity_api_statut_libelle($r['d_status'] ?? ''),
        'mdm'            => !empty($r['d_mdm']),
        'archive'        => !empty($r['d_archived']),
    ];
    if ($ids) {
        $t['imei']         = simcity_api_txt($r['d_imei'] ?? null);
        $t['numero_serie'] = simcity_api_txt($r['d_serial'] ?? null);
        $t['inventaire']   = simcity_api_txt($r['d_inventory'] ?? null);
    }
    return $t;
}

/** Ligne mobile, d'après une ligne de SIMCITY_API_SQL_LIGNES. */
function simcity_api_ligne_vue(array $r, bool $ids): array {
    $numero = simcity_phone_canon($r['phone_number'] ?? '');
    $agent = null;
    if (!empty($r['agent_id'])) {
        $agent = ['nom' => simcity_api_txt($r['a_last'] ?? null), 'prenom' => simcity_api_txt($r['a_first'] ?? null),
                  'service' => simcity_api_txt($r['a_service'] ?? null)];
    }
    $sim = ['type' => !empty($r['esim']) ? 'esim' : 'physique', 'vierge' => !empty($r['sim_vierge'])];
    if ($ids) $sim['iccid'] = simcity_api_txt($r['iccid'] ?? null);
    $forfait = simcity_api_txt($r['plan_name'] ?? null);
    $compte = simcity_api_txt($r['billing_number'] ?? null);
    return [
        'numero'             => $numero !== '' ? $numero : null,
        'numero_affiche'     => $numero !== '' ? implode(' ', str_split($numero, 2)) : null,
        'statut'             => simcity_api_txt($r['status'] ?? null),
        'statut_libelle'     => simcity_api_statut_libelle($r['status'] ?? ''),
        'archivee'           => !empty($r['archived']),
        'agent'              => $agent,
        'service'            => simcity_api_txt($r['l_service'] ?? null) ?? ($agent['service'] ?? null),
        'operateur'          => simcity_api_txt($r['operator_name'] ?? null),
        'forfait'            => $forfait === null ? null : ['nom' => $forfait, 'data' => simcity_api_txt($r['plan_data'] ?? null)],
        'compte_facturation' => $compte === null ? null : ['numero' => $compte, 'nom' => simcity_api_txt($r['billing_name'] ?? null)],
        'sim'                => $sim,
        'terminal'           => simcity_api_terminal_vue($r, $ids),
        'terminal_personnel' => !empty($r['personal_device']),
        'date_activation'    => simcity_api_txt($r['activation_date'] ?? null),
    ];
}

/** Bon de remise / restitution : jamais le jeton, la signature ni le contenu figé. */
function simcity_api_bon_vue(array $b, ?int $now = null): array {
    [$code, $libelle] = simcity_api_bon_statut($b, $now);
    return [
        'numero'         => simcity_api_txt($b['numero'] ?? null),
        'type'           => ($b['type'] ?? '') === 'restitution' ? 'restitution' : 'remise',
        'statut'         => $code,
        'statut_libelle' => $libelle,
        'cree_le'        => simcity_api_txt($b['created_at'] ?? null),
        'signe_le'       => $code === 'signe' ? simcity_api_txt($b['signed_at'] ?? null) : null,
    ];
}

/** Échappe les jokers de LIKE dans un fragment saisi. */
function simcity_api_like(string $t): string {
    return '%' . addcslashes($t, '\\%_') . '%';
}

/** Mots d'un nom (« Jean-Pierre DURAND », « Mme d'Angelo ») : civilités
 *  retirées (« M. » réduirait la recherche aux noms qui contiennent un m),
 *  4 mots au plus. */
function simcity_api_mots(string $s): array {
    $civilites = ['m', 'mr', 'mme', 'mlle', 'madame', 'monsieur', 'mademoiselle'];
    $mots = preg_split("/[\\s\\-'’.,]+/u", mb_substr(trim($s), 0, 100), -1, PREG_SPLIT_NO_EMPTY);
    $mots = array_filter($mots, fn($m) => !in_array(mb_strtolower($m, 'UTF-8'), $civilites, true));
    return array_slice(array_values($mots), 0, 4);
}

// ─────────────────────────────────────────────────────────────
// Lectures en base
// ─────────────────────────────────────────────────────────────

// Colonnes SÉLECTIONNÉES une à une (jamais l.*) : pin, puk, pin2, puk2, rio,
// activation_code, eid, notes et options_details ne quittent pas la base.
const SIMCITY_API_SQL_LIGNES = "SELECT l.id, l.phone_number, l.iccid, l.status, l.archived, l.agent_id,
        IFNULL(l.esim,0) esim, IFNULL(l.sim_vierge,0) sim_vierge, IFNULL(l.personal_device,0) personal_device,
        l.activation_date, sl.name l_service,
        a.first_name a_first, a.last_name a_last, sa.name a_service,
        p.name plan_name, p.data_limit plan_data, o.name operator_name,
        b.account_number billing_number, b.name billing_name,
        d.id d_id, d.imei d_imei, d.serial_number d_serial, d.inventory_label d_inventory, d.status d_status,
        d.mdm d_mdm, d.archived d_archived, m.brand d_brand, m.name d_model, m.category d_category
    FROM mobile_lines l
    LEFT JOIN services sl ON sl.id = l.service_id
    LEFT JOIN agents a ON a.id = l.agent_id
    LEFT JOIN services sa ON sa.id = a.service_id
    LEFT JOIN plan_types p ON p.id = l.plan_id
    LEFT JOIN operators o ON o.id = p.operator_id
    LEFT JOIN billing_accounts b ON b.id = l.billing_id
    LEFT JOIN devices d ON d.id = l.device_id
    LEFT JOIN models m ON m.id = d.model_id";

/** Lignes d'après un numéro, un agent ou un service. Retourne [lignes, tronqué]. */
function simcity_api_lignes(PDO $pdo, array $critere, bool $ids): array {
    $where = []; $args = [];
    if (isset($critere['numero'])) {
        $where[] = sprintf(SIMCITY_SQL_PHONE_CANON, 'l.phone_number') . ' = ?';
        $args[] = $critere['numero'];
    }
    if (isset($critere['agent'])) {
        $mots = simcity_api_mots($critere['agent']);
        if (!$mots) return [[], false];   // « M. » seul : jamais tout le parc
        $where[] = 'l.archived = 0';
        foreach ($mots as $mot) {
            $where[] = '(a.first_name LIKE ? OR a.last_name LIKE ?)';
            array_push($args, simcity_api_like($mot), simcity_api_like($mot));
        }
    }
    if (isset($critere['service'])) {
        $where[] = 'l.archived = 0';
        $where[] = '(sl.name LIKE ? OR (l.service_id IS NULL AND sa.name LIKE ?))';
        array_push($args, simcity_api_like($critere['service']), simcity_api_like($critere['service']));
    }
    if (!$where) return [[], false];
    $st = $pdo->prepare(SIMCITY_API_SQL_LIGNES . ' WHERE ' . implode(' AND ', $where)
        . ' ORDER BY l.archived, a.last_name, a.first_name, l.phone_number LIMIT ' . (SIMCITY_API_LIGNES_MAX + 1));
    $st->execute($args);
    $rows = $st->fetchAll(PDO::FETCH_ASSOC);
    $tronque = count($rows) > SIMCITY_API_LIGNES_MAX;
    return [array_map(fn($r) => simcity_api_ligne_vue($r, $ids), array_slice($rows, 0, SIMCITY_API_LIGNES_MAX)), $tronque];
}

/** Agents dont le nom correspond, avec leur dotation (lignes, terminaux, bons). */
function simcity_api_agents(PDO $pdo, string $nom, bool $ids): array {
    $mots = simcity_api_mots($nom);
    if (!$mots) return [];
    $where = []; $args = [];
    foreach ($mots as $mot) {
        $where[] = '(a.first_name LIKE ? OR a.last_name LIKE ?)';
        array_push($args, simcity_api_like($mot), simcity_api_like($mot));
    }
    $st = $pdo->prepare("SELECT a.id, a.first_name, a.last_name, a.fonction, IFNULL(a.archived,0) archived, s.name service
        FROM agents a LEFT JOIN services s ON s.id = a.service_id
        WHERE " . implode(' AND ', $where) . " ORDER BY a.archived, a.last_name, a.first_name LIMIT " . SIMCITY_API_AGENTS_MAX);
    $st->execute($args);
    $agents = [];
    $stL = $pdo->prepare(SIMCITY_API_SQL_LIGNES . " WHERE l.agent_id = ? AND l.archived = 0 ORDER BY l.phone_number");
    // Même périmètre que la dotation d'un bon (bonSnapshotItems) : matériels
    // attribués à l'agent, ou portés par une de ses lignes.
    $stD = $pdo->prepare("SELECT DISTINCT d.id d_id, d.imei d_imei, d.serial_number d_serial, d.inventory_label d_inventory,
            d.status d_status, d.mdm d_mdm, d.archived d_archived, m.brand d_brand, m.name d_model, m.category d_category
        FROM devices d LEFT JOIN models m ON m.id = d.model_id
        WHERE d.archived = 0 AND (d.agent_id = ? OR d.id IN (SELECT device_id FROM mobile_lines WHERE agent_id = ? AND archived = 0 AND device_id IS NOT NULL))
        ORDER BY d.id");
    $stB = $pdo->prepare("SELECT numero, type, status, expires_at, created_at, signed_at FROM bons
        WHERE agent_id = ? ORDER BY created_at DESC, id DESC LIMIT 10");
    foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $a) {
        $id = (int)$a['id'];
        $stL->execute([$id]); $stD->execute([$id, $id]); $stB->execute([$id]);
        $agents[] = [
            'nom'       => simcity_api_txt($a['last_name']),
            'prenom'    => simcity_api_txt($a['first_name']),
            'service'   => simcity_api_txt($a['service']),
            'fonction'  => simcity_api_txt($a['fonction']),
            'archive'   => !empty($a['archived']),
            'lignes'    => array_map(fn($r) => simcity_api_ligne_vue($r, $ids), $stL->fetchAll(PDO::FETCH_ASSOC)),
            'terminaux' => array_values(array_filter(array_map(fn($r) => simcity_api_terminal_vue($r, $ids), $stD->fetchAll(PDO::FETCH_ASSOC)))),
            'bons'      => array_map('simcity_api_bon_vue', $stB->fetchAll(PDO::FETCH_ASSOC)),
        ];
    }
    return $agents;
}

/** Réglage numérique (seuils d'alerte), sans dépendre d'index.php. */
function simcity_api_setting_int(PDO $pdo, string $key, int $def): int {
    $st = $pdo->prepare("SELECT setting_value FROM settings WHERE setting_key=?");
    $st->execute([$key]);
    $v = $st->fetchColumn();
    return ($v === false || $v === '') ? $def : (int)$v;
}

/** Stock : mêmes définitions que le tableau de bord (statut « Stock », non archivé). */
function simcity_api_stock(PDO $pdo): array {
    $parModele = $pdo->query("SELECT IFNULL(m.brand,'') marque, IFNULL(m.name,'') modele, IFNULL(m.category,'') categorie, COUNT(*) nombre
        FROM devices d LEFT JOIN models m ON m.id = d.model_id
        WHERE d.archived = 0 AND d.status = 'Stock'
        GROUP BY m.brand, m.name, m.category ORDER BY nombre DESC, marque, modele")->fetchAll(PDO::FETCH_ASSOC);
    $parForfait = $pdo->query("SELECT IFNULL(o.name,'') operateur, IFNULL(p.name,'') forfait, COUNT(*) nombre,
            SUM(IFNULL(l.sim_vierge,0)) vierges, SUM(IFNULL(l.esim,0)) esim
        FROM mobile_lines l LEFT JOIN plan_types p ON p.id = l.plan_id LEFT JOIN operators o ON o.id = p.operator_id
        WHERE l.archived = 0 AND l.status = 'Stock'
        GROUP BY o.name, p.name ORDER BY nombre DESC, operateur, forfait")->fetchAll(PDO::FETCH_ASSOC);
    $nbTerm = array_sum(array_map(fn($r) => (int)$r['nombre'], $parModele));
    $nbSim  = array_sum(array_map(fn($r) => (int)$r['nombre'], $parForfait));
    $seuilT = simcity_api_setting_int($pdo, 'device_stock_alert', 3);
    $seuilS = simcity_api_setting_int($pdo, 'sim_stock_alert', 5);
    $txt = fn($v) => simcity_api_txt($v);
    return [
        'terminaux' => [
            'total' => $nbTerm, 'seuil_alerte' => $seuilT, 'sous_le_seuil' => $nbTerm <= $seuilT,
            'par_modele' => array_map(fn($r) => ['marque' => $txt($r['marque']), 'modele' => $txt($r['modele']),
                                                 'categorie' => $txt($r['categorie']), 'nombre' => (int)$r['nombre']], $parModele),
        ],
        'sim' => [
            'total' => $nbSim, 'seuil_alerte' => $seuilS, 'sous_le_seuil' => $nbSim <= $seuilS,
            'vierges' => array_sum(array_map(fn($r) => (int)$r['vierges'], $parForfait)),
            'esim' => array_sum(array_map(fn($r) => (int)$r['esim'], $parForfait)),
            'par_forfait' => array_map(fn($r) => ['operateur' => $txt($r['operateur']), 'forfait' => $txt($r['forfait']),
                                                  'nombre' => (int)$r['nombre']], $parForfait),
        ],
    ];
}

/** Comptes par statut, service, opérateur, forfait ; sans aucun nom d'agent. */
function simcity_api_synthese(PDO $pdo): array {
    $q = fn(string $sql) => $pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC);
    $statuts = fn(array $rows) => array_map(fn($r) => ['statut' => $r['k'], 'libelle' => simcity_api_statut_libelle($r['k']),
                                                       'nombre' => (int)$r['n']], $rows);
    $comptes = fn(array $rows, string $cle) => array_map(fn($r) => [$cle => simcity_api_txt($r['k']) ?? 'Non renseigné',
                                                                    'nombre' => (int)$r['n']], $rows);
    $lignes = [
        'total'              => (int)$pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived = 0")->fetchColumn(),
        'archivees'          => (int)$pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived = 1")->fetchColumn(),
        'esim'               => (int)$pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived = 0 AND IFNULL(esim,0) = 1")->fetchColumn(),
        'terminal_personnel' => (int)$pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived = 0 AND IFNULL(personal_device,0) = 1")->fetchColumn(),
        'par_statut'         => $statuts($q("SELECT status k, COUNT(*) n FROM mobile_lines WHERE archived = 0 GROUP BY status ORDER BY n DESC")),
        'par_service'        => $comptes($q("SELECT COALESCE(sl.name, sa.name) k, COUNT(*) n FROM mobile_lines l
                                    LEFT JOIN services sl ON sl.id = l.service_id LEFT JOIN agents a ON a.id = l.agent_id
                                    LEFT JOIN services sa ON sa.id = a.service_id
                                    WHERE l.archived = 0 AND l.status <> 'Stock' GROUP BY k ORDER BY n DESC, k"), 'service'),
        'par_operateur'      => $comptes($q("SELECT o.name k, COUNT(*) n FROM mobile_lines l LEFT JOIN plan_types p ON p.id = l.plan_id
                                    LEFT JOIN operators o ON o.id = p.operator_id WHERE l.archived = 0 GROUP BY k ORDER BY n DESC, k"), 'operateur'),
        'par_forfait'        => $comptes($q("SELECT p.name k, COUNT(*) n FROM mobile_lines l LEFT JOIN plan_types p ON p.id = l.plan_id
                                    WHERE l.archived = 0 GROUP BY k ORDER BY n DESC, k"), 'forfait'),
    ];
    $terminaux = [
        'total'         => (int)$pdo->query("SELECT COUNT(*) FROM devices WHERE archived = 0")->fetchColumn(),
        'archives'      => (int)$pdo->query("SELECT COUNT(*) FROM devices WHERE archived = 1")->fetchColumn(),
        'par_statut'    => $statuts($q("SELECT status k, COUNT(*) n FROM devices WHERE archived = 0 GROUP BY status ORDER BY n DESC")),
        'par_categorie' => $comptes($q("SELECT m.category k, COUNT(*) n FROM devices d LEFT JOIN models m ON m.id = d.model_id
                                WHERE d.archived = 0 GROUP BY k ORDER BY n DESC, k"), 'categorie'),
        'par_service'   => $comptes($q("SELECT COALESCE(sd.name, sa.name) k, COUNT(*) n FROM devices d
                                LEFT JOIN services sd ON sd.id = d.service_id LEFT JOIN agents a ON a.id = d.agent_id
                                LEFT JOIN services sa ON sa.id = a.service_id
                                WHERE d.archived = 0 AND d.status <> 'Stock' GROUP BY k ORDER BY n DESC, k"), 'service'),
        'mdm'           => ['enroles'     => (int)$pdo->query("SELECT COUNT(*) FROM devices WHERE archived = 0 AND mdm = 1")->fetchColumn(),
                            'non_enroles' => (int)$pdo->query("SELECT COUNT(*) FROM devices WHERE archived = 0 AND mdm = 0")->fetchColumn()],
    ];
    $bons = ['en_attente' => (int)$pdo->query("SELECT COUNT(*) FROM bons WHERE status = 'pending' AND (expires_at IS NULL OR expires_at >= NOW())")->fetchColumn(),
             'expires'    => (int)$pdo->query("SELECT COUNT(*) FROM bons WHERE status = 'pending' AND expires_at < NOW()")->fetchColumn()];
    $agents = (int)$pdo->query("SELECT COUNT(DISTINCT agent_id) FROM mobile_lines WHERE archived = 0 AND agent_id IS NOT NULL")->fetchColumn();
    return ['lignes' => $lignes, 'terminaux' => $terminaux, 'bons' => $bons, 'agents_avec_ligne' => $agents];
}

// ─────────────────────────────────────────────────────────────
// Routage — [code HTTP, charge utile] ; les paramètres sont validés AVANT
// toute requête, pour que le test unitaire les vérifie sans base.
// ─────────────────────────────────────────────────────────────

/** Paramètres d'une requête → [ressource, critère] ou [null, [code, erreur]]. */
function simcity_api_parse(array $get): array {
    $ressource = strtolower(trim((string)($get['ressource'] ?? '')));
    if (!in_array($ressource, SIMCITY_API_RESSOURCES, true)) {
        return [null, [404, ['erreur' => 'ressource_inconnue', 'message' => 'Ressource inconnue.',
                             'ressources' => SIMCITY_API_RESSOURCES]]];
    }
    $texte = function (string $cle) use ($get): ?string {
        if (!isset($get[$cle]) || is_array($get[$cle])) return null;
        $v = trim(preg_replace('/\s+/u', ' ', strip_tags((string)$get[$cle])));
        return $v === '' ? null : mb_substr($v, 0, 100);
    };
    $critere = [];
    if ($ressource === 'ligne') {
        if (($n = $texte('numero')) !== null) {
            $canon = simcity_phone_canon($n);
            if (strlen($canon) < 6 || strlen($canon) > 15) {
                return [null, [400, ['erreur' => 'numero_invalide', 'message' => 'Numéro de ligne illisible (6 à 15 chiffres).']]];
            }
            $critere['numero'] = $canon;
        } elseif (($a = $texte('agent')) !== null) {
            $critere['agent'] = $a;
        } elseif (($s = $texte('service')) !== null) {
            $critere['service'] = $s;
        } else {
            return [null, [400, ['erreur' => 'critere_manquant', 'message' => 'Paramètre « numero », « agent » ou « service » attendu.']]];
        }
        foreach (['agent', 'service'] as $k) {
            if (isset($critere[$k]) && mb_strlen($critere[$k]) < 2) {
                return [null, [400, ['erreur' => 'critere_trop_court', 'message' => 'Deux caractères au moins.']]];
            }
        }
    } elseif ($ressource === 'agent') {
        $nom = $texte('nom');
        if ($nom === null || mb_strlen($nom) < 2) {
            return [null, [400, ['erreur' => 'critere_manquant', 'message' => 'Paramètre « nom » attendu (deux caractères au moins).']]];
        }
        $critere['nom'] = $nom;
    }
    return [$ressource, $critere];
}

/** Exécute une ressource validée. */
function simcity_api_dispatch(PDO $pdo, string $ressource, array $critere, bool $ids): array {
    $base = ['version' => SIMCITY_API_VERSION, 'ressource' => $ressource];
    switch ($ressource) {
        case 'etat':
            return [200, $base + [
                'application'  => 'SimCity',
                'version_application' => defined('APP_VERSION') ? APP_VERSION : null,
                'lecture_seule' => true,
                'identifiants' => $ids,
                'ressources'   => SIMCITY_API_RESSOURCES,
                'compteurs'    => [
                    'lignes'    => (int)$pdo->query("SELECT COUNT(*) FROM mobile_lines WHERE archived = 0")->fetchColumn(),
                    'terminaux' => (int)$pdo->query("SELECT COUNT(*) FROM devices WHERE archived = 0")->fetchColumn(),
                ],
            ]];
        case 'ligne':
            [$lignes, $tronque] = simcity_api_lignes($pdo, $critere, $ids);
            return [200, $base + ['critere' => $critere, 'nombre' => count($lignes), 'tronque' => $tronque, 'lignes' => $lignes]];
        case 'agent':
            $agents = simcity_api_agents($pdo, $critere['nom'], $ids);
            return [200, $base + ['critere' => $critere, 'nombre' => count($agents), 'agents' => $agents]];
        case 'stock':
            return [200, $base + simcity_api_stock($pdo)];
        case 'synthese':
            return [200, $base + simcity_api_synthese($pdo)];
    }
    return [404, ['erreur' => 'ressource_inconnue', 'message' => 'Ressource inconnue.']];
}

/** JSON lisible (accents gardés) mais sans balise interprétable si la
 *  réponse était un jour affichée par erreur dans une page. */
function simcity_api_json($payload): string {
    return (string)json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP
                                       | JSON_INVALID_UTF8_SUBSTITUTE);
}
