<?php
// ============================================================
//  SimCity — Export de parc SFR (« état de parc », .xlsx)
//
//  Utilisée par :
//    - index.php (Référentiels et Paramètres → Maintenance → Import depuis SFR)
//
//  L'export de l'espace client SFR Business liste TOUTES les lignes du compte
//  avec leur titulaire, leur forfait, leur statut, leur terminal et son IMEI.
//  Il sert d'abord de CONTRÔLE du référentiel SimCity : rien n'est écrit sans
//  validation explicite, poste par poste, depuis l'écran de contrôle.
//
//  Codes SIM : PIN 1 / PUK 1 alimentent les colonnes mobile_lines.pin et .puk,
//  qui existent depuis l'origine et que l'import CSV remplit déjà. PIN 2 et
//  PUK 2 ont leurs propres colonnes. Ces codes ne sont écrits que si le poste
//  correspondant est coché à l'écran de contrôle, et ils ne sortent jamais
//  dans un message ni dans un journal — l'historique note un décompte, pas
//  une valeur. Ils restent en clair en base : la sauvegarde SQL et l'accès à
//  la base doivent donc être protégés en conséquence (cf. README).
//
//  Le RIO n'est pas dans ce fichier : la colonne contient le renvoi « Voir
//  export RIO » du portail. Il n'est donc repris que s'il ressemble à un vrai
//  RIO (12 caractères alphanumériques), ce qui n'arrive pas avec cet export.
// ============================================================

// Dépendances explicites : la comparaison des noms est définie avec le parseur
// de factures, leur mise en forme dans la bibliothèque partagée. Les deux
// sources d'import (CSV et portail) doivent produire des noms identiques.
require_once __DIR__ . '/invoice_lib.php';
require_once __DIR__ . '/lib_format.php';

const SIMCITY_PARC_MAX_BYTES = 15 * 1024 * 1024;

// Colonnes retenues, désignées par leur en-tête dans l'export (comparaison
// tolérante : accents, casse et espaces multiples sont normalisés).
const SIMCITY_PARC_COLUMNS = [
    'phone'        => 'reference',
    'civility'     => 'civilite',
    'last_name'    => 'nom',
    'first_name'   => 'prenom',
    'billing_acct' => 'n cf',
    'billing_name' => 'nom cf',
    'status'       => 'statut ligne',
    'activation'   => 'date de mise en service',
    'engagement'   => 'date de fin de periode d engagement',
    'plan'         => 'forfait',
    'device_used'  => 'terminal communiquant',
    'device_bought'=> 'terminal achete',
    'imei_used'    => 'imei communiquant',
    'imei_bought'  => 'imei achete',
    'sim_format'   => 'format sim',
    'eid'          => 'eid',
    'iccid'        => 'n de csim',
    'offer'        => 'type d offre',
    'pin'          => 'pin 1',
    'pin2'         => 'pin 2',
    'puk'          => 'puk 1',
    'puk2'         => 'puk 2',
    'rio'          => 'rio',
];

// ─────────────────────────────────────────────────────────────
// LECTURE XLSX SANS EXTENSION
// ─────────────────────────────────────────────────────────────

// Valide le fichier téléversé. Retourne un message d'erreur, ou '' si OK.
function simcity_parc_validate(array $upload): string {
    if (($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        return "Aucun fichier reçu (ou téléversement interrompu).";
    }
    if (($upload['size'] ?? 0) > SIMCITY_PARC_MAX_BYTES) {
        return "Fichier trop volumineux (max " . round(SIMCITY_PARC_MAX_BYTES / 1048576) . " Mo).";
    }
    // Un .xlsx est une archive ZIP : la signature suffit à écarter les erreurs
    // de fichier, et le parsing dira si le contenu est bien un classeur.
    $fh = fopen($upload['tmp_name'], 'rb');
    $magic = $fh ? fread($fh, 4) : '';
    if ($fh) fclose($fh);
    if (strncmp((string)$magic, "PK\x03\x04", 4) !== 0) {
        return "Ce fichier n'est pas un classeur .xlsx (export « État de parc » de l'espace client SFR).";
    }
    return '';
}

// Extrait un fichier d'une archive ZIP sans l'extension zip : on lit le
// répertoire central (seul endroit où les tailles sont toujours fiables — les
// en-têtes locaux peuvent les reporter dans un descripteur), puis on
// décompresse avec zlib, toujours compilé dans PHP.
// Retourne le contenu, ou null si l'entrée est absente ou illisible.
function simcity_zip_read(string $zipPath, string $entry): ?string {
    if (class_exists('ZipArchive')) {                    // chemin rapide si dispo
        $z = new ZipArchive();
        if ($z->open($zipPath) === true) {
            $data = $z->getFromName($entry);
            $z->close();
            if ($data !== false) return $data;
        }
    }
    $raw = file_get_contents($zipPath);
    if ($raw === false) return null;

    // Fin du répertoire central (« EOCD »), cherchée depuis la fin : elle peut
    // être suivie d'un commentaire d'archive de taille variable.
    $eocd = strrpos($raw, "PK\x05\x06");
    if ($eocd === false || $eocd + 22 > strlen($raw)) return null;
    $e = unpack('vdisk/vcddisk/ventries/vtotal/Vcdsize/Vcdoff/vcommentlen', substr($raw, $eocd + 4, 18));
    $pos = $e['cdoff'];

    for ($i = 0; $i < $e['total']; $i++) {
        if (substr($raw, $pos, 4) !== "PK\x01\x02") return null;
        $h = unpack('vmade/vneed/vflag/vmethod/vtime/vdate/Vcrc/Vcsize/Vusize/vnamelen/vextralen/vcommentlen'
                  . '/vdisknum/vinattr/Vexattr/Vlocaloff', substr($raw, $pos + 4, 42));
        $name = substr($raw, $pos + 46, $h['namelen']);
        if ($name === $entry) {
            // L'en-tête local ne sert qu'à sauter le nom et l'extra field,
            // dont les longueurs peuvent différer de celles du répertoire.
            $lo = $h['localoff'];
            if (substr($raw, $lo, 4) !== "PK\x03\x04") return null;
            $l = unpack('vver/vflag/vmethod/vtime/vdate/Vcrc/Vcsize/Vusize/vnamelen/vextralen',
                        substr($raw, $lo + 4, 26));
            $blob = substr($raw, $lo + 30 + $l['namelen'] + $l['extralen'], $h['csize']);
            if ($h['method'] === 0) return $blob;                          // stocké
            // Taille décompressée plafonnée : une « bombe » ZIP de quelques Mo
            // ne doit pas pouvoir épuiser la mémoire du serveur.
            if ($h['method'] === 8) { $out = @gzinflate($blob, 256 * 1024 * 1024); return $out === false ? null : $out; }
            return null;                                                   // méthode exotique
        }
        $pos += 46 + $h['namelen'] + $h['extralen'] + $h['commentlen'];
    }
    return null;
}

// Normalise un en-tête de colonne : minuscules, sans accent, espaces simples.
function simcity_parc_norm_header(string $s): string {
    $s = strtr($s, ['à'=>'a','â'=>'a','ä'=>'a','é'=>'e','è'=>'e','ê'=>'e','ë'=>'e','î'=>'i','ï'=>'i',
                    'ô'=>'o','ö'=>'o','ù'=>'u','û'=>'u','ü'=>'u','ç'=>'c','°'=>'',
                    'À'=>'A','Â'=>'A','É'=>'E','È'=>'E','Ê'=>'E','Î'=>'I','Ô'=>'O','Ù'=>'U','Ç'=>'C']);
    $s = strtolower(preg_replace('/[^A-Za-z0-9]+/', ' ', $s));
    return trim(preg_replace('/\s+/', ' ', $s));
}

// « AB12 » → index de colonne 0-based.
function simcity_parc_col_index(string $ref): int {
    preg_match('/^([A-Z]+)/', $ref, $m);
    $n = 0;
    foreach (str_split($m[1] ?? 'A') as $ch) $n = $n * 26 + (ord($ch) - 64);
    return $n - 1;
}

// Chemin de la première feuille du classeur, résolu via workbook.xml et ses
// relations : elle ne s'appelle pas forcément « sheet1.xml » (feuilles
// réordonnées, fichier ré-enregistré par un autre outil). Null si introuvable.
function simcity_xlsx_first_sheet(string $path): ?string {
    $wb   = simcity_zip_read($path, 'xl/workbook.xml');
    $rels = simcity_zip_read($path, 'xl/_rels/workbook.xml.rels');
    if ($wb === null || $rels === null) return null;
    $xw = @simplexml_load_string($wb);
    $xr = @simplexml_load_string($rels);
    if ($xw === false || $xr === false || !isset($xw->sheets->sheet[0])) return null;
    $rid = (string)($xw->sheets->sheet[0]->attributes('http://schemas.openxmlformats.org/officeDocument/2006/relationships')['id'] ?? '');
    foreach ($xr->Relationship as $rel) {
        if ((string)$rel['Id'] === $rid) {
            $target = (string)$rel['Target'];
            return str_starts_with($target, '/') ? ltrim($target, '/') : 'xl/' . $target;
        }
    }
    return null;
}

// Lit la première feuille d'un .xlsx et retourne un tableau de lignes
// (chaque ligne = tableau indexé par numéro de colonne).
// $truncated est mis à true si le classeur dépasse $maxRows : l'appelant doit
// le dire à l'utilisateur, sinon les lignes non lues passeraient pour
// « absentes du fichier ».
function simcity_xlsx_rows(string $path, int $maxRows = 20000, ?bool &$truncated = null): array {
    $truncated = false;
    $entry = simcity_xlsx_first_sheet($path) ?? 'xl/worksheets/sheet1.xml';
    $sheet = simcity_zip_read($path, $entry)
          ?? ($entry !== 'xl/worksheets/sheet1.xml' ? simcity_zip_read($path, 'xl/worksheets/sheet1.xml') : null);
    if ($sheet === null) throw new RuntimeException("Feuille de calcul illisible dans le classeur.");

    // Chaînes partagées (les exports SFR utilisent surtout des chaînes en ligne,
    // mais les deux formes existent selon la version du portail).
    $shared = [];
    $sst = simcity_zip_read($path, 'xl/sharedStrings.xml');
    if ($sst !== null) {
        $x = @simplexml_load_string($sst);
        if ($x !== false) foreach ($x->si as $si) {
            $t = '';
            foreach ($si->xpath('.//*[local-name()="t"]') as $node) $t .= (string)$node;
            $shared[] = $t;
        }
    }

    $x = @simplexml_load_string($sheet);
    if ($x === false) throw new RuntimeException("Feuille de calcul illisible (XML invalide).");
    $rows = [];
    foreach ($x->sheetData->row as $row) {
        $r = [];
        foreach ($row->c as $c) {
            $type = (string)$c['t'];
            if ($type === 'inlineStr') {
                $v = '';
                foreach ($c->xpath('.//*[local-name()="t"]') as $node) $v .= (string)$node;
            } elseif ($type === 's') {
                $v = $shared[(int)$c->v] ?? '';
            } else {
                $v = isset($c->v) ? (string)$c->v : '';
            }
            $r[simcity_parc_col_index((string)$c['r'])] = trim($v);
        }
        $rows[] = $r;
        if (count($rows) >= $maxRows) { $truncated = true; break; }
    }
    return $rows;
}

// ─────────────────────────────────────────────────────────────
// LECTURE DE L'EXPORT
// ─────────────────────────────────────────────────────────────

// Parse l'export : retourne ['records' => [...], 'ignored' => n, 'columns' => [...], 'truncated' => bool]
function simcity_parc_parse(string $path): array {
    $rows = simcity_xlsx_rows($path, 20000, $truncated);
    if (count($rows) < 2) throw new RuntimeException("Le classeur ne contient aucune donnée.");

    // Repérage des colonnes par en-tête (l'ordre du portail peut changer).
    $map = [];
    foreach ($rows[0] as $i => $head) {
        $n = simcity_parc_norm_header((string)$head);
        foreach (SIMCITY_PARC_COLUMNS as $key => $expected) {
            if ($n === $expected) { $map[$key] = $i; break; }
        }
    }
    if (!isset($map['phone'])) {
        throw new RuntimeException("Colonne « Référence » introuvable — ce classeur n'est pas un export de parc SFR.");
    }

    $records = []; $ignored = 0;
    foreach (array_slice($rows, 1) as $r) {
        $get = fn(string $k) => isset($map[$k]) ? trim((string)($r[$map[$k]] ?? '')) : '';
        $phone = simcity_phone_canon($get('phone'));
        if (strlen($phone) < 9) { $ignored++; continue; }
        $records[] = [
            'phone'         => $phone,
            // Mise en forme commune à toutes les entrées de l'application
            // (fiches, import CSV, portail) : sans elle, le même agent
            // s'afficherait « durand » ici et « DURAND » ailleurs.
            'last_name'     => (string)fmtLastName($get('last_name')),
            'first_name'    => (string)fmtFirstName($get('first_name')),
            'civility'      => $get('civility'),
            'billing_acct'  => preg_replace('/\s+/', '', $get('billing_acct')),
            'billing_name'  => $get('billing_name'),
            'status'        => $get('status'),
            'activation'    => simcity_parc_date($get('activation')),
            'engagement'    => simcity_parc_date($get('engagement')),
            'plan'          => $get('plan'),
            'device_used'   => $get('device_used'),
            'device_bought' => $get('device_bought'),
            'imei_used'     => simcity_parc_digits($get('imei_used')),
            'imei_bought'   => simcity_parc_digits($get('imei_bought')),
            'sim_format'    => $get('sim_format'),
            'eid'           => simcity_parc_digits($get('eid')),
            'iccid'         => simcity_parc_digits($get('iccid')),
            'offer'         => $get('offer'),
            // Codes SIM : uniquement des chiffres, longueurs plausibles.
            'pin'           => simcity_parc_code($get('pin'), 4, 8),
            'pin2'          => simcity_parc_code($get('pin2'), 4, 8),
            'puk'           => simcity_parc_code($get('puk'), 8, 12),
            'puk2'          => simcity_parc_code($get('puk2'), 8, 12),
            // Le portail renvoie « Voir export RIO » : on ne garde que ce qui
            // ressemble réellement à un RIO.
            'rio'           => preg_match('/^[A-Za-z0-9]{12}$/', $get('rio')) ? strtoupper($get('rio')) : '',
        ];
    }
    return ['records' => $records, 'ignored' => $ignored, 'columns' => array_keys($map),
            'truncated' => (bool)$truncated];
}

// Identifiant numérique long (ICCID, IMEI, EID) : chiffres seuls. Une cellule
// convertie en notation scientifique par Excel (« 8.90331E+19 ») a perdu des
// chiffres — mieux vaut l'écarter que de retenir un identifiant faux.
function simcity_parc_digits(string $s): string {
    if (preg_match('/\dE\+?\d/i', $s)) return '';
    return preg_replace('/\D/', '', $s);
}

// Code SIM : chiffres uniquement, dans une longueur plausible, sinon ''.
// Écarte les cellules de remplissage du portail (« - », « n/a »…).
function simcity_parc_code(string $s, int $min, int $max): string {
    $d = preg_replace('/\D/', '', $s);
    return (strlen($d) >= $min && strlen($d) <= $max) ? $d : '';
}

// « 18/06/2019 » → « Y-m-d » (null si vide ou invalide).
// Gère aussi le nombre de série Excel (cellule typée date/nombre, cas d'un
// fichier ré-enregistré dans Excel) : jours écoulés depuis le 30/12/1899.
function simcity_parc_date(string $s): ?string {
    $s = trim($s);
    if (preg_match('/^\d+(?:\.\d+)?$/', $s)) {
        $n = (int)$s;
        if ($n < 20000 || $n > 80000) return null;      // hors 1954–2119 : pas une date
        return gmdate('Y-m-d', ($n - 25569) * 86400);   // 25569 = 01/01/1970
    }
    if (!preg_match('#^(\d{2})/(\d{2})/(\d{4})$#', $s, $m)) return null;
    return checkdate((int)$m[2], (int)$m[1], (int)$m[3]) ? "$m[3]-$m[2]-$m[1]" : null;
}

// Statut SFR → statut SimCity (les autres valeurs restent telles quelles).
function simcity_parc_status(string $sfr): string {
    $s = simcity_parc_norm_header($sfr);
    if ($s === 'actif' || $s === 'active') return 'Active';
    if (str_starts_with($s, 'suspend')) return 'Suspended';
    if (str_starts_with($s, 'resili')) return 'Resiliated';
    return '';
}

// ─────────────────────────────────────────────────────────────
// CONTRÔLE CONTRE LE RÉFÉRENTIEL
// ─────────────────────────────────────────────────────────────

// Compare l'export au référentiel SimCity. N'écrit rien.
// Retourne ['rows' => [...], 'counts' => [...], 'missing' => [...]]
function simcity_parc_compare(PDO $pdo, array $records): array {
    // Référentiel indexé par numéro normalisé.
    $app = [];
    $sql = "SELECT l.id, l.phone_number, l.iccid, l.status, l.archived, l.sim_vierge, l.agent_id,
                   l.plan_id, l.billing_id, l.device_id, l.activation_date,
                   IFNULL(l.pin,'') pin, IFNULL(l.pin2,'') pin2,
                   IFNULL(l.puk,'') puk, IFNULL(l.puk2,'') puk2, IFNULL(l.rio,'') rio,
                   IFNULL(a.last_name,'') ln, IFNULL(a.first_name,'') fn,
                   IFNULL(p.name,'') plan_name, REPLACE(IFNULL(b.account_number,''),' ','') acct,
                   IFNULL(d.imei,'') imei, IFNULL(m.brand,'') brand, IFNULL(m.name,'') model
            FROM mobile_lines l
            LEFT JOIN agents a         ON l.agent_id = a.id
            LEFT JOIN plan_types p     ON l.plan_id = p.id
            LEFT JOIN billing_accounts b ON l.billing_id = b.id
            LEFT JOIN devices d        ON l.device_id = d.id
            LEFT JOIN models m         ON d.model_id = m.id
            ORDER BY l.archived DESC, l.id";
    // Clé = numéro canonique (règle commune, +33 compris). En cas de doublon
    // de numéro (ligne archivée + ligne recréée), la ligne ACTIVE gagne :
    // l'ORDER BY fait passer les archivées d'abord, elles sont donc écrasées.
    foreach ($pdo->query($sql) as $r) {
        $app[simcity_phone_canon((string)$r['phone_number'])] = $r;
    }
    // IMEI présents au parc, pour dire si le terminal utilisé est connu.
    $imeis = [];
    foreach ($pdo->query("SELECT imei FROM devices WHERE imei IS NOT NULL AND imei <> ''") as $r) {
        $imeis[preg_replace('/\D/', '', (string)$r['imei'])] = true;
    }

    $rows = [];
    $counts = ['total' => count($records), 'unknown' => 0, 'name' => 0, 'plan' => 0, 'status' => 0,
               'billing' => 0, 'iccid' => 0, 'imei' => 0, 'codes' => 0, 'device_swap' => 0,
               'imei_absent' => 0, 'ok' => 0];
    $seen = [];
    foreach ($records as $rec) {
        $seen[$rec['phone']] = true;
        $a = $app[$rec['phone']] ?? null;
        $issues = [];

        if (!$a) {
            $issues[] = 'unknown';
            $counts['unknown']++;
        } else {
            // Nom : règle commune à tous les rapprochements de l'application.
            $sfrName = trim($rec['last_name'] . ' ' . $rec['first_name']);
            $appName = trim($a['ln'] . ' ' . $a['fn']);
            if ($sfrName !== '' && $appName !== '' && !simcity_name_matches($sfrName, $appName)
                && !simcity_name_found_in($sfrName, (string)$a['ln'], (string)$a['fn'])) {
                $issues[] = 'name'; $counts['name']++;
            }
            if ($rec['plan'] !== '' && simcity_parc_norm_header($rec['plan']) !== simcity_parc_norm_header($a['plan_name'])) {
                $issues[] = 'plan'; $counts['plan']++;
            }
            $st = simcity_parc_status($rec['status']);
            if ($st !== '' && !$a['archived'] && $st !== $a['status'] && $a['status'] !== 'Stock') {
                $issues[] = 'status'; $counts['status']++;
            }
            if ($rec['billing_acct'] !== '' && $rec['billing_acct'] !== $a['acct']) {
                $issues[] = 'billing'; $counts['billing']++;
            }
            if ($rec['iccid'] !== '' && preg_replace('/\D/', '', (string)$a['iccid']) !== $rec['iccid']) {
                $issues[] = 'iccid'; $counts['iccid']++;
            }
            if ($rec['imei_used'] !== '' && $a['imei'] !== '' && preg_replace('/\D/', '', $a['imei']) !== $rec['imei_used']) {
                $issues[] = 'imei'; $counts['imei']++;
            }
            // Codes SIM : on signale un écart, jamais les valeurs. « Absent
            // dans SimCity » compte aussi comme un écart à compléter. Le
            // périmètre est exactement celui de l'application du poste
            // (simcity_parc_apply) : PIN 1/2, PUK 1/2 et RIO — sinon le badge
            // annoncerait « 0 écart » puis l'application écrirait quand même.
            $codesDiff = false;
            foreach (['pin', 'pin2', 'puk', 'puk2', 'rio'] as $ck) {
                if ($rec[$ck] !== '' && $rec[$ck] !== trim((string)$a[$ck])) { $codesDiff = true; break; }
            }
            if ($codesDiff) {
                $issues[] = 'codes'; $counts['codes']++;
            }
            if (!$issues) $counts['ok']++;
        }
        // Contrôles indépendants du référentiel de lignes.
        if ($rec['imei_used'] !== '' && $rec['imei_bought'] !== '' && $rec['imei_used'] !== $rec['imei_bought']) {
            $issues[] = 'device_swap'; $counts['device_swap']++;
        }
        if ($rec['imei_used'] !== '' && !isset($imeis[$rec['imei_used']])) {
            $issues[] = 'imei_absent'; $counts['imei_absent']++;
        }
        $rows[] = ['rec' => $rec, 'app' => $a, 'issues' => $issues];
    }

    // Lignes SimCity actives absentes de l'export : résiliées chez l'opérateur ?
    $missing = [];
    foreach ($app as $phone => $a) {
        if (isset($seen[$phone]) || $a['archived'] || !empty($a['sim_vierge'])) continue;
        if (in_array($a['status'], ['Resiliated', 'Stock'], true)) continue;
        $missing[] = $a;
    }
    $counts['missing'] = count($missing);
    return ['rows' => $rows, 'counts' => $counts, 'missing' => $missing];
}

// ─────────────────────────────────────────────────────────────
// MISE À JOUR CIBLÉE (uniquement les postes cochés)
// ─────────────────────────────────────────────────────────────

// $opts : ['billing'=>bool, 'plan'=>bool, 'status'=>bool, 'iccid'=>bool, 'create'=>bool]
// Retourne le décompte des écritures réalisées.
function simcity_parc_apply(PDO $pdo, array $records, array $opts): array {
    $done = ['billing' => 0, 'plan' => 0, 'status' => 0, 'iccid' => 0, 'codes' => 0, 'created' => 0,
             'accounts' => 0, 'plans' => 0];

    // Référentiels résolus / créés à la demande.
    $acctId = [];
    foreach ($pdo->query("SELECT id, REPLACE(account_number,' ','') n FROM billing_accounts") as $r) $acctId[$r['n']] = (int)$r['id'];
    $planId = [];
    foreach ($pdo->query("SELECT id, name FROM plan_types") as $r) $planId[simcity_parc_norm_header((string)$r['name'])] = (int)$r['id'];

    // Même normalisation que le contrôle (+33 compris) ; à numéro égal, la
    // ligne active est préférée à une ancienne ligne archivée.
    $findLine = $pdo->prepare("SELECT id, iccid, status, archived, plan_id, billing_id,
            IFNULL(pin,'') pin, IFNULL(pin2,'') pin2, IFNULL(puk,'') puk, IFNULL(puk2,'') puk2, IFNULL(rio,'') rio
        FROM mobile_lines
        WHERE " . sprintf(SIMCITY_SQL_PHONE_CANON, 'phone_number') . " = ?
        ORDER BY archived ASC, id DESC LIMIT 1");

    foreach ($records as $rec) {
        $findLine->execute([$rec['phone']]);
        $line = $findLine->fetch(PDO::FETCH_ASSOC);

        // Compte de facturation : créé s'il manque au référentiel.
        $bid = null;
        if ($rec['billing_acct'] !== '') {
            if (!isset($acctId[$rec['billing_acct']])) {
                if (!empty($opts['billing'])) {
                    $pdo->prepare("INSERT INTO billing_accounts (account_number, name, notes) VALUES (?,?,?)")
                        ->execute([$rec['billing_acct'], $rec['billing_name'] ?: $rec['billing_acct'], 'Créé depuis un export de parc SFR']);
                    $acctId[$rec['billing_acct']] = (int)$pdo->lastInsertId();
                    $done['accounts']++;
                }
            }
            $bid = $acctId[$rec['billing_acct']] ?? null;
        }
        // Forfait : créé s'il manque au référentiel.
        $pid = null;
        if ($rec['plan'] !== '') {
            $key = simcity_parc_norm_header($rec['plan']);
            if (!isset($planId[$key]) && !empty($opts['plan'])) {
                $limit = preg_match('/(\d+)\s*(Go|Mo)/i', $rec['plan'], $m) ? $m[1] . strtoupper($m[2][0]) . 'o' : '';
                $pdo->prepare("INSERT INTO plan_types (name, data_limit, notes) VALUES (?,?,?)")
                    ->execute([$rec['plan'], $limit, 'Créé depuis un export de parc SFR']);
                $planId[$key] = (int)$pdo->lastInsertId();
                $done['plans']++;
            }
            $pid = $planId[$key] ?? null;
        }
        $status = simcity_parc_status($rec['status']);

        if (!$line) {
            // Création : ligne en stock, sans agent — l'affectation reste manuelle.
            if (empty($opts['create'])) continue;
            // Une ligne résiliée chez SFR et inconnue de SimCity n'a rien à
            // faire dans le référentiel : la créer « en stock » ferait
            // apparaître une SIM morte comme disponible.
            if ($status === 'Resiliated') continue;
            $withCodes = !empty($opts['codes']);
            $pdo->prepare("INSERT INTO mobile_lines (phone_number, iccid, plan_id, billing_id, status,
                    activation_date, pin, pin2, puk, puk2, rio, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
                ->execute([$rec['phone'], $rec['iccid'] ?: null, $pid, $bid,
                           $status === 'Suspended' ? 'Suspended' : 'Stock', $rec['activation'],
                           $withCodes ? ($rec['pin']  ?: null) : null,
                           $withCodes ? ($rec['pin2'] ?: null) : null,
                           $withCodes ? ($rec['puk']  ?: null) : null,
                           $withCodes ? ($rec['puk2'] ?: null) : null,
                           $withCodes ? ($rec['rio']  ?: null) : null,
                           'Créée depuis un export de parc SFR']);
            $done['created']++;
            continue;
        }

        // Mises à jour ciblées, champ par champ, seulement si le poste est coché
        // et si la valeur diffère réellement.
        if (!empty($opts['billing']) && $bid && (int)$line['billing_id'] !== $bid) {
            $pdo->prepare("UPDATE mobile_lines SET billing_id=? WHERE id=?")->execute([$bid, $line['id']]);
            $done['billing']++;
        }
        if (!empty($opts['plan']) && $pid && (int)$line['plan_id'] !== $pid) {
            $pdo->prepare("UPDATE mobile_lines SET plan_id=? WHERE id=?")->execute([$pid, $line['id']]);
            $done['plan']++;
        }
        // Jamais sur une ligne archivée : l'écran de contrôle les exclut du
        // décompte des écarts de statut — appliquer ici réactiverait en
        // silence une ligne résiliée/archivée jamais montrée à l'utilisateur.
        if (!empty($opts['status']) && $status !== '' && empty($line['archived'])
            && $status !== $line['status'] && $line['status'] !== 'Stock') {
            $pdo->prepare("UPDATE mobile_lines SET status=? WHERE id=?")->execute([$status, $line['id']]);
            $done['status']++;
        }
        // ICCID : uniquement si le champ est vide côté SimCity (on ne remplace
        // jamais une valeur saisie par un agent).
        if (!empty($opts['iccid']) && $rec['iccid'] !== '' && trim((string)$line['iccid']) === '') {
            $pdo->prepare("UPDATE mobile_lines SET iccid=? WHERE id=?")->execute([$rec['iccid'], $line['id']]);
            $done['iccid']++;
        }
        // Codes SIM : l'opérateur est la source de référence, on aligne donc
        // les valeurs présentes dans l'export (champ vide côté export = on ne
        // touche pas). Un seul UPDATE, compté une fois par ligne.
        if (!empty($opts['codes'])) {
            $set = []; $args = [];
            foreach (['pin' => 'pin', 'pin2' => 'pin2', 'puk' => 'puk', 'puk2' => 'puk2', 'rio' => 'rio'] as $k => $col) {
                if ($rec[$k] !== '' && $rec[$k] !== trim((string)$line[$col])) { $set[] = "$col=?"; $args[] = $rec[$k]; }
            }
            if ($set) {
                $args[] = $line['id'];
                $pdo->prepare("UPDATE mobile_lines SET " . implode(',', $set) . " WHERE id=?")->execute($args);
                $done['codes']++;
            }
        }
    }
    return $done;
}
