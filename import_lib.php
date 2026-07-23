<?php
// ============================================================
//  SimCity — Importation CSV (bibliothèque partagée)
//
//  Utilisée par :
//    - index.php (Référentiels → Paramètres → Maintenance)
//
//  Reprise d'inventaire depuis un export CSV : crée à la volée services,
//  modèles, forfaits, opérateurs, comptes de facturation et utilisateurs,
//  puis les matériels et les lignes mobiles. Les doublons (numéro de ligne,
//  IMEI) sont ignorés : l'import est rejouable sans créer de duplicatas.
//
//  Dépendances : lib_format.php (fmtLastName / fmtFirstName) et schema.php
//  (simcity_apply_schema, pour l'option de purge).
// ============================================================

// Marques reconnues en tête de libellé de modèle : « APPLE IPHONE 13 » est
// scindé en marque « APPLE » et modèle « IPHONE 13 ».
const SIMCITY_IMPORT_BRANDS = ['XIAOMI','APPLE','SAMSUNG','ALCATEL','OPPO','ALTICE','MOTOROLA','MOBIWIRE','CROSSCALL','HUAWEI','TP-LINK','ZTE','SIERRA','NOKIA'];

// Taille maximale acceptée pour le fichier CSV.
const SIMCITY_IMPORT_MAX_BYTES = 10 * 1024 * 1024;

// Types MIME tolérés : les tableurs étiquettent un CSV de façons variées.
const SIMCITY_IMPORT_MIME = ['text/plain','text/csv','application/csv','application/vnd.ms-excel','text/comma-separated-values'];

// Valide un fichier téléversé. Retourne un message d'erreur, ou '' si tout va bien.
function simcity_import_validate(array $upload): string {
    if (($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        return "Aucun fichier reçu (ou téléversement interrompu).";
    }
    if ($upload['size'] > SIMCITY_IMPORT_MAX_BYTES) {
        return "Fichier trop volumineux (max " . round(SIMCITY_IMPORT_MAX_BYTES / 1048576) . " Mo).";
    }
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime  = $finfo->file($upload['tmp_name']);
    if (!in_array($mime, SIMCITY_IMPORT_MIME, true)) {
        return "Type de fichier non autorisé ($mime). Envoyez un fichier CSV.";
    }
    return '';
}

// Vide la base et recrée la structure courante. Destructif : l'appelant doit
// avoir vérifié les droits super-administrateur et la confirmation saisie.
// La table `users` est volontairement épargnée : purger les comptes
// d'administration déconnecterait l'opérateur au milieu de son import.
// Les demandes de téléphone sont en revanche supprimées — elles référencent
// agents et services, et survivraient à la purge en pointant dans le vide.
function simcity_import_purge(PDO $pdo): void {
    $pdo->exec("SET FOREIGN_KEY_CHECKS = 0");
    $pdo->exec("DROP TABLE IF EXISTS request_steps, requests, bons, signatures, sign_tokens, sim_history, attachments, mobile_lines, devices, history_logs, agents, billing_accounts, plan_types, operators, models, services, settings");
    $pdo->exec("SET FOREIGN_KEY_CHECKS = 1");
    simcity_apply_schema($pdo);
}

// Devine la catégorie d'un matériel depuis son libellé : sans colonne « type »
// dans les exports, tout partait en Smartphone. Heuristique sur des mots-clés
// (mêmes valeurs que la modale Modèles : Smartphone / Tablette / Borne 4G…).
function simcity_import_guess_category(string $brand, string $model): string {
    $t = mb_strtoupper($brand . ' ' . $model);
    if (preg_match('/TABLET|TABLETTE|\bTAB\b|IPAD|GALAXY TAB|MEDIAPAD/u', $t)) return 'Tablette';
    if (preg_match('/AIRBOX|\bBOX\b|BORNE|MODEM|ROUTEUR|ROUTER|MIFI|HOTSPOT|TP-LINK|SIERRA|\bM7\d{3}\b/u', $t)) return 'Borne 4G';
    if (preg_match('/CLE 4G|CLÉ 4G|DONGLE|\bE3\d{3}\b|\bE8\d{3}\b/u', $t)) return 'Clé 4G';
    return 'Smartphone';
}

// Analyse le CSV sans rien écrire : liste les utilisateurs distincts du
// fichier et les rapproche du référentiel (nom + prénom, insensible à la
// casse). Sert à l'étape de contrôle avant importation : l'opérateur peut
// associer manuellement les non-correspondances à un agent existant.
function simcity_import_scan_users(PDO $pdo, string $csvPath): array {
    $file = fopen($csvPath, 'r');
    if (!$file) throw new RuntimeException("Fichier CSV illisible.");
    $startReading = false;
    $users = [];
    while (($row = fgetcsv($file, 4000, ";")) !== false) {
        $row = array_map(fn($v) => mb_convert_encoding((string)$v, 'UTF-8', 'Windows-1252'), $row);
        if (!$startReading) {
            if (isset($row[0]) && stripos($row[0], 'LIGNE') !== false) $startReading = true;
            continue;
        }
        $phone = preg_replace('/\s+/', '', $row[0] ?? '');
        $imei  = preg_replace('/[^0-9]/', '', $row[10] ?? '');
        if ($phone === '' && $imei === '') continue;
        $nom    = (string) fmtLastName($row[2] ?? '');
        $prenom = (string) fmtFirstName($row[3] ?? '');
        if ($nom === '' && $prenom === '') continue;
        $key = mb_strtolower($nom . '|' . $prenom);
        if (!isset($users[$key])) $users[$key] = ['key'=>$key, 'nom'=>$nom, 'prenom'=>$prenom, 'service'=>trim($row[6] ?? ''), 'nb'=>0];
        $users[$key]['nb']++;
    }
    fclose($file);

    $agents = [];
    foreach ($pdo->query("SELECT a.id, a.last_name, a.first_name, IFNULL(a.email,'') AS email, IFNULL(s.name,'') AS service_name
                          FROM agents a LEFT JOIN services s ON a.service_id=s.id WHERE a.archived=0") as $a) {
        $agents[mb_strtolower($a['last_name'] . '|' . $a['first_name'])] = $a;
    }
    $matched = $unmatched = [];
    foreach ($users as $u) {
        if (isset($agents[$u['key']])) { $u['agent'] = $agents[$u['key']]; $matched[] = $u; }
        else { $unmatched[] = $u; }
    }
    $byName = fn($a, $b) => strcmp($a['key'], $b['key']);
    usort($matched, $byName); usort($unmatched, $byName);
    return ['matched' => $matched, 'unmatched' => $unmatched];
}

// Importe le CSV et retourne le décompte des objets créés, par catégorie.
// $agentMap : associations décidées à l'étape de contrôle — clé
// mb_strtolower("NOM|Prénom") => id d'un agent existant. Les utilisateurs
// absents de la carte suivent le comportement historique (créés au besoin).
function simcity_import_csv(PDO $pdo, string $csvPath, array $agentMap = []): array {
    $stats  = ['services'=>0,'models'=>0,'devices'=>0,'lines'=>0,'agents'=>0,'plans'=>0,'billings'=>0,'operators'=>0];
    $caches = ['models'=>[], 'services'=>[], 'plan_types'=>[], 'billing_accounts'=>[], 'agents'=>[], 'operators'=>[]];

    // Récupère l'identifiant d'un libellé, en le créant au besoin. Le cache
    // évite une requête par ligne du CSV sur des valeurs très répétitives.
    $getOrCreate = function($table, $col, $val, $extraCol = null, $extraVal = null) use ($pdo, &$caches, &$stats) {
        $val = trim($val);
        if ($val === '') return null;
        $key = strtolower($val . ($extraVal !== null ? '_' . $extraVal : ''));
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
        if ($dateStr === '') return null;
        $d = DateTime::createFromFormat('d/m/Y', $dateStr);
        if (!$d) $d = DateTime::createFromFormat('Y-m-d', $dateStr);
        return $d ? $d->format('Y-m-d') : null;
    };

    $file = fopen($csvPath, 'r');
    if (!$file) throw new RuntimeException("Fichier CSV illisible.");
    $startReading = false;

    while (($row = fgetcsv($file, 4000, ";")) !== false) {
        $row = array_map(fn($v) => mb_convert_encoding((string)$v, 'UTF-8', 'Windows-1252'), $row);

        // Tout ce qui précède la ligne d'en-tête « LIGNE » est ignoré :
        // les exports comportent souvent des lignes de titre.
        if (!$startReading) {
            if (isset($row[0]) && stripos($row[0], 'LIGNE') !== false) $startReading = true;
            continue;
        }

        $phone = preg_replace('/\s+/', '', $row[0] ?? '');
        $imei  = preg_replace('/[^0-9]/', '', $row[10] ?? '');
        if ($phone === '' && $imei === '') continue;

        $nom       = (string) fmtLastName($row[2] ?? '');
        $prenom    = (string) fmtFirstName($row[3] ?? '');
        $notes     = trim($row[4] ?? '');
        $cf        = trim($row[5] ?? '');
        $service   = trim($row[6] ?? '');
        $options   = trim($row[7] ?? '');
        $dateAct   = $formatDate($row[9] ?? '');
        $rawMod    = trim($row[11] ?? '');
        $plan      = trim($row[12] ?? '');
        $iccid     = preg_replace('/[^a-zA-Z0-9]/', '', $row[13] ?? '');
        $pin       = trim($row[14] ?? '');
        $puk2      = trim($row[15] ?? '');
        $operateur = trim($row[16] ?? '');

        $brand = 'Inconnu'; $modelName = $rawMod;
        foreach (SIMCITY_IMPORT_BRANDS as $kb) {
            if (stripos($rawMod, $kb) === 0) {
                $brand = $kb; $modelName = trim(substr($rawMod, strlen($kb))); break;
            }
        }

        $svcId  = $getOrCreate('services', 'name', $service);
        $billId = $getOrCreate('billing_accounts', 'account_number', $cf);

        // Modèle : créé avec sa catégorie devinée depuis le libellé (tablette,
        // borne 4G…) — sans quoi tout le parc arrivait en « Smartphone ».
        $modId = null;
        if ($modelName !== '') {
            $modKey = strtolower($modelName . '_' . $brand);
            if (!isset($caches['models'][$modKey])) {
                $stM = $pdo->prepare("SELECT id FROM models WHERE name=? AND brand=?");
                $stM->execute([$modelName, $brand]);
                $mid = $stM->fetchColumn();
                if (!$mid) {
                    $pdo->prepare("INSERT INTO models (name, brand, category) VALUES (?,?,?)")
                        ->execute([$modelName, $brand, simcity_import_guess_category($brand, $rawMod)]);
                    $mid = $pdo->lastInsertId(); $stats['models']++;
                }
                $caches['models'][$modKey] = $mid;
            }
            $modId = $caches['models'][$modKey];
        }
        $opId   = $operateur ? $getOrCreate('operators', 'name', $operateur) : null;

        // Un forfait est identifié par son nom ET son opérateur : deux
        // opérateurs peuvent commercialiser un « Forfait 20 Go ».
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
            // Association décidée à l'étape de contrôle : prime sur la création.
            $mapKey = mb_strtolower($nom . '|' . $prenom);
            if (!empty($agentMap[$mapKey])) {
                $agtId = (int)$agentMap[$mapKey];
            } else {
                $agtId = $getOrCreate('agents', 'last_name', $nom, 'first_name', $prenom);
            }
            if ($svcId) $pdo->prepare("UPDATE agents SET service_id=? WHERE id=? AND (service_id IS NULL OR service_id=0)")->execute([$svcId, $agtId]);
        }

        $devId = null;
        if ($imei !== '') {
            $stD = $pdo->prepare("SELECT id FROM devices WHERE imei=?"); $stD->execute([$imei]);
            $devId = $stD->fetchColumn();
            if (!$devId) {
                $devStatus = ($phone === '') ? 'Stock' : 'Deployed';
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

    return $stats;
}
