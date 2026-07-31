<?php
// ============================================================
//  SimCity — Factures opérateur (bibliothèque partagée)
//
//  Utilisée par :
//    - index.php (page Facturation / Contrôle)
//
//  Parse les factures PDF « SFR Business » via pdftotext (poppler-utils,
//  présent dans l'image Docker). Parseur déterministe : aucune donnée ne
//  sort du serveur. Types reconnus :
//    9A…  : facture mensuelle — contient « Votre détail par compte client »
//           avec, par numéro de ligne, l'utilisateur connu de SFR, le
//           forfait et les consommations (appels, data, SMS/MMS, surtaxés,
//           international) → type 'lines'
//    9T…  : achats de terminaux/accessoires (IMEI en clair) → type 'devices'
//    9AF… : facture manuelle de régularisation → type 'manual'
//    9AA… : avoir → type 'credit'
//
//  Unités stockées : durées en secondes, data en Ko, montants en € HT.
// ============================================================

// Taille maximale d'un PDF de facture.
const SIMCITY_INVOICE_MAX_BYTES = 30 * 1024 * 1024;

// ─────────────────────────────────────────────────────────────
// EXTRACTION TEXTE (pdftotext -layout)
// ─────────────────────────────────────────────────────────────

// Valide un fichier téléversé. Retourne un message d'erreur, ou '' si OK.
function simcity_invoice_validate(array $upload): string {
    if (($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        return "Aucun fichier reçu (ou téléversement interrompu).";
    }
    if ($upload['size'] > SIMCITY_INVOICE_MAX_BYTES) {
        return "Fichier trop volumineux (max " . round(SIMCITY_INVOICE_MAX_BYTES / 1048576) . " Mo).";
    }
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime  = $finfo->file($upload['tmp_name']);
    if ($mime !== 'application/pdf') {
        return "Type de fichier non autorisé ($mime). Envoyez la facture PDF de l'opérateur.";
    }
    return '';
}

// Binaire pdftotext : surchargable par variable d'environnement (tests, Windows).
function simcity_invoice_pdftotext_bin(): string {
    return getenv('SIMCITY_PDFTOTEXT') ?: 'pdftotext';
}

// Délai maximal d'extraction, en secondes. Une facture mensuelle réelle
// (plusieurs centaines de pages) s'extrait en quelques secondes ; la marge est
// large à dessein, le seuil ne vise que les blocages francs.
const SIMCITY_PDFTOTEXT_TIMEOUT = 60;

// Extrait le texte d'un PDF avec mise en page préservée (-layout).
// stdout et stderr sont séparés : les warnings poppler ne doivent jamais se
// mêler au texte parsé, et un binaire absent doit se diagnostiquer comme tel
// (pas comme « facture illisible »).
//
// La lecture est bornée dans le temps. poppler est historiquement sujet aux
// boucles et aux explosions de complexité sur PDF malformé : sans délai,
// stream_get_contents() attend EOF indéfiniment et immobilise le worker Apache.
// Un dépôt groupé de factures suffirait alors à épuiser le pool de workers.
function simcity_invoice_extract_text(string $pdfPath): string {
    $bin = simcity_invoice_pdftotext_bin();
    $cmd = escapeshellarg($bin) . ' -layout -enc UTF-8 ' . escapeshellarg($pdfPath) . ' -';
    $proc = @proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($proc)) {
        throw new RuntimeException("pdftotext indisponible (binaire : $bin).");
    }

    if (DIRECTORY_SEPARATOR === '\\') {
        // Windows : stream_select() ne sait pas surveiller les tubes de
        // proc_open. On garde la lecture bloquante d'origine — le poste de
        // développement n'expose pas d'uploads, l'enjeu est côté conteneur.
        $out = (string)stream_get_contents($pipes[1]);
        $err = trim((string)stream_get_contents($pipes[2]));
        fclose($pipes[1]); fclose($pipes[2]);
        proc_close($proc);
    } else {
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = ''; $err = ''; $timedOut = false;
        $deadline = microtime(true) + SIMCITY_PDFTOTEXT_TIMEOUT;
        $open = [1 => $pipes[1], 2 => $pipes[2]];
        while ($open) {
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0) { $timedOut = true; break; }
            $read = array_values($open); $w = null; $x = null;
            $sec = (int)$remaining;
            $n = @stream_select($read, $w, $x, $sec, (int)(($remaining - $sec) * 1000000));
            if ($n === false) break;                  // interruption : on sort et on traite ce qu'on a
            if ($n === 0) { $timedOut = true; break; }
            foreach ($read as $pipe) {
                $chunk = fread($pipe, 65536);
                if ($chunk === false || $chunk === '') {
                    if (feof($pipe)) unset($open[$pipe === $pipes[2] ? 2 : 1]);
                    continue;
                }
                if ($pipe === $pipes[2]) $err .= $chunk; else $out .= $chunk;
            }
        }
        if ($timedOut) {
            proc_terminate($proc, 9);
            foreach ($pipes as $p) { if (is_resource($p)) fclose($p); }
            proc_close($proc);
            throw new RuntimeException('Extraction interrompue : pdftotext a dépassé '
                . SIMCITY_PDFTOTEXT_TIMEOUT . " s sur ce PDF. Fichier probablement corrompu.");
        }
        foreach ($pipes as $p) { if (is_resource($p)) fclose($p); }
        proc_close($proc);
        $err = trim($err);
    }

    if (trim($out) === '') {
        if ($err !== '' && (stripos($err, 'not found') !== false || stripos($err, 'reconnu') !== false
                            || stripos($err, 'introuvable') !== false)) {
            throw new RuntimeException("pdftotext indisponible (binaire : $bin) — $err");
        }
        throw new RuntimeException('PDF illisible par pdftotext' . ($err !== '' ? ' — ' . mb_substr($err, 0, 200) : '') . '.');
    }
    return $out;
}

// ─────────────────────────────────────────────────────────────
// PETITS CONVERTISSEURS
// ─────────────────────────────────────────────────────────────

// « 13 224,04 » / « -2,00 » → float (les espaces sont des séparateurs de milliers).
function simcity_inv_amount(?string $s): float {
    if ($s === null) return 0.0;
    $s = str_replace(["\u{202f}", "\u{a0}", ' '], '', trim($s));
    return (float)str_replace(',', '.', $s);
}

// « 01:33:37 » → secondes.
function simcity_inv_seconds(string $s): int {
    $p = array_map('intval', explode(':', $s));
    return count($p) === 3 ? $p[0] * 3600 + $p[1] * 60 + $p[2] : 0;
}

// « 01/06/2026 » ou « 30/03/26 » → « Y-m-d » (null si invalide).
// Le format est choisi selon la longueur de l'année : « d/m/Y » accepterait
// « 26 » comme l'an 26.
function simcity_inv_date(?string $s): ?string {
    if (!$s || !preg_match('/^\d{2}\/\d{2}\/(\d{2,4})$/', $s, $m)) return null;
    $d = DateTime::createFromFormat(strlen($m[1]) === 4 ? 'd/m/Y' : 'd/m/y', $s);
    return $d ? $d->format('Y-m-d') : null;
}

// Normalise un nom pour le rapprochement : majuscules sans accents, sans
// civilité (M. / Mme / Mlle), espaces uniques. « Mme CAZAUX RIBEIRE Anaïs »
// → « CAZAUX RIBEIRE ANAIS ».
function simcity_inv_normalize_name(?string $s): string {
    $s = trim((string)$s);
    if ($s === '') return '';
    $s = preg_replace('/^(M\.|Mme|Mlle|Mr|Mme\.)\s+/iu', '', $s);
    // Table explicite (le //TRANSLIT d'iconv dépend de la libc du système).
    $s = strtr($s, ['à'=>'a','â'=>'a','ä'=>'a','á'=>'a','é'=>'e','è'=>'e','ê'=>'e','ë'=>'e','î'=>'i','ï'=>'i','í'=>'i',
                    'ô'=>'o','ö'=>'o','ó'=>'o','ù'=>'u','û'=>'u','ü'=>'u','ú'=>'u','ç'=>'c','ñ'=>'n','œ'=>'oe','æ'=>'ae',
                    'À'=>'A','Â'=>'A','Ä'=>'A','Á'=>'A','É'=>'E','È'=>'E','Ê'=>'E','Ë'=>'E','Î'=>'I','Ï'=>'I','Í'=>'I',
                    'Ô'=>'O','Ö'=>'O','Ó'=>'O','Ù'=>'U','Û'=>'U','Ü'=>'U','Ú'=>'U','Ç'=>'C','Ñ'=>'N','Œ'=>'OE','Æ'=>'AE']);
    $s = strtoupper(preg_replace('/[^A-Za-z0-9\- ]/', ' ', $s));
    return trim(preg_replace('/\s+/', ' ', $s));
}

// Deux noms désignent-ils la même personne ? Règle unique de l'application,
// utilisée par le rapprochement des factures ET par le contrôle de l'état de
// parc : la même question doit recevoir la même réponse dans les deux écrans.
// Tolérante à l'ordre des mots, aux prénoms composés absents d'un côté et aux
// fautes de frappe légères.
function simcity_name_matches(?string $a, ?string $b): bool {
    $wa = array_values(array_filter(explode(' ', simcity_inv_normalize_name($a))));
    $wb = array_values(array_filter(explode(' ', simcity_inv_normalize_name($b))));
    if (!$wa || !$wb) return false;
    $inter = array_intersect($wa, $wb);
    if (count($inter) >= min(count($wa), count($wb))) return true;   // l'un contient l'autre
    // NB : « 2 mots communs suffisent » serait trop lâche — un patronyme
    // composé partagé (« CAZAUX RIBEIRE Anaïs » / « CAZAUX RIBEIRE Bertrand »)
    // masquerait un vrai changement de titulaire. Si chaque côté garde un mot
    // propre, on ne conclut que sur la distance globale.
    return levenshtein(implode(' ', $wa), implode(' ', $wb)) <= 3;   // tolérance typo
}

// Mots de libellé qui ne sont PAS des morceaux de patronyme : matériel, type
// de ligne, mention d'exploitation. SFR les accole au nom (« IPAD Lainee
// Benjamin »), et le référentiel finit par en garder aussi. Ils ne doivent ni
// être exigés côté facture, ni faire échouer le rapprochement.
const SIMCITY_NAME_FILLERS = ['IPAD', 'IPHONE', 'TABLETTE', 'TABLET', 'TEL', 'TELEPHONE', 'PORTABLE',
                              'MOBILE', 'LIGNE', 'SIM', 'CLE', 'BOX', 'ASTREINTE', 'AUTR', 'SERVICE'];

// Complément DIRECTIONNEL de la règle ci-dessus, quand l'appelant connaît le
// nom et le prénom du référentiel séparément : le champ « Utilisateur » côté
// SFR charrie souvent du texte en plus (service, matériel, mention
// d'astreinte, résidu de mise en page). Si le NOM DE FAMILLE complet du
// référentiel s'y retrouve, c'est la même personne : le surplus ne doit pas
// déclarer un « titulaire différent ».
//
// Décision du 28/07/2026 (demandée explicitement) : le PRÉNOM n'est plus
// exigé. « M. LAINEE Martin » facturé pour la fiche « IPAD Lainee Benjamin »
// est désormais un rapprochement OK — le numéro est le même, la famille est la
// même, et l'écart de prénom relève de la saisie, pas d'un changement de
// titulaire. Contrepartie assumée : un vrai transfert de ligne entre deux
// personnes du même nom (« CAZAUX RIBEIRE Anaïs » → « … Bertrand ») n'est plus
// signalé sur l'écran de rapprochement.
function simcity_name_found_in(?string $sfrText, ?string $lastName, ?string $firstName): bool {
    $hay = array_flip(array_filter(explode(' ', simcity_inv_normalize_name($sfrText))));
    $ln  = array_values(array_diff(array_filter(explode(' ', simcity_inv_normalize_name($lastName))),
                                   SIMCITY_NAME_FILLERS));
    if (!$hay || !$ln) return false;      // sans patronyme exploitable : on ne conclut pas
    foreach ($ln as $w) if (!isset($hay[$w])) return false;   // nom de famille complet requis
    return true;
}

// ─────────────────────────────────────────────────────────────
// PARSEUR PRINCIPAL
// ─────────────────────────────────────────────────────────────

// Parse le texte complet d'une facture. Retourne :
//   ['header' => [...], 'lines' => [...], 'devices' => [...]]
function simcity_invoice_parse(string $text): array {
    $header  = simcity_invoice_parse_header($text);
    $lines   = [];
    $devices = [];

    if ($header['invoice_type'] === 'lines') {
        $lines = simcity_invoice_merge_lines(simcity_invoice_parse_lines($text));
        // Le mois de consommation des blocs fait foi pour month_key.
        if ($lines && !empty($lines[0]['period_start'])) {
            $header['period_start'] = $lines[0]['period_start'];
            $header['period_end']   = $lines[0]['period_end'];
            $header['month_key']    = substr($lines[0]['period_start'], 0, 7);
        }
        if (!$lines) $header['invoice_type'] = 'other'; // 9A sans détail par ligne
    } elseif ($header['invoice_type'] === 'devices') {
        $devices = simcity_invoice_parse_devices($text);
    }
    return ['header' => $header, 'lines' => $lines, 'devices' => $devices];
}

// En-tête (page 1) : numéro, type, compte, dates, totaux.
function simcity_invoice_parse_header(string $text): array {
    $h = ['invoice_number' => null, 'invoice_type' => 'other', 'billing_account' => null,
          'invoice_date' => null, 'period_start' => null, 'period_end' => null,
          'month_key' => null, 'total_ht' => null, 'total_ttc' => null];

    if (preg_match("/N° d(?:e facture|'avoir)\s*:\s*(9[A-Z0-9]+)/u", $text, $m)) {
        $h['invoice_number'] = $m[1];
    }
    $num = (string)$h['invoice_number'];
    if (str_starts_with($num, '9AA'))     $h['invoice_type'] = 'credit';
    elseif (str_starts_with($num, '9AF')) $h['invoice_type'] = 'manual';
    elseif (str_starts_with($num, '9T'))  $h['invoice_type'] = 'devices';
    elseif (str_starts_with($num, '9A')) {
        // 'lines' si le document contient le détail par compte client
        $h['invoice_type'] = (stripos($text, 'détail par compte client') !== false) ? 'lines' : 'other';
    }

    // « N° de compte de facturation : 1166808 H09 » (l'espace avant le
    // sous-compte est un artefact de mise en page).
    if (preg_match('/N° de compte de facturation\s*:\s*([0-9]+(?:\s*[A-Z0-9]{1,5})?)\b/u', $text, $m)) {
        $h['billing_account'] = preg_replace('/\s+/', '', $m[1]);
    }
    if (preg_match('/Date(?:\s*facture)?\s*:\s*(\d{2}\/\d{2}\/\d{4})/u', $text, $m)) {
        $h['invoice_date'] = simcity_inv_date($m[1]);
    }
    if (preg_match('/Montant total HT\s+(-?\s?[\d\s\x{a0}\x{202f}]*\d,\d{2})/u', $text, $m)) {
        $h['total_ht'] = simcity_inv_amount($m[1]);
    }
    if (preg_match('/Montant total TTC\s+(-?\s?[\d\s\x{a0}\x{202f}]*\d,\d{2})/u', $text, $m)) {
        $h['total_ttc'] = simcity_inv_amount($m[1]);
    }
    // Période de consommation (page 1, année parfois sur 2 chiffres).
    if (preg_match('/consommations facturées du\s+(\d{2}\/\d{2}\/\d{2,4})\s+au\s+(\d{2}\/\d{2}\/\d{2,4})/u', $text, $m)) {
        $h['period_start'] = simcity_inv_date($m[1]);
        $h['period_end']   = simcity_inv_date($m[2]);
    }
    // month_key : mois de consommation, sinon mois de la date de facture.
    $h['month_key'] = $h['period_start'] ? substr($h['period_start'], 0, 7)
                    : ($h['invoice_date'] ? substr($h['invoice_date'], 0, 7) : null);
    return $h;
}

// Lignes parasites de la mise en page (en-têtes/pieds de page répétés) à
// ignorer lors de la capture du nom d'utilisateur.
function simcity_inv_is_noise(string $line): bool {
    $l = trim($line);
    if ($l === '') return true;
    return (bool)preg_match(
        '/^(AE\/FE|\d+\/\d+$|Date facture|N° de|Votre détail|MAIRIE |SFR, 16|Veuillez trouver|\d{5} [A-Z])/u', $l)
        || str_contains($l, '/P/');
}

// Fusionne les blocs d'un même numéro au sein d'une même facture (changement
// de forfait ou de sous-compte en cours de mois) : la clé UNIQUE
// (invoice_id, phone_number) n'autorise qu'un enregistrement par numéro —
// sans fusion, les montants du second bloc seraient silencieusement perdus.
function simcity_invoice_merge_lines(array $lines): array {
    $merged = [];
    foreach ($lines as $l) {
        $k = $l['phone_number'];
        if (!isset($merged[$k])) { $merged[$k] = $l; continue; }
        $m =& $merged[$k];
        foreach (['abo_ht','conso_ht','total_ht','surtaxe_ht','intl_ht','hf_ht',
                  'calls_count','calls_seconds','sms_count','mms_count','data_ko',
                  'surtaxe_count','surtaxe_seconds','intl_count','intl_seconds'] as $f) $m[$f] += $l[$f];
        if ($m['sfr_user'] === '' && $l['sfr_user'] !== '') $m['sfr_user'] = $l['sfr_user'];
        if ($m['plan_name'] === null && $l['plan_name'] !== null) $m['plan_name'] = $l['plan_name'];
        if ($m['period_start'] === null && $l['period_start'] !== null) {
            $m['period_start'] = $l['period_start']; $m['period_end'] = $l['period_end'];
        }
        if ($m['catalog_ht'] === null && $l['catalog_ht'] !== null) {
            $m['catalog_ht'] = $l['catalog_ht']; $m['remise_pct'] = $l['remise_pct'];
        }
        unset($m);
    }
    return array_values($merged);
}

// Détail par compte client → un enregistrement par numéro de ligne.
function simcity_invoice_parse_lines(string $text): array {
    $pos = mb_stripos($text, 'détail par compte client');
    if ($pos === false) return [];
    $section = mb_substr($text, $pos);

    // Découpe en blocs : chaque bloc commence à « Référence : 06.xx… ».
    $parts = preg_split('/^(?=\s*Référence\s*:\s*\d{2}\.)/mu', $section);
    array_shift($parts); // avant le premier bloc
    $out = [];

    foreach ($parts as $block) {
        $r = simcity_invoice_parse_line_block($block);
        if ($r !== null) $out[] = $r;
    }
    return $out;
}

function simcity_invoice_parse_line_block(string $block): ?array {
    if (!preg_match('/Référence\s*:\s*((?:\d{2}\.){4}\d{2})/u', $block, $m)) return null;
    $phone = str_replace('.', '', $m[1]);

    $r = ['phone_number' => $phone, 'sfr_user' => '', 'plan_name' => null,
          'abo_ht' => 0.0, 'conso_ht' => 0.0, 'total_ht' => 0.0,
          'calls_count' => 0, 'calls_seconds' => 0, 'sms_count' => 0, 'mms_count' => 0,
          'data_ko' => 0, 'surtaxe_count' => 0, 'surtaxe_seconds' => 0, 'surtaxe_ht' => 0.0,
          'intl_count' => 0, 'intl_seconds' => 0, 'intl_ht' => 0.0, 'hf_ht' => 0.0,
          'catalog_ht' => null, 'remise_pct' => null,
          'period_start' => null, 'period_end' => null];

    $lines = preg_split('/\R/u', $block);

    // ── Nom d'utilisateur : sur la ligne « Utilisateur : » puis les lignes
    // suivantes (colonne de gauche) jusqu'à la phrase « Vos abonnements ».
    $nameParts = []; $nameOpen = false; $nameDone = false;
    foreach ($lines as $line) {
        if ($nameDone) break;
        if (!$nameOpen) {
            if (preg_match('/Utilisateur\s*:\s*(.*)$/u', $line, $mm)) {
                $nameOpen = true;
                $first = preg_split('/\s{3,}/u', trim($mm[1]))[0] ?? '';
                if ($first !== '') $nameParts[] = $first;
                // La phrase peut déjà être sur cette ligne (nom vide).
                if (str_contains($line, 'Vos abonnements')) $nameDone = true;
            }
            continue;
        }
        if (simcity_inv_is_noise($line)) continue;
        $p = mb_strpos($line, 'Vos abonnements');
        if ($p !== false) {
            $left = trim(mb_substr($line, 0, $p));
            if ($left !== '') $nameParts[] = preg_split('/\s{3,}/u', $left)[0];
            $nameDone = true;
        } else {
            $left = preg_split('/\s{3,}/u', trim($line))[0] ?? '';
            if ($left === '' || preg_match('/\d,\d{2}\s*$/', $line)) { continue; }
            // Résidus à ignorer : lettres orphelines du filigrane DUPLICATA,
            // en-têtes de colonnes et libellés d'un bloc voisin décalés par
            // la mise en page.
            if (mb_strlen($left) <= 2) continue;
            if (preg_match('/^(MONTANT TOTAL|Total de vos|Nombre|unitaire|EUR HT|TVA|Prix|Quantité|Compris dans|Au-delà|Forfait )/u', $left)) continue;
            $nameParts[] = $left;
        }
        if (count($nameParts) > 4) $nameDone = true; // garde-fou
    }
    $r['sfr_user'] = trim(preg_replace('/\s+/', ' ', implode(' ', $nameParts)));

    // ── Forfait : première ligne d'abonnement commençant par « Forfait ».
    if (preg_match('/^\s+(Forfait [^\n]*?)\s{2,}\d+\s+\d/mu', $block, $mm)) {
        $r['plan_name'] = trim($mm[1]);
    } elseif (preg_match('/(Forfait [A-Za-z0-9À-ÿ\'’+ .\/-]{2,60}?)(?:\s{2,}|\s*$)/mu', $block, $mm)) {
        // Repli : la mise en page décroche parfois le libellé de sa quantité
        // (nom d'utilisateur sur la même ligne, montant entièrement remisé…).
        $r['plan_name'] = trim($mm[1]);
    }

    // ── Remise marché : « Remise sur abonnement (96,00% de 20,00€ HT) ».
    // Le taux et le prix catalogue sont écrits en clair dans chaque bloc : ils
    // permettent de vérifier que la remise du marché est bien appliquée, au
    // lieu de la deviner à partir du montant facturé.
    if (preg_match('/Remise sur abonnement\s*\(\s*(\d{1,3},\d+)\s*%\s*de\s*([\d\s]*\d,\d{2})\s*€/u', $block, $mm)) {
        $r['remise_pct'] = simcity_inv_amount($mm[1]);
        $r['catalog_ht'] = simcity_inv_amount($mm[2]);
    }

    // ── Montants de synthèse du bloc.
    if (preg_match('/Total de vos abonnements, options et services\s+(-?[\d\s]*\d,\d{2})/u', $block, $mm)) {
        $r['abo_ht'] = simcity_inv_amount($mm[1]);
    }
    if (preg_match('/Total de vos consommations(?:\s+avant remise applicable)?\s+(-?[\d\s]*\d,\d{2})/u', $block, $mm)) {
        $r['conso_ht'] = simcity_inv_amount($mm[1]);
    }
    if (preg_match('/MONTANT TOTAL HT(?!\s+DE)\s+(-?[\d\s]*\d,\d{2})/u', $block, $mm)) {
        $r['total_ht'] = simcity_inv_amount($mm[1]);
    }
    if (preg_match('/consommations facturées du\s+(\d{2}\/\d{2}\/\d{2,4})\s+au\s+(\d{2}\/\d{2}\/\d{2,4})/u', $block, $mm)) {
        $r['period_start'] = simcity_inv_date($mm[1]);
        $r['period_end']   = simcity_inv_date($mm[2]);
    }

    // Filigrane DUPLICATA : sur certains duplicatas, le montant est décroché
    // de son libellé par les lettres du filigrane. Repli arithmétique — dans
    // un bloc SFR, MONTANT TOTAL HT = abonnements + consommations.
    if ($r['total_ht'] == 0.0 && ($r['abo_ht'] != 0.0 || $r['conso_ht'] != 0.0)) {
        $r['total_ht'] = round($r['abo_ht'] + $r['conso_ht'], 2);
    }

    // ── Rubriques de consommation. Deux zones : « Compris dans vos forfaits »
    // (pas de montant) puis « Au-delà ou hors forfait » (montants facturés).
    $inHF = false;
    foreach ($lines as $line) {
        if (stripos($line, 'Compris dans vos forfaits') !== false) { $inHF = false; continue; }
        if (stripos($line, 'Au-delà ou hors forfait')   !== false) { $inHF = true;  continue; }
        if (stripos($line, 'Total de vos consommations') !== false) { $inHF = false; continue; }

        // Le libellé peut contenir un chiffre (« Appels internationaux Zone 2 ») :
        // il commence par un non-chiffre puis court, en lazy, jusqu'au premier
        // double espace suivi des colonnes numériques — les gaps de -layout.
        // Durée : « Appels France   53   01:33:37 [20,00%  0,62] »
        if (preg_match('/^\s+(\D[^\n]*?)\s{2,}(\d+)\s+(\d{1,3}:\d{2}:\d{2})(?:\s+[\d,]+%)?(?:\s+(-?[\d\s]*\d,\d{2}))?\s*$/u', $line, $mm)) {
            simcity_inv_add_conso($r, trim($mm[1]), (int)$mm[2], simcity_inv_seconds($mm[3]), 0, $inHF, simcity_inv_amount($mm[4] ?? null));
            continue;
        }
        // Data : « Data France   35   413386 Ko [20,00%  1,20] »
        if (preg_match('/^\s+(\D[^\n]*?)\s{2,}(\d+)\s+([\d\s]+)\s?Ko(?:\s+[\d,]+%)?(?:\s+(-?[\d\s]*\d,\d{2}))?\s*$/u', $line, $mm)) {
            $ko = (int)preg_replace('/\s+/', '', $mm[3]);
            simcity_inv_add_conso($r, trim($mm[1]), (int)$mm[2], 0, $ko, $inHF, simcity_inv_amount($mm[4] ?? null));
            continue;
        }
        // À l'acte (SMS / MMS) : « SMS France   8   08 A l acte [ 0,00] ».
        // L'apostrophe varie selon la version de poppler (', ’ ou espace).
        if (preg_match("/^\s+(\D[^\n]*?)\s{2,}(\d+)\s+\d+\s+A\s+l\W{0,2}acte(?:\s+[\d,]+%)?(?:\s+(-?[\d\s]*\d,\d{2}))?\s*$/u", $line, $mm)) {
            simcity_inv_add_conso($r, trim($mm[1]), (int)$mm[2], 0, 0, $inHF, simcity_inv_amount($mm[3] ?? null));
            continue;
        }
    }
    return $r;
}

// Ventile une rubrique de consommation dans les compteurs de la ligne.
function simcity_inv_add_conso(array &$r, string $label, int $count, int $seconds, int $ko, bool $horsForfait, float $eur): void {
    $l = mb_strtolower($label);
    $isSurtaxe = str_contains($l, 'surtax');
    // « internationa » couvre « international » ET « internationaux » (le
    // pluriel ne contient pas le singulier : …aux ≠ …al).
    $isIntl    = str_contains($l, 'internationa') || str_contains($l, 'étranger')
              || str_contains($l, 'dom') || str_contains($l, 'roaming') || str_contains($l, 'maghreb');

    if ($isSurtaxe) {
        $r['surtaxe_count'] += $count; $r['surtaxe_seconds'] += $seconds; $r['surtaxe_ht'] += $eur;
    } elseif (str_starts_with($l, 'sms')) {
        // Un SMS reste un SMS, même émis vers/depuis l'international ;
        // seul son éventuel surcoût part dans la colonne international.
        $r['sms_count'] += $count;
        if ($isIntl) $r['intl_ht'] += $eur;
    } elseif (str_starts_with($l, 'mms')) {
        $r['mms_count'] += $count;
        if ($isIntl) $r['intl_ht'] += $eur;
    } elseif ($ko > 0 || str_starts_with($l, 'data')) {
        $r['data_ko'] += $ko;
        if ($isIntl) $r['intl_ht'] += $eur;
    } elseif ($isIntl) { // appels internationaux / en itinérance
        $r['intl_count'] += $count; $r['intl_seconds'] += $seconds; $r['intl_ht'] += $eur;
    } else { // appels (et rubriques voix inconnues)
        $r['calls_count'] += $count; $r['calls_seconds'] += $seconds;
    }
    if ($horsForfait) $r['hf_ht'] += $eur;
}

// Factures 9T : terminaux et accessoires (« Autres prestations »).
function simcity_invoice_parse_devices(string $text): array {
    $out = [];
    // Un article multi-quantité liste un IMEI par exemplaire : une ligne par
    // IMEI (sinon seul le dernier serait rapproché du parc), le montant total
    // réparti au centime près.
    $flush = function(?array $cur) use (&$out): void {
        if (!$cur) return;
        $imeis = $cur['imeis']; unset($cur['imeis']);
        if (count($imeis) <= 1) {
            $cur['imei'] = $imeis[0] ?? null;
            $out[] = $cur;
            return;
        }
        $n = count($imeis); $reste = $cur['total_ht'];
        foreach ($imeis as $i => $im) {
            $part = $i === $n - 1 ? round($reste, 2) : round($cur['total_ht'] / $n, 2);
            $reste -= $part;
            $out[] = ['label' => $cur['label'], 'imei' => $im, 'qty' => 1,
                      'unit_ht' => $cur['unit_ht'], 'total_ht' => $part];
        }
    };
    $lines = preg_split('/\R/u', $text);
    $cur = null;
    foreach ($lines as $line) {
        // « 558160 - APPLE IPHONE 17 256GO BLANC   1   799,00   799,00 »
        if (preg_match('/^\s+(\d{4,8})\s*-\s*(.+?)\s{2,}(\d+)\s+(-?[\d\s]*\d,\d{2})\s+(-?[\d\s]*\d,\d{2})\s*$/u', $line, $m)) {
            $flush($cur);
            $cur = ['label' => trim($m[2]), 'imei' => null, 'imeis' => [], 'qty' => (int)$m[3],
                    'unit_ht' => simcity_inv_amount($m[4]), 'total_ht' => simcity_inv_amount($m[5])];
            continue;
        }
        // Ligne(s) suivante(s) : « IMEI 358843989542106 Garantie 12 mois »
        if ($cur && preg_match('/IMEI\s+(\d{14,16})/u', $line, $m)) {
            $cur['imeis'][] = $m[1];
        }
    }
    $flush($cur);
    return $out;
}

// ─────────────────────────────────────────────────────────────
// ENREGISTREMENT EN BASE
// ─────────────────────────────────────────────────────────────

// Importe un PDF de facture : extraction, parsing, archivage du PDF et
// insertion. Retourne un résumé ['status' => 'ok'|'duplicate'|'error', ...].
function simcity_invoice_import(PDO $pdo, string $pdfTmpPath, string $origName, string $author): array {
    $text   = simcity_invoice_extract_text($pdfTmpPath);
    $parsed = simcity_invoice_parse($text);
    $h = $parsed['header'];

    if (empty($h['invoice_number'])) {
        return ['status' => 'error', 'file' => $origName,
                'message' => "Numéro de facture introuvable — est-ce bien une facture SFR ?"];
    }
    $st = $pdo->prepare("SELECT id FROM invoices WHERE invoice_number=?");
    $st->execute([$h['invoice_number']]);
    if ($st->fetchColumn()) {
        return ['status' => 'duplicate', 'file' => $origName, 'invoice_number' => $h['invoice_number']];
    }

    $pdo->prepare("INSERT INTO invoices (invoice_number, invoice_type, billing_account, invoice_date,
            period_start, period_end, month_key, total_ht, total_ttc, nb_lines, pdf_path, file_name, imported_by)
        VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?,?)")
        ->execute([$h['invoice_number'], $h['invoice_type'], $h['billing_account'], $h['invoice_date'],
            $h['period_start'], $h['period_end'], $h['month_key'], $h['total_ht'], $h['total_ttc'],
            count($parsed['lines']), $origName, $author]);
    $invId = (int)$pdo->lastInsertId();

    simcity_invoice_store_detail($pdo, $invId, $parsed);

    // Archivage du PDF (pièce justificative) APRÈS les écritures : un échec
    // d'insertion ne laisse pas de PDF orphelin sur le disque, et un échec de
    // copie laisse pdf_path à NULL avec un avertissement explicite (plutôt
    // qu'une facture « archivée » dont la ré-analyse échouera plus tard).
    $dir = __DIR__ . '/uploads/invoices';
    if (!is_dir($dir)) @mkdir($dir, 0775, true);
    $safe = preg_replace('/[^A-Za-z0-9_\-]/', '', $h['invoice_number']);
    $dest = "uploads/invoices/$safe.pdf";
    $warn = null;
    if (@copy($pdfTmpPath, __DIR__ . '/' . $dest) && is_file(__DIR__ . '/' . $dest)) {
        $pdo->prepare("UPDATE invoices SET pdf_path=? WHERE id=?")->execute([$dest, $invId]);
    } else {
        $warn = "importée, mais PDF non archivé (droits sur uploads/invoices/ ?) — la ré-analyse sera impossible";
    }

    return ['status' => 'ok', 'file' => $origName, 'invoice_number' => $h['invoice_number'],
            'invoice_id' => $invId, 'type' => $h['invoice_type'], 'month_key' => $h['month_key'],
            'nb_lines' => count($parsed['lines']), 'nb_devices' => count($parsed['devices']),
            'total_ttc' => $h['total_ttc'], 'message' => $warn];
}

// Insère le détail (lignes + matériels) d'une facture déjà enregistrée.
function simcity_invoice_store_detail(PDO $pdo, int $invId, array $parsed): void {
    $h = $parsed['header'];
    if ($parsed['lines']) {
        $ins = $pdo->prepare("INSERT INTO invoice_lines (invoice_id, month_key, billing_account, phone_number, sfr_user, plan_name,
                abo_ht, conso_ht, total_ht, calls_count, calls_seconds, sms_count, mms_count, data_ko,
                surtaxe_count, surtaxe_seconds, surtaxe_ht, intl_count, intl_seconds, intl_ht, hf_ht,
                catalog_ht, remise_pct)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
        foreach ($parsed['lines'] as $l) {
            $mk = $l['period_start'] ? substr($l['period_start'], 0, 7) : ($h['month_key'] ?? '');
            $ins->execute([$invId, $mk, $h['billing_account'], $l['phone_number'], $l['sfr_user'] ?: null, $l['plan_name'],
                $l['abo_ht'], $l['conso_ht'], $l['total_ht'], $l['calls_count'], $l['calls_seconds'],
                $l['sms_count'], $l['mms_count'], $l['data_ko'], $l['surtaxe_count'], $l['surtaxe_seconds'],
                round($l['surtaxe_ht'], 2), $l['intl_count'], $l['intl_seconds'], round($l['intl_ht'], 2),
                round($l['hf_ht'], 2), $l['catalog_ht'], $l['remise_pct']]);
        }
    }
    if ($parsed['devices']) {
        $ins = $pdo->prepare("INSERT INTO invoice_devices (invoice_id, label, imei, qty, unit_ht, total_ht)
                              VALUES (?,?,?,?,?,?)");
        foreach ($parsed['devices'] as $d) {
            $ins->execute([$invId, $d['label'], $d['imei'], $d['qty'], $d['unit_ht'], $d['total_ht']]);
        }
    }
}

// Ré-analyse une facture depuis son PDF archivé avec le parseur courant :
// le détail est reconstruit, l'en-tête mis à jour. Utile après une mise à
// jour du parseur — sans re-téléverser les PDF. Retourne '' ou une erreur.
function simcity_invoice_reparse(PDO $pdo, array $invoice): string {
    $pdf = __DIR__ . '/' . ($invoice['pdf_path'] ?? '');
    if (empty($invoice['pdf_path']) || !is_file($pdf)) return "PDF archivé introuvable";
    try {
        $parsed = simcity_invoice_parse(simcity_invoice_extract_text($pdf));
    } catch (Throwable $e) {
        return $e->getMessage();
    }
    $h = $parsed['header'];
    if (($h['invoice_number'] ?? '') !== $invoice['invoice_number']) return "numéro inattendu dans le PDF";
    $pdo->prepare("DELETE FROM invoice_lines   WHERE invoice_id=?")->execute([$invoice['id']]);
    $pdo->prepare("DELETE FROM invoice_devices WHERE invoice_id=?")->execute([$invoice['id']]);
    $pdo->prepare("UPDATE invoices SET invoice_type=?, billing_account=?, invoice_date=?, period_start=?,
                   period_end=?, month_key=?, total_ht=?, total_ttc=?, nb_lines=? WHERE id=?")
        ->execute([$h['invoice_type'], $h['billing_account'], $h['invoice_date'], $h['period_start'],
                   $h['period_end'], $h['month_key'], $h['total_ht'], $h['total_ttc'],
                   count($parsed['lines']), $invoice['id']]);
    simcity_invoice_store_detail($pdo, (int)$invoice['id'], $parsed);
    return '';
}
