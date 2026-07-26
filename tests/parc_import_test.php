<?php
// ============================================================
//  SimCity — Tests de l'import depuis SFR et du contrôle
//
//  S'exécute sans base de données ni fichier de données réel : le classeur
//  .xlsx et le CSV sont FABRIQUÉS par le test, avec des valeurs inventées.
//  Couvre le lecteur ZIP écrit à la main (méthodes « stocké » et « deflate »),
//  la lecture du classeur, la reconnaissance des colonnes, les normalisations
//  et la règle de rapprochement des noms partagée avec les factures.
//
//  Usage : php tests/parc_import_test.php
// ============================================================

// Les bibliothèques déclarent leurs propres dépendances : le test n'a rien à
// précharger, et il vérifie donc bien la mise en forme réelle des noms.
require __DIR__ . '/../sfr_parc_lib.php';
require __DIR__ . '/../import_lib.php';

$fails = 0;
function check(string $label, $expected, $actual): void {
    global $fails;
    $ok = is_float($expected) ? abs($expected - (float)$actual) < 0.001 : $expected === $actual;
    if ($ok) { echo "  ✅ $label\n"; }
    else { $fails++; echo "  ❌ $label — attendu " . var_export($expected, true) . ", obtenu " . var_export($actual, true) . "\n"; }
}

// ─────────────────────────────────────────────────────────────
// Fabrique d'archive ZIP minimale (pour ne dépendre d'aucun binaire)
// ─────────────────────────────────────────────────────────────
function zz_zip(array $entries, bool $deflate): string {
    $local = ''; $central = '';
    foreach ($entries as $name => $content) {
        $crc  = crc32($content);
        $raw  = strlen($content);
        $data = $deflate ? gzdeflate($content, 6) : $content;
        $comp = strlen($data);
        $meth = $deflate ? 8 : 0;
        $off  = strlen($local);
        $hdr  = pack('vvvvvVVVvv', 20, 0, $meth, 0, 0, $crc, $comp, $raw, strlen($name), 0);
        $local   .= "PK\x03\x04" . $hdr . $name . $data;
        $central .= "PK\x01\x02" . pack('vvvvvvVVVvvvvvVV', 20, 20, 0, $meth, 0, 0,
                        $crc, $comp, $raw, strlen($name), 0, 0, 0, 0, 0, $off) . $name;
    }
    return $local . $central . "PK\x05\x06" . pack('vvvvVVv', 0, 0, count($entries), count($entries),
        strlen($central), strlen($local), 0);
}

// Classeur synthétique : en-têtes réels du portail, données inventées.
function zz_xlsx(bool $deflate): string {
    $cols = ['Référence', 'Civilité', 'Nom', 'Prénom', 'N° CF', 'Statut Ligne',
             'Date de mise  en service', 'Forfait', 'Terminal communiquant', 'Terminal acheté',
             'IMEI communiquant', 'IMEI acheté', 'N° de CSIM', 'PIN 1', 'PIN 2', 'PUK 1', 'PUK 2', 'RIO'];
    $rows = [
        ['06 11 22 33 44', 'M.', 'durand', 'paul', '1234567H01', 'Actif', '18/06/2019',
         'Forfait Mobile 5G Eco 1Go', 'MARQUE MODELE A', 'MARQUE MODELE A',
         '350000000000001', '350000000000001', '89000000000000000001', '1111', '2222', '11111111', '22222222', 'Voir export RIO'],
        ['0655667788', 'Mme', 'MARTIN', 'Claire', '1234567H02', 'Suspendue', '01/07/2026',
         'Forfait Mobile Eco 5Go', 'MARQUE MODELE B', 'MARQUE MODELE C',
         '350000000000002', '350000000000009', '89000000000000000002', '3333', '4444', '33333333', '44444444', 'AB12CD34EF56'],
        ['pas un numéro', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
    ];
    $xml = '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>';
    // Index 0-based → référence de colonne Excel (0 = A, 25 = Z, 26 = AA).
    $letter = function (int $i): string {
        $s = ''; $n = $i + 1;
        while ($n > 0) { $s = chr(65 + ($n - 1) % 26) . $s; $n = intdiv($n - 1, 26); }
        return $s;
    };
    foreach (array_merge([$cols], $rows) as $r => $line) {
        $xml .= '<row r="' . ($r + 1) . '">';
        foreach ($line as $c => $v) {
            $xml .= '<c r="' . $letter($c) . ($r + 1) . '" t="inlineStr"><is><t>'
                  . htmlspecialchars((string)$v, ENT_XML1) . '</t></is></c>';
        }
        $xml .= '</row>';
    }
    $xml .= '</sheetData></worksheet>';
    return zz_zip(['xl/worksheets/sheet1.xml' => $xml], $deflate);
}

echo "── Lecteur ZIP écrit à la main\n";
foreach (['stocké' => false, 'deflate' => true] as $mode => $deflate) {
    $f = tempnam(sys_get_temp_dir(), 'zzx') . '.xlsx';
    file_put_contents($f, zz_xlsx($deflate));
    $sheet = simcity_zip_read($f, 'xl/worksheets/sheet1.xml');
    check("entrée lue ($mode)", true, is_string($sheet) && str_contains((string)$sheet, 'sheetData'));
    check("entrée absente ($mode)", null, simcity_zip_read($f, 'xl/introuvable.xml'));
    unlink($f);
}

echo "── Lecture du classeur\n";
$f = tempnam(sys_get_temp_dir(), 'zzx') . '.xlsx';
file_put_contents($f, zz_xlsx(true));
$p = simcity_parc_parse($f);
check('enregistrements retenus',            2, count($p['records']));
check('ligne sans numéro ignorée',          1, $p['ignored']);
check('colonnes reconnues',                18, count($p['columns']));
[$r1, $r2] = $p['records'];
check('numéro normalisé',        '0611223344', $r1['phone']);
check('nom mis en forme',            'DURAND', $r1['last_name']);
check('prénom mis en forme',           'Paul', $r1['first_name']);
check('compte de facturation',   '1234567H01', $r1['billing_acct']);
check('date de mise en service', '2019-06-18', $r1['activation']);
check('forfait',   'Forfait Mobile 5G Eco 1Go', $r1['plan']);
check('longueur du PIN retenu',             4, strlen($r1['pin']));
check('longueur du PUK retenu',             8, strlen($r1['puk']));
check('RIO « Voir export RIO » écarté',    '', $r1['rio']);
check('RIO valide conservé',    'AB12CD34EF56', $r2['rio']);
check('terminal utilisé ≠ acheté détectable', true, $r2['imei_used'] !== $r2['imei_bought']);
unlink($f);

echo "── Normalisations\n";
check('statut Actif',            'Active',    simcity_parc_status('Actif'));
check('statut Suspendue',        'Suspended', simcity_parc_status('Suspendue'));
check('statut inconnu',          '',          simcity_parc_status('Bidule'));
check('date invalide',           null,        simcity_parc_date('31/02/2026'));
check('code trop court écarté',  '',          simcity_parc_code('12', 4, 8));
check('code non numérique',      '',          simcity_parc_code('n/a', 4, 8));
check('en-tête normalisé',       'n cf',      simcity_parc_norm_header('N° CF'));
check('en-tête accentué',        'date de fin de periode d engagement',
                                              simcity_parc_norm_header("Date de Fin de  Période d'Engagement"));

echo "── Règle de rapprochement des noms (commune aux deux contrôles)\n";
check('identique',                     true,  simcity_name_matches('DURAND Paul', 'Durand paul'));
check('ordre inversé',                 true,  simcity_name_matches('DURAND Paul', 'Paul DURAND'));
check('prénom absent d\'un côté',      true,  simcity_name_matches('CAZAUX RIBEIRE', 'Cazaux Ribeire Anaïs'));
check('accents et civilité',           true,  simcity_name_matches('Mme CAZAUX RIBEIRE Anaïs', 'CAZAUX RIBEIRE ANAIS'));
check('faute de frappe légère',        true,  simcity_name_matches('MARTIN Claire', 'MARTAN Claire'));
check('personnes différentes',         false, simcity_name_matches('DURAND Paul', 'LEFEBVRE Sophie'));
check('nom vide',                      false, simcity_name_matches('', 'DURAND Paul'));

echo "── Convertisseur CSV → même forme que l'export SFR\n";
$csv = tempnam(sys_get_temp_dir(), 'zzc') . '.csv';
$fh  = fopen($csv, 'w');
foreach ([
    ['LIGNE','x','NOM','PRENOM','NOTES','COMPTE FACTURATION','SERVICE','OPTIONS','y','DATE ACTIVATION','IMEI','MODELE','FORFAIT','ICCID','PIN','PUK','OPERATEUR'],
    ['06 11 22 33 44','','durand','paul','','1234567H01','DSI','','','18/06/2019','350000000000001','MARQUE MODELE A','Forfait Mobile 5G Eco 1Go','89000000000000000001','1111','11111111','SFR'],
    ['','','','','','','DSI','','','','350000000000003','MARQUE MODELE D','','','','',''],
] as $row) {
    fputcsv($fh, array_map(fn($v) => mb_convert_encoding((string)$v, 'Windows-1252', 'UTF-8'), $row), ';');
}
fclose($fh);
$recs = simcity_import_csv_records($csv);
check('ligne sans numéro ignorée',              1, count($recs));
check('numéro normalisé',            '0611223344', $recs[0]['phone']);
check('date convertie',              '2019-06-18', $recs[0]['activation']);
check('compte de facturation',       '1234567H01', $recs[0]['billing_acct']);
$sfrKeys = array_keys($p['records'][0]); $csvKeys = array_keys($recs[0]);
sort($sfrKeys); sort($csvKeys);
check('forme identique à l\'export SFR', $sfrKeys, $csvKeys);
unlink($csv);

echo $fails ? "\nÉCHEC : $fails assertion(s) en erreur\n" : "\nOK : import et contrôle validés\n";
exit($fails ? 1 : 0);
