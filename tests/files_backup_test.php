<?php
// ============================================================
//  SimCity — Tests de l'archivage des fichiers téléversés
//               et du rapprochement disque ↔ base
//
//  S'exécute sans base de données : les fichiers sont FABRIQUÉS par le
//  test dans un dossier temporaire, et le rapprochement est appelé sur
//  son cœur sans SGBD (simcity_uploads_compare).
//
//  Couvre :
//    - l'aller-retour tar.gz (contenus identiques, noms > 100 caractères,
//      fichier vide, taille non multiple de 512, sous-dossiers) ;
//    - le refus d'une archive hostile (remontée « ../ », chemin absolu,
//      lettre de lecteur, extension exécutable) ;
//    - le garde-fou du vidage de dossier ;
//    - la classification des orphelins et des références cassées.
//
//  Usage : php tests/files_backup_test.php
// ============================================================

// Le dossier de travail sert aussi de UPLOAD_DIR : simcity_uploads_dir() en
// dépend, et c'est lui qui garde le vidage de dossier.
$TMP = sys_get_temp_dir() . '/simcity_files_test_' . getmypid();
define('UPLOAD_DIR', $TMP . '/uploads/');
require __DIR__ . '/../files_lib.php';

$fails = 0;
function check(string $label, $expected, $actual): void {
    global $fails;
    if ($expected === $actual) { echo "  ✅ $label\n"; }
    else { $fails++; echo "  ❌ $label — attendu " . var_export($expected, true) . ", obtenu " . var_export($actual, true) . "\n"; }
}
function rmrf(string $d): void {
    if (!is_dir($d)) return;
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS),
                                           RecursiveIteratorIterator::CHILD_FIRST) as $i) {
        $i->isDir() ? @rmdir($i->getPathname()) : @unlink($i->getPathname());
    }
    @rmdir($d);
}
rmrf($TMP);
mkdir($TMP . '/uploads/invoices', 0775, true);

// ─────────────────────────────────────────────────────────────
echo "\n── Nommage et normalisation ──\n";
// ─────────────────────────────────────────────────────────────
check("archive compagnon d'un dump",
    'simcity_2026-07-31_020000_uploads.tar.gz',
    simcity_files_archive_for('simcity_2026-07-31_020000.sql'));
check("chemin base normalisé (antislashs, ./)",
    'uploads/invoices/9A00.pdf',
    simcity_files_norm_rel('./uploads\\invoices\\9A00.pdf'));

// ─────────────────────────────────────────────────────────────
echo "\n── Aller-retour de l'archive ──\n";
// ─────────────────────────────────────────────────────────────
$src = $TMP . '/uploads';
// Cas limites choisis pour casser un écrivain tar naïf : nom au-delà des 100
// caractères ustar (préfixe aléatoire + nom d'origine), taille non multiple
// de 512, bloc exact, fichier vide, accents.
$longName = str_repeat('a', 32) . '_' . str_repeat('document-au-nom-tres-long-', 4) . 'fin.pdf';
$fixtures = [
    'invoices/9A0038820383.pdf' => str_repeat("\x01\x9f\xe2", 100000),   // 300 000 o
    'invoices/9AF000045936.pdf' => str_repeat('B', 512),                 // un bloc pile
    'pdf_logo_abcdef.png'       => str_repeat("\x89PNG", 256),
    'deadbeef_document.pdf'     => "contenu accentué : éàüç\n",
    $longName                   => str_repeat('L', 4096),
    'vide.txt'                  => '',
];
foreach ($fixtures as $rel => $data) file_put_contents($src . '/' . $rel, $data);

$archive = $TMP . '/archive.tar.gz';
check('nombre de fichiers archivés', 6, simcity_files_archive_create($src, $archive));

$out = $TMP . '/extrait';
mkdir($out, 0775, true);
[$ok, $skipped] = simcity_files_archive_extract($archive, $out);
check('fichiers extraits', 6, $ok);
check('fichiers ignorés', 0, $skipped);

$identical = true; $wrong = '';
foreach ($fixtures as $rel => $data) {
    if (!is_file($out . '/' . $rel) || file_get_contents($out . '/' . $rel) !== $data) {
        $identical = false; $wrong = $rel; break;
    }
}
check('contenus identiques après aller-retour' . ($wrong ? " (écart : $wrong)" : ''), true, $identical);

[$count, $bytes] = simcity_files_dir_stats($src);
check('inventaire — nombre de fichiers', 6, $count);
check('inventaire — octets', array_sum(array_map('strlen', $fixtures)), $bytes);

// ─────────────────────────────────────────────────────────────
echo "\n── Archive hostile ──\n";
// ─────────────────────────────────────────────────────────────
// Une archive peut être TÉLÉVERSÉE par l'administrateur : on ne se fie pas à
// sa provenance. Rien ne doit s'écrire hors de la cible, aucun script déposé.
$evil = $TMP . '/evil.tar.gz';
$gz = gzopen($evil, 'wb6');
$put = function (string $name, string $data) use ($gz) {
    simcity_tar_put_header($gz, $name, strlen($data), 0, '0', 0644);
    gzwrite($gz, $data);
    $pad = (512 - strlen($data) % 512) % 512;
    if ($pad) gzwrite($gz, str_repeat("\0", $pad));
};
$put('../evade_relatif.txt',                  "remontée\n");
$put('sous/dossier/../../../evade_profond.txt', "remontée profonde\n");
$put('/tmp/evade_absolu.txt',                 "chemin absolu\n");
$put('C:/evade_windows.txt',                  "lettre de lecteur\n");
$put('shell.php',                             "<?php system(\$_GET['c']);\n");
$put('legitime.pdf',                          "contenu sain\n");
gzwrite($gz, str_repeat("\0", 1024));
gzclose($gz);

$evilOut = $TMP . '/evil_out';
mkdir($evilOut, 0775, true);
[$eOk, $eSkip] = simcity_files_archive_extract($evil, $evilOut);
check('archive hostile — un seul fichier extrait', 1, $eOk);
check('archive hostile — cinq entrées refusées', 5, $eSkip);
check('archive hostile — aucun script déposé', false, file_exists($evilOut . '/shell.php'));
$escaped = array_filter([
    $TMP . '/evade_relatif.txt',
    $TMP . '/evade_profond.txt',
    dirname($TMP) . '/evade_relatif.txt',
    sys_get_temp_dir() . '/evade_absolu.txt',
    'C:/evade_windows.txt',
], 'file_exists');
check('archive hostile — aucune écriture hors cible' . ($escaped ? ' : ' . implode(', ', $escaped) : ''),
      true, $escaped === []);

// ─────────────────────────────────────────────────────────────
echo "\n── Garde-fou du vidage de dossier ──\n";
// ─────────────────────────────────────────────────────────────
// Vider le mauvais dossier détruirait des fichiers qu'aucune sauvegarde SQL
// ne contient : la fonction doit refuser toute cible autre que uploads/.
$refused = false;
try { simcity_files_wipe_dir($TMP . '/extrait'); } catch (RuntimeException $e) { $refused = true; }
check('refus de vider un dossier inattendu', true, $refused);
check('le dossier visé est intact', true, is_file($out . '/deadbeef_document.pdf'));

// ─────────────────────────────────────────────────────────────
echo "\n── Rapprochement disque ↔ base ──\n";
// ─────────────────────────────────────────────────────────────
// Références telles que la base les stocke : relatives à la racine de
// l'application. Deux pointent vers des fichiers réellement présents, une
// vers un fichier disparu.
$ref = [
    'uploads/invoices/9A0038820383.pdf' => ['kind' => 'invoice',    'label' => 'Facture 9A0038820383', 'id' => 1],
    'uploads/deadbeef_document.pdf'     => ['kind' => 'attachment', 'label' => 'Document « x.pdf »',   'id' => 7],
    'uploads/invoices/9A_DISPARUE.pdf'  => ['kind' => 'invoice',    'label' => 'Facture 9A_DISPARUE',  'id' => 2],
];
$scan = simcity_uploads_compare($ref, $src, $TMP);

check('références cassées détectées', 1, count($scan['missing']));
check('référence cassée — chemin', 'uploads/invoices/9A_DISPARUE.pdf', $scan['missing'][0]['path']);

$orphanPaths = array_column($scan['orphans'], 'path');
sort($orphanPaths);
check('orphelins détectés', 4, count($orphanPaths));
check('orphelin — PDF de facture non référencé', true,
      in_array('uploads/invoices/9AF000045936.pdf', $orphanPaths, true));
check('orphelin — fichier référencé exclu', false,
      in_array('uploads/invoices/9A0038820383.pdf', $orphanPaths, true));

$byPath = array_column($scan['orphans'], null, 'path');
check('classement — facture',       'invoice',    $byPath['uploads/invoices/9AF000045936.pdf']['kind']);
check('classement — logo',          'logo',       $byPath['uploads/pdf_logo_abcdef.png']['kind']);
check('classement — document',      'attachment', $byPath['uploads/vide.txt']['kind']);
check('facture orpheline — numéro repris du nom (ré-import)', '9AF000045936',
      $byPath['uploads/invoices/9AF000045936.pdf']['hint']);

// Un .htaccess de protection n'est pas un orphelin.
file_put_contents($src . '/.htaccess', "Require all denied\n");
$scan2 = simcity_uploads_compare($ref, $src, $TMP);
check('fichier caché ignoré (.htaccess)', 4, count($scan2['orphans']));

rmrf($TMP);
echo "\n" . ($fails === 0 ? "✅ Tous les tests passent.\n" : "❌ $fails test(s) en échec.\n");
exit($fails === 0 ? 0 : 1);
