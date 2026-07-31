<?php
// ============================================================
//  SimCity — Fichiers téléversés : archivage et cohérence
//
//  Deux responsabilités, une même matière : le dossier uploads/.
//
//    1. ARCHIVE — un instantané tar.gz du dossier, jointe à la sauvegarde
//       SQL. Sans elle une restauration est boiteuse : la base revient en
//       arrière, les fichiers restent au présent. Justificatifs supprimés
//       depuis, PDF importés depuis : les deux se désynchronisent.
//
//    2. RAPPROCHEMENT — disque ↔ base. Fichiers orphelins (plus aucune
//       ligne ne les référence, invisibles mais toujours sur le disque) et
//       références cassées (la ligne existe, le fichier a disparu).
//
//  Aucune dépendance externe : tar écrit à la main (512 octets par
//  en-tête), gzip par zlib — toujours compilé dans PHP. L'extension
//  « zip », absente de l'image php:8.3-apache, n'est PAS requise.
// ============================================================

// Extensions refusées à l'extraction. Une archive produite par SimCity n'en
// contient jamais (l'upload les bloque déjà), mais une archive *téléversée*
// par l'administrateur passe par le même extracteur : on ne se fie pas à sa
// provenance. Doit rester alignée sur la liste de l'upload de documents.
const SIMCITY_FILES_BLOCKED_EXT = ['php','phtml','phar','php3','php4','php5','php7','phps','cgi','pl','py','sh','rb','exe'];

// ─────────────────────────────────────────────────────────────
//  Chemins
// ─────────────────────────────────────────────────────────────

// Chemin absolu du dossier des fichiers téléversés (indépendant du CWD).
function simcity_uploads_dir(): string {
    $dir = defined('UPLOAD_DIR') ? UPLOAD_DIR : 'uploads/';
    if (!preg_match('#^([a-zA-Z]:[\\\\/]|/)#', $dir)) $dir = __DIR__ . '/' . $dir;
    return rtrim($dir, '/\\') . '/';
}

// Nom de l'archive compagnon d'une sauvegarde SQL :
//   simcity_2026-07-31_020000.sql → simcity_2026-07-31_020000_uploads.tar.gz
function simcity_files_archive_for(string $sqlName): string {
    return preg_replace('/\.sql$/', '', basename($sqlName)) . '_uploads.tar.gz';
}

// Normalise un chemin stocké en base (« uploads/x.pdf », « ./uploads\x.pdf »)
// en chemin relatif à la racine de l'application, séparateurs unifiés.
function simcity_files_norm_rel(string $path): string {
    $p = str_replace('\\', '/', trim($path));
    $p = preg_replace('#^\./#', '', $p);
    return ltrim($p, '/');
}

// ─────────────────────────────────────────────────────────────
//  Écriture d'une archive tar.gz
// ─────────────────────────────────────────────────────────────

// Écrit un en-tête tar (ustar) de 512 octets dans le flux gzip.
// Les noms de plus de 100 caractères passent par un en-tête GNU « L »
// (typeflag L) : les pièces jointes portent un préfixe aléatoire de 32
// caractères suivi du nom d'origine, la limite ustar est vite atteinte.
function simcity_tar_put_header($gz, string $name, int $size, int $mtime, string $type, int $mode): void {
    if (strlen($name) > 100) {
        $long = $name . "\0";
        simcity_tar_put_header($gz, '././@LongLink', strlen($long), 0, 'L', 0644);
        gzwrite($gz, $long);
        $pad = (512 - strlen($long) % 512) % 512;
        if ($pad) gzwrite($gz, str_repeat("\0", $pad));
        $name = substr($name, 0, 100);
    }
    $oct = fn(int $v, int $len) => str_pad(decoct($v), $len - 1, '0', STR_PAD_LEFT) . "\0";
    $h  = str_pad($name, 100, "\0");
    $h .= $oct($mode, 8) . $oct(0, 8) . $oct(0, 8);          // mode, uid, gid
    $h .= $oct($size, 12) . $oct($mtime, 12);
    $h .= str_repeat(' ', 8);                                 // somme de contrôle : espaces pendant le calcul
    $h .= $type;
    $h .= str_repeat("\0", 100);                              // linkname
    $h .= "ustar\0" . "00";
    $h .= str_pad('root', 32, "\0") . str_pad('root', 32, "\0");
    $h .= $oct(0, 8) . $oct(0, 8);                            // devmajor, devminor
    $h  = str_pad($h, 512, "\0");                             // prefix + bourrage
    $sum = 0;
    for ($i = 0; $i < 512; $i++) $sum += ord($h[$i]);
    $h = substr_replace($h, str_pad(decoct($sum), 6, '0', STR_PAD_LEFT) . "\0 ", 148, 8);
    gzwrite($gz, $h);
}

// Archive récursivement $srcDir dans $destPath (tar.gz). Retourne le nombre
// de fichiers écrits. Les fichiers sont copiés par blocs : une archive de
// plusieurs centaines de Mo de PDF ne doit pas tenir en mémoire.
function simcity_files_archive_create(string $srcDir, string $destPath): int {
    $srcDir = rtrim($srcDir, '/\\');
    if (!is_dir($srcDir)) throw new RuntimeException("Dossier introuvable : $srcDir");
    // Compression au niveau 1 volontairement : le contenu est presque
    // exclusivement des PDF et des PNG, déjà compressés. Les niveaux
    // supérieurs ne gagnent que quelques pour cent pour plusieurs fois le
    // temps de calcul — or l'archivage automatique se déclenche pendant la
    // requête d'un visiteur, qui attend.
    $gz = @gzopen($destPath, 'wb1');
    if (!$gz) throw new RuntimeException("Impossible d'écrire l'archive : $destPath");
    $n = 0;
    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($srcDir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST);
        foreach ($it as $item) {
            $rel = str_replace('\\', '/', substr($item->getPathname(), strlen($srcDir) + 1));
            if ($rel === '') continue;
            if ($item->isDir()) {
                simcity_tar_put_header($gz, $rel . '/', 0, (int)$item->getMTime(), '5', 0755);
                continue;
            }
            if (!$item->isFile() || !$item->isReadable()) continue;
            $size = (int)$item->getSize();
            $fh = @fopen($item->getPathname(), 'rb');
            if (!$fh) continue;
            simcity_tar_put_header($gz, $rel, $size, (int)$item->getMTime(), '0', 0644);
            $written = 0;
            while ($written < $size && !feof($fh)) {
                $chunk = fread($fh, min(262144, $size - $written));
                if ($chunk === false || $chunk === '') break;
                gzwrite($gz, $chunk);
                $written += strlen($chunk);
            }
            fclose($fh);
            // Le fichier a rétréci pendant la lecture : compléter pour que la
            // taille écrite corresponde à l'en-tête, sinon l'archive est décalée.
            if ($written < $size) gzwrite($gz, str_repeat("\0", $size - $written));
            $pad = (512 - $size % 512) % 512;
            if ($pad) gzwrite($gz, str_repeat("\0", $pad));
            $n++;
        }
        gzwrite($gz, str_repeat("\0", 1024));   // deux blocs vides = fin d'archive
    } finally {
        gzclose($gz);
    }
    return $n;
}

// Taille et nombre de fichiers d'un dossier : [count, bytes].
function simcity_files_dir_stats(string $dir): array {
    if (!is_dir($dir)) return [0, 0];
    $count = 0; $bytes = 0;
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(rtrim($dir, '/\\'), FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST);
    foreach ($it as $item) {
        if ($item->isFile()) { $count++; $bytes += (int)$item->getSize(); }
    }
    return [$count, $bytes];
}

// ─────────────────────────────────────────────────────────────
//  Lecture d'une archive tar.gz
// ─────────────────────────────────────────────────────────────

// Extrait une archive dans $destDir. Retourne [extraits, ignorés].
// Tout chemin absolu, remontant (« ../ ») ou d'extension exécutable est
// ignoré : l'archive peut venir d'un téléversement, pas seulement de nous.
function simcity_files_archive_extract(string $archivePath, string $destDir): array {
    $gz = @gzopen($archivePath, 'rb');
    if (!$gz) throw new RuntimeException("Archive illisible : " . basename($archivePath));
    $destDir  = rtrim($destDir, '/\\');
    $ok = 0; $skipped = 0; $longName = null;
    try {
        while (!gzeof($gz)) {
            $hdr = gzread($gz, 512);
            if ($hdr === false || strlen($hdr) < 512) break;
            if (trim($hdr, "\0") === '') break;              // bloc de fin
            $size   = (int)octdec(trim(substr($hdr, 124, 12), " \0"));
            $type   = substr($hdr, 156, 1);
            $blocks = (int)ceil($size / 512);

            if ($type === 'L') {                              // nom long (GNU)
                $longName = rtrim(gzread($gz, $blocks * 512), "\0");
                continue;
            }
            if ($longName !== null) {
                $name = $longName;
                $longName = null;
            } else {
                $name   = rtrim(substr($hdr, 0, 100), "\0");
                $prefix = rtrim(substr($hdr, 345, 155), "\0");
                if ($prefix !== '') $name = $prefix . '/' . $name;
            }

            $rel  = str_replace('\\', '/', $name);
            $safe = $rel !== ''
                 && $rel[0] !== '/'
                 && !preg_match('#(^|/)\.\.(/|$)#', $rel)
                 && !preg_match('#^[A-Za-z]:#', $rel)
                 && !in_array(strtolower(pathinfo($rel, PATHINFO_EXTENSION)), SIMCITY_FILES_BLOCKED_EXT, true);

            if (!$safe) {
                if ($blocks) gzread($gz, $blocks * 512);
                $skipped++;
                continue;
            }
            if ($type === '5') {                              // répertoire
                @mkdir($destDir . '/' . rtrim($rel, '/'), 0775, true);
                continue;
            }
            if ($type !== '0' && $type !== "\0" && $type !== '') {
                if ($blocks) gzread($gz, $blocks * 512);
                $skipped++;
                continue;
            }
            $target = $destDir . '/' . $rel;
            $dir    = dirname($target);
            if (!is_dir($dir)) @mkdir($dir, 0775, true);
            $out = @fopen($target, 'wb');
            $left = $size;
            while ($left > 0) {
                $chunk = gzread($gz, min(262144, $left));
                if ($chunk === false || $chunk === '') break;
                if ($out) fwrite($out, $chunk);
                $left -= strlen($chunk);
            }
            if ($out) { fclose($out); $ok++; } else { $skipped++; }
            $pad = (512 - $size % 512) % 512;
            if ($pad) gzread($gz, $pad);
        }
    } finally {
        gzclose($gz);
    }
    return [$ok, $skipped];
}

// Vide le contenu d'un dossier (le dossier lui-même est conservé).
// Garde-fou volontairement strict : la cible doit être le dossier des
// téléversements de CETTE installation. Une erreur de chemin ici effacerait
// des données irrécupérables — aucune sauvegarde ne contient les fichiers
// hors archive.
function simcity_files_wipe_dir(string $dir): int {
    $real = realpath($dir);
    $expected = realpath(rtrim(simcity_uploads_dir(), '/\\'));
    if ($real === false || $expected === false || $real !== $expected) {
        throw new RuntimeException("Refus de vider un dossier inattendu : $dir");
    }
    $n = 0;
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($real, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $item) {
        if ($item->isDir()) { @rmdir($item->getPathname()); }
        elseif (@unlink($item->getPathname())) { $n++; }
    }
    return $n;
}

// Remplace le contenu de uploads/ par celui de l'archive.
// Retourne ['deleted' => n, 'extracted' => n, 'skipped' => n].
function simcity_files_restore(string $archivePath): array {
    if (!is_file($archivePath)) throw new RuntimeException("Archive introuvable : " . basename($archivePath));
    $dir = rtrim(simcity_uploads_dir(), '/\\');
    if (!is_dir($dir) && !@mkdir($dir, 0775, true)) throw new RuntimeException("Dossier des téléversements inaccessible : $dir");
    $deleted = simcity_files_wipe_dir($dir);
    [$ok, $skipped] = simcity_files_archive_extract($archivePath, $dir);
    return ['deleted' => $deleted, 'extracted' => $ok, 'skipped' => $skipped];
}

// ─────────────────────────────────────────────────────────────
//  Rapprochement disque ↔ base
// ─────────────────────────────────────────────────────────────

// Inventaire des chemins référencés en base : chemin relatif => description.
// Trois familles seulement écrivent dans uploads/ : PDF de factures,
// pièces jointes des fiches agents, logo des bons PDF.
function simcity_files_referenced(PDO $pdo): array {
    $ref = [];
    $add = function (?string $path, string $kind, string $label, $id) use (&$ref) {
        $p = simcity_files_norm_rel((string)$path);
        if ($p !== '') $ref[$p] = ['kind' => $kind, 'label' => $label, 'id' => $id];
    };
    foreach ($pdo->query("SELECT id, invoice_number, pdf_path FROM invoices WHERE pdf_path IS NOT NULL AND pdf_path <> ''") as $r) {
        $add($r['pdf_path'], 'invoice', 'Facture ' . $r['invoice_number'], (int)$r['id']);
    }
    foreach ($pdo->query("SELECT id, file_name, file_path FROM attachments WHERE file_path IS NOT NULL AND file_path <> ''") as $r) {
        $add($r['file_path'], 'attachment', 'Document « ' . $r['file_name'] . ' »', (int)$r['id']);
    }
    $logo = $pdo->query("SELECT setting_value FROM settings WHERE setting_key='pdf_logo_path'")->fetchColumn();
    if ($logo) $add($logo, 'logo', 'Logo des bons PDF', null);
    return $ref;
}

// Compare le disque et la base. Retourne :
//   ['orphans' => [...]]  fichiers présents sur le disque, référencés par rien
//   ['missing' => [...]]  lignes en base dont le fichier a disparu
function simcity_uploads_scan(PDO $pdo): array {
    return simcity_uploads_compare(simcity_files_referenced($pdo));
}

// Cœur du rapprochement, isolé de la base : l'inventaire des références est
// passé en argument, les racines sont paramétrables. Testable sans SGBD.
function simcity_uploads_compare(array $ref, ?string $root = null, ?string $appRoot = null): array {
    $root    = rtrim($root    ?? simcity_uploads_dir(), '/\\');
    $appRoot = rtrim($appRoot ?? __DIR__, '/\\');
    $orphans = [];
    $missing = [];

    // Sens 1 : disque → base
    if (is_dir($root)) {
        $base = basename($root);
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST);
        foreach ($it as $item) {
            if (!$item->isFile()) continue;
            $sub = str_replace('\\', '/', substr($item->getPathname(), strlen($root) + 1));
            if ($sub === '' || str_starts_with(basename($sub), '.')) continue;   // .htaccess de protection
            $rel = $base . '/' . $sub;
            if (isset($ref[$rel])) continue;
            $kind = str_starts_with($sub, 'invoices/') ? 'invoice'
                  : (str_starts_with($sub, 'pdf_logo_') ? 'logo' : 'attachment');
            $hint = null;
            if ($kind === 'invoice') {
                // Le PDF porte le numéro de facture : il est ré-importable tel quel.
                $hint = pathinfo($sub, PATHINFO_FILENAME);
            }
            $orphans[] = ['path' => $rel, 'kind' => $kind, 'size' => (int)$item->getSize(),
                          'mtime' => (int)$item->getMTime(), 'hint' => $hint];
        }
    }
    usort($orphans, fn($a, $b) => [$a['kind'], $a['path']] <=> [$b['kind'], $b['path']]);

    // Sens 2 : base → disque
    foreach ($ref as $rel => $meta) {
        if (!is_file($appRoot . '/' . $rel)) {
            $missing[] = $meta + ['path' => $rel];
        }
    }
    usort($missing, fn($a, $b) => [$a['kind'], $a['path']] <=> [$b['kind'], $b['path']]);

    return ['orphans' => $orphans, 'missing' => $missing];
}

// Supprime les fichiers orphelins désignés. Le statut d'orphelin est
// RECALCULÉ ici : le formulaire transmet des chemins, jamais une autorisation.
// Un fichier redevenu référencé entre l'affichage et la validation est épargné.
function simcity_uploads_delete_orphans(PDO $pdo, array $rels): array {
    $scan = simcity_uploads_scan($pdo);
    $allowed = array_column($scan['orphans'], 'path');
    $deleted = 0; $refused = 0;
    foreach ($rels as $rel) {
        $rel = simcity_files_norm_rel((string)$rel);
        if (!in_array($rel, $allowed, true)) { $refused++; continue; }
        if (@unlink(__DIR__ . '/' . $rel)) $deleted++; else $refused++;
    }
    return ['deleted' => $deleted, 'refused' => $refused];
}
