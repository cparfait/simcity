<?php
// ============================================================
//  SimCity — Sauvegarde / restauration SQL (bibliothèque partagée)
//
//  Utilisée par :
//    - index.php  (module d'administration)
//    - backup.php (tâche planifiée / cron)
//
//  Aucune dépendance externe : dump 100 % PHP via PDO.
// ============================================================

// Écrit un dump SQL complet (structure + données) dans un flux ouvert.
function simcity_write_dump(PDO $pdo, $fh): void {
    fwrite($fh, "-- ============================================================\n");
    fwrite($fh, "-- SimCity v" . (defined('APP_VERSION') ? APP_VERSION : '1.0') . " — Sauvegarde de `" . DB_NAME . "`\n");
    fwrite($fh, "-- Générée le " . date('d/m/Y \a\\t H:i:s') . "\n");
    fwrite($fh, "-- Restauration : mysql -u <user> -p " . DB_NAME . " < ce_fichier.sql\n");
    fwrite($fh, "-- ============================================================\n\n");
    fwrite($fh, "SET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\n\n");

    foreach ($pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN) as $table) {
        $create = $pdo->query("SHOW CREATE TABLE `$table`")->fetch(PDO::FETCH_ASSOC);
        fwrite($fh, "-- ── Table `$table` ──\n");
        fwrite($fh, "DROP TABLE IF EXISTS `$table`;\n" . $create['Create Table'] . ";\n\n");
        $rows = $pdo->query("SELECT * FROM `$table`");
        while ($row = $rows->fetch(PDO::FETCH_ASSOC)) {
            $cols = '`' . implode('`,`', array_keys($row)) . '`';
            $vals = implode(',', array_map(fn($v) => $v === null ? 'NULL' : $pdo->quote((string)$v), array_values($row)));
            fwrite($fh, "INSERT INTO `$table` ($cols) VALUES ($vals);\n");
        }
        fwrite($fh, "\n");
    }
    fwrite($fh, "SET FOREIGN_KEY_CHECKS=1;\n-- Fin de la sauvegarde\n");
}

// Chemin absolu du dossier de sauvegardes (résolu depuis config, indépendant du CWD).
function simcity_backup_dir(): string {
    $dir = defined('BACKUP_DIR') ? BACKUP_DIR : 'backups/';
    // Chemin relatif → ancré sur le dossier de l'application
    if (!preg_match('#^([a-zA-Z]:[\\\\/]|/)#', $dir)) $dir = __DIR__ . '/' . $dir;
    return rtrim($dir, '/\\') . '/';
}

// Crée une sauvegarde sur le disque puis applique la rotation. Retourne le nom du fichier.
function simcity_backup_to_disk(PDO $pdo, ?string $dir = null, ?int $retention = null): string {
    $dir       = $dir ?? simcity_backup_dir();
    $retention = $retention ?? (defined('BACKUP_RETENTION') ? BACKUP_RETENTION : 7);
    if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
        throw new RuntimeException("Impossible de créer le dossier de sauvegarde : $dir");
    }
    // Les sauvegardes contiennent signatures + mot de passe SMTP : jamais servies par le web.
    $ht = $dir . '.htaccess';
    if (!file_exists($ht)) @file_put_contents($ht, "Require all denied\nDeny from all\n");

    $name = 'simcity_' . date('Y-m-d_His') . '.sql';
    $path = $dir . $name;
    $fh = fopen($path, 'w');
    if (!$fh) throw new RuntimeException("Impossible d'écrire dans : $path");
    try { simcity_write_dump($pdo, $fh); } finally { fclose($fh); }

    simcity_prune_backups($dir, $retention);
    return $name;
}

// Conserve les N sauvegardes les plus récentes, supprime les plus anciennes.
function simcity_prune_backups(string $dir, int $retention): void {
    $files = glob(rtrim($dir, '/\\') . '/simcity_*.sql') ?: [];
    rsort($files);   // nom horodaté → tri lexical = tri chronologique inverse
    foreach (array_slice($files, max(1, $retention)) as $old) @unlink($old);
}

// Liste les sauvegardes présentes (de la plus récente à la plus ancienne).
function simcity_list_backups(?string $dir = null): array {
    $dir   = $dir ?? simcity_backup_dir();
    $files = glob(rtrim($dir, '/\\') . '/simcity_*.sql') ?: [];
    rsort($files);
    $out = [];
    foreach ($files as $f) {
        $out[] = ['name' => basename($f), 'path' => $f, 'size' => filesize($f), 'mtime' => filemtime($f)];
    }
    return $out;
}

// Restaure un script SQL (contenu texte). Retourne le nombre d'instructions exécutées.
function simcity_restore_sql(PDO $pdo, string $sql): int {
    $stmts = simcity_split_sql($sql);
    $count = 0;
    $pdo->exec("SET FOREIGN_KEY_CHECKS=0");
    foreach ($stmts as $s) {
        if (trim($s) === '') continue;
        $pdo->exec($s);
        $count++;
    }
    $pdo->exec("SET FOREIGN_KEY_CHECKS=1");
    return $count;
}

// Découpe un script SQL en instructions, en respectant :
//   - les chaînes quotées (' et "), y compris les échappements \' et les ; internes,
//   - les valeurs multi-lignes (notes, options…),
//   - les commentaires « -- » en début de ligne (style de nos dumps).
function simcity_split_sql(string $sql): array {
    $stmts = []; $buf = '';
    $len = strlen($sql);
    $inStr = false; $q = ''; $esc = false; $atLineStart = true;

    for ($i = 0; $i < $len; $i++) {
        $c = $sql[$i];
        if ($inStr) {
            $buf .= $c;
            if ($esc)               $esc = false;
            elseif ($c === '\\')    $esc = true;
            elseif ($c === $q)      $inStr = false;
            continue;
        }
        // Commentaire pleine ligne « -- … » (uniquement en début de ligne)
        if ($atLineStart && $c === '-' && $i + 1 < $len && $sql[$i + 1] === '-') {
            while ($i < $len && $sql[$i] !== "\n") $i++;
            $atLineStart = true;
            continue;
        }
        if ($c === "'" || $c === '"') { $inStr = true; $q = $c; $buf .= $c; $atLineStart = false; continue; }
        if ($c === ';')               { $stmts[] = $buf; $buf = ''; $atLineStart = false; continue; }
        $buf .= $c;
        $atLineStart = ($c === "\n" || ($atLineStart && ctype_space($c)));
    }
    if (trim($buf) !== '') $stmts[] = $buf;
    return $stmts;
}
