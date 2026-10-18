<?php
// ============================================================
//  SimCity — Vérification des bibliothèques front-end vendues
//
//  Le dépôt n'a pas de gestionnaire de paquets : Chart.js, Bootstrap
//  Icons, qrcode.js et les polices IBM Plex sont copiés tels quels dans
//  vendor/ et js/. vendor.lock.json tient lieu de lockfile : version,
//  paquet npm d'origine et empreinte SHA-256 de chaque fichier.
//
//  Couvre :
//    - chaque fichier listé existe et a l'empreinte attendue (une
//      modification, même d'un octet, est détectée) ;
//    - aucun fichier de vendor/ ou js/ n'échappe au verrouillage ;
//    - avec --upstream : télécharge chaque paquet npm, vérifie son
//      intégrité (sha512 publié par le registre) et que le fichier vendu
//      est identique à celui du paquet. Nécessite un accès réseau.
//
//  Usage : php tests/vendor_test.php [--upstream]
// ============================================================

$root     = dirname(__DIR__);
$upstream = in_array('--upstream', $argv, true);

$fails = 0;
function check(string $label, $expected, $actual): void {
    global $fails;
    if ($expected === $actual) { echo "  ✅ $label\n"; }
    else { $fails++; echo "  ❌ $label — attendu " . var_export($expected, true) . ", obtenu " . var_export($actual, true) . "\n"; }
}

$lock = json_decode((string)file_get_contents("$root/vendor.lock.json"), true);
if (!is_array($lock) || !isset($lock['packages'])) {
    echo "❌ vendor.lock.json illisible.\n";
    exit(1);
}

// ─────────────────────────────────────────────────────────────
echo "\n── Empreintes locales ──\n";
// ─────────────────────────────────────────────────────────────
$listed = [];
foreach ($lock['packages'] as $pkg) {
    foreach ($pkg['files'] as $path => $f) {
        $listed[$path] = true;
        $full = "$root/$path";
        $hash = is_file($full) ? hash_file('sha256', $full) : 'absent';
        check("{$pkg['name']} {$pkg['version']} : $path", $f['sha256'], $hash);
    }
}

// ─────────────────────────────────────────────────────────────
echo "\n── Fichiers non verrouillés ──\n";
// ─────────────────────────────────────────────────────────────
$orphans = [];
foreach (['vendor', 'js'] as $dir) {
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator("$root/$dir", FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($root) + 1));
        if (!isset($listed[$rel])) { $orphans[] = $rel; }
    }
}
sort($orphans);
check('tout fichier de vendor/ et js/ figure dans vendor.lock.json', [], $orphans);

// ─────────────────────────────────────────────────────────────
if ($upstream) {
    echo "\n── Comparaison avec les paquets npm officiels ──\n";
    foreach ($lock['packages'] as $pkg) {
        if (empty($pkg['tarball'])) {
            echo "  ⏭️  {$pkg['name']} : pas de paquet npm, empreintes locales uniquement\n";
            continue;
        }
        $tgz = @file_get_contents($pkg['tarball']);
        if ($tgz === false) {
            check("{$pkg['name']} : téléchargement de {$pkg['tarball']}", true, false);
            continue;
        }
        [$algo, $b64] = explode('-', $pkg['integrity'], 2);
        check("{$pkg['name']} {$pkg['version']} : intégrité du paquet ($algo)", $b64, base64_encode(hash($algo, $tgz, true)));

        // PharData sait lire un .tgz directement, sans l'extraire sur disque.
        $tmp = tempnam(sys_get_temp_dir(), 'vendor') . '.tgz';
        file_put_contents($tmp, $tgz);
        foreach ($pkg['files'] as $path => $f) {
            $ref = @file_get_contents("phar://$tmp/{$f['from']}");
            check("{$pkg['name']} : $path identique à {$f['from']}",
                  $ref === false ? 'absent du paquet' : hash('sha256', $ref),
                  is_file("$root/$path") ? hash_file('sha256', "$root/$path") : 'absent');
        }
        unlink($tmp);
    }
}

echo "\n" . ($fails === 0 ? "✅ Tous les tests passent.\n" : "❌ $fails test(s) en échec.\n");
exit($fails === 0 ? 0 : 1);
