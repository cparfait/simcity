<?php
// ============================================================
//  SimCity — Normalisation des noms / e-mails (partagé)
//  Utilisé à l'écriture par index.php (fiches, comptes, LDAP,
//  ajout rapide) et import.php (import CSV).
// ============================================================

if (!function_exists('fmtLastName')) {
    /** Nom de famille : tout en MAJUSCULES (gère « MARTIN-DUPONT », « DE LA TOUR »). */
    function fmtLastName(?string $s): ?string {
        $s = trim((string)$s);
        return $s === '' ? null : mb_strtoupper($s, 'UTF-8');
    }

    /** Prénom : 1re lettre de chaque partie en majuscule, reste en minuscules,
     *  en gérant les composés à tiret, espace ou apostrophe
     *  (« jean-pierre » → « Jean-Pierre », « marie claire » → « Marie Claire »). */
    function fmtFirstName(?string $s): ?string {
        $s = trim((string)$s);
        if ($s === '') return null;
        $s = mb_strtolower($s, 'UTF-8');
        return preg_replace_callback('/(^|[\s\-\'’])(\p{L})/u',
            fn($m) => $m[1] . mb_strtoupper($m[2], 'UTF-8'), $s);
    }

    /** E-mail : entièrement en minuscules. */
    function fmtEmail(?string $s): ?string {
        $s = trim((string)$s);
        return $s === '' ? null : mb_strtolower($s, 'UTF-8');
    }
}
