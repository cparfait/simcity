<?php
// ============================================================
//  SimCity — Normalisation des noms / e-mails (partagé)
//  Utilisé à l'écriture par index.php (fiches, comptes, LDAP,
//  ajout rapide) et import_lib.php (import CSV).
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

    /** Numéro de ligne sous forme canonique : chiffres seuls, préfixe
     *  international 33 ramené à 0 (« +33 6 12 34 56 78 » → « 0612345678 »).
     *  Règle unique de l'application — toute clé de rapprochement entre le
     *  référentiel et une source externe (factures, état de parc, CSV) doit
     *  passer par ici, sous peine de déclarer « inconnue » une ligne connue. */
    function simcity_phone_canon(?string $s): string {
        $d = preg_replace('/\D/', '', (string)$s);
        if (strlen($d) === 11 && strncmp($d, '33', 2) === 0) $d = '0' . substr($d, 2);
        return $d;
    }
}

/** Équivalent SQL de simcity_phone_canon() pour les rapprochements faits en
 *  base : mêmes séparateurs retirés, même conversion +33 → 0. À utiliser tel
 *  quel sur une colonne : sprintf(SIMCITY_SQL_PHONE_CANON, 'ml.phone_number'). */
if (!defined('SIMCITY_SQL_PHONE_CANON')) {
    define('SIMCITY_SQL_PHONE_CANON',
        "REPLACE(REPLACE(REPLACE(REPLACE(%s,' ',''),'.',''),'-',''),'+33','0')");
}
