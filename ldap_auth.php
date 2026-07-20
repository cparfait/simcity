<?php
// ============================================================
//  SimCity — Authentification LDAP / Active Directory
//  Port PHP du module ldap_auth de Sentinelle : LDAPS (TLS),
//  validation de certificat configurable, restriction à un
//  groupe AD (groupes imbriqués inclus), provisionnement auto.
//  L'authentification locale et LDAP cohabitent : on tente
//  d'abord le mot de passe local, puis (si activé) un bind LDAP.
// ============================================================

/** Vrai si l'authentification LDAP est activée et utilisable. */
function ldap_auth_enabled(): bool {
    return defined('LDAP_ENABLED') && LDAP_ENABLED
        && LDAP_SERVER !== ''
        && extension_loaded('ldap');
}

/**
 * Construit l'URI de connexion et le port effectif.
 * Schéma optionnel : on accepte un simple FQDN/IP. Si l'utilisateur a saisi
 * ldap:// ou ldaps://, on le détecte pour en déduire le mode TLS.
 * Retourne [uri, use_ssl, port].
 */
function ldap_build_uri(): array {
    $raw = trim(LDAP_SERVER);
    $low = strtolower($raw);
    $schemeSsl = null;
    if (str_starts_with($low, 'ldaps://'))    { $schemeSsl = true;  $raw = substr($raw, 8); }
    elseif (str_starts_with($low, 'ldap://')) { $schemeSsl = false; $raw = substr($raw, 7); }
    $host = trim(rtrim($raw, '/'));
    $useSsl = LDAP_USE_SSL || $schemeSsl === true;
    $port = LDAP_PORT ?: ($useSsl ? 636 : 389);
    if ($useSsl && $port === 389) $port = 636;  // port en clair laissé par défaut -> LDAPS standard
    $uri = ($useSsl ? 'ldaps' : 'ldap') . "://{$host}:{$port}";
    return [$uri, $useSsl, $port];
}

/**
 * Ouvre une connexion LDAP configurée (protocole v3, referrals off, timeouts,
 * options TLS pour LDAPS). Retourne la ressource/objet de connexion, ou null.
 */
function ldap_open_connection() {
    [$uri, $useSsl, ] = ldap_build_uri();
    $conn = @ldap_connect($uri);
    if (!$conn) return null;
    ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);
    ldap_set_option($conn, LDAP_OPT_NETWORK_TIMEOUT, 8);
    if (defined('LDAP_OPT_TIMELIMIT')) ldap_set_option($conn, LDAP_OPT_TIMELIMIT, 8);
    if ($useSsl) {
        // Validation du certificat serveur : désactivable pour CA interne/auto-signée
        if (defined('LDAP_OPT_X_TLS_REQUIRE_CERT')) {
            ldap_set_option($conn, LDAP_OPT_X_TLS_REQUIRE_CERT,
                LDAP_VALIDATE_CERT ? LDAP_OPT_X_TLS_DEMAND : LDAP_OPT_X_TLS_NEVER);
        }
        if (LDAP_CA_CERT !== '' && defined('LDAP_OPT_X_TLS_CACERTFILE')) {
            ldap_set_option($conn, LDAP_OPT_X_TLS_CACERTFILE, LDAP_CA_CERT);
        }
    }
    return $conn;
}

/** Échappe une valeur pour un filtre LDAP (RFC 4515). */
function ldap_esc(string $v): string {
    return ldap_escape($v, '', LDAP_ESCAPE_FILTER);
}

/**
 * Vrai si l'utilisateur appartient au groupe AD (groupes imbriqués inclus).
 * `$group` peut être un DN (CN=...,DC=...) ou un simple nom (cn/sAMAccountName).
 */
function ldap_user_in_group($conn, string $base, string $username, string $group): bool {
    $group = trim($group);
    if ($group === '') return true;
    $groupDn = $group;
    // Nom simple -> résoudre le DN du groupe
    if (!str_contains($group, '=')) {
        $g = ldap_esc($group);
        $sr = @ldap_search($conn, $base, "(&(objectClass=group)(|(cn={$g})(sAMAccountName={$g})))", ['cn'], 0, 1);
        $entries = $sr ? ldap_get_entries($conn, $sr) : false;
        if (!$entries || $entries['count'] === 0) return false;
        $groupDn = $entries[0]['dn'];
    }
    $u = ldap_esc($username);
    // Appartenance récursive (matching rule AD LDAP_MATCHING_RULE_IN_CHAIN)
    $gDnEsc = ldap_esc($groupDn);
    $sr = @ldap_search($conn, $base,
        "(&(sAMAccountName={$u})(memberOf:1.2.840.113556.1.4.1941:={$gDnEsc}))", ['cn'], 0, 1);
    if ($sr) {
        $entries = ldap_get_entries($conn, $sr);
        if ($entries && $entries['count'] > 0) return true;
    }
    // Repli : appartenance directe via memberOf
    $sr = @ldap_search($conn, $base, "(sAMAccountName={$u})", ['memberof'], 0, 1);
    if ($sr) {
        $entries = ldap_get_entries($conn, $sr);
        if ($entries && $entries['count'] > 0 && isset($entries[0]['memberof'])) {
            for ($i = 0; $i < $entries[0]['memberof']['count']; $i++) {
                if (strcasecmp($entries[0]['memberof'][$i], $groupDn) === 0) return true;
            }
        }
    }
    return false;
}

/**
 * Tente un bind LDAP avec les identifiants fournis.
 * Retourne un tableau d'infos (succès) ou null (échec/désactivé) :
 *   ['email' => ?string, 'display_name' => ?string,
 *    'first_name' => ?string, 'last_name' => ?string]
 */
function ldap_authenticate_user(string $username, string $password): ?array {
    if (!ldap_auth_enabled() || $username === '' || $password === '') return null;
    // Un mot de passe vide déclencherait un bind anonyme « réussi » : refusé plus
    // haut, mais on garde la ceinture et les bretelles.

    // Identifiant de bind : UPN (user@domaine) par défaut, sinon gabarit DN.
    if (LDAP_USER_DN_TEMPLATE !== '') {
        $bindUser = str_replace('{username}', $username, LDAP_USER_DN_TEMPLATE);
    } elseif (LDAP_DOMAIN !== '') {
        $bindUser = $username . '@' . LDAP_DOMAIN;
    } else {
        $bindUser = $username;
    }

    $conn = ldap_open_connection();
    if (!$conn) return null;
    if (!@ldap_bind($conn, $bindUser, $password)) {
        ldap_unbind($conn);
        return null;
    }

    $base = LDAP_BASE_DN;
    $requiredGroup = trim(LDAP_REQUIRED_GROUP);

    // Restriction d'accès à un groupe AD (fortement conseillé) : si configuré,
    // seul un membre peut se connecter. Échec fermé si non vérifiable.
    if ($requiredGroup !== '') {
        if ($base === '' || !ldap_user_in_group($conn, $base, $username, $requiredGroup)) {
            ldap_unbind($conn);
            return null;
        }
    }

    // Récupération des attributs (email, nom affiché) pour le provisionnement
    $info = ['email' => null, 'display_name' => null, 'first_name' => null, 'last_name' => null];
    if ($base !== '') {
        $sr = @ldap_search($conn, $base, '(sAMAccountName=' . ldap_esc($username) . ')',
            ['mail', 'displayname', 'givenname', 'sn'], 0, 1);
        if ($sr) {
            $entries = ldap_get_entries($conn, $sr);
            if ($entries && $entries['count'] > 0) {
                $e = $entries[0];
                $info['email']        = $e['mail'][0]        ?? null;
                $info['display_name'] = $e['displayname'][0] ?? null;
                $info['first_name']   = $e['givenname'][0]   ?? null;
                $info['last_name']    = $e['sn'][0]          ?? null;
            }
        }
    }
    ldap_unbind($conn);
    return $info;
}

/**
 * Teste la connexion LDAP (et le bind du compte de service si renseigné).
 * Retourne [ok: bool, message: string] pour affichage direct à l'admin.
 */
function ldap_test_connection(): array {
    if (!defined('LDAP_ENABLED') || !LDAP_ENABLED) {
        return [false, "LDAP désactivé : positionnez LDAP_ENABLED=true dans l'environnement."];
    }
    if (LDAP_SERVER === '') {
        return [false, "Aucun serveur LDAP configuré (LDAP_SERVER)."];
    }
    if (!extension_loaded('ldap')) {
        return [false, "Extension PHP « ldap » non installée (php.ini : extension=ldap)."];
    }
    [, $useSsl, $port] = ldap_build_uri();
    $proto = $useSsl
        ? "LDAPS (TLS, port {$port}, " . (LDAP_VALIDATE_CERT ? 'certificat validé' : 'certificat non validé') . ")"
        : "LDAP non chiffré (port {$port})";
    $conn = ldap_open_connection();
    if (!$conn) return [false, "URI LDAP invalide."];
    if (LDAP_BIND_USER !== '' && LDAP_BIND_PASSWORD !== '') {
        if (!@ldap_bind($conn, LDAP_BIND_USER, LDAP_BIND_PASSWORD)) {
            $err = ldap_error($conn);
            ldap_unbind($conn);
            return [false, "Échec de connexion LDAP : {$err}"];
        }
        if (LDAP_BASE_DN !== '') {
            @ldap_read($conn, LDAP_BASE_DN, '(objectClass=*)', ['dn']);
        }
        ldap_unbind($conn);
        return [true, "Connexion et authentification réussies via {$proto} (compte de service : " . LDAP_BIND_USER . ")."];
    }
    // Sans compte de service : bind anonyme (souvent refusé par AD, mais la
    // jointure TCP/TLS valide déjà l'accessibilité du serveur).
    if (@ldap_bind($conn)) {
        ldap_unbind($conn);
        return [true, "Connexion au serveur LDAP réussie via {$proto} (aucun compte de service configuré)."];
    }
    $err = ldap_error($conn);
    $errno = ldap_errno($conn);
    ldap_unbind($conn);
    // AD refuse le bind anonyme (résultat 1 / operationsError) : le serveur répond, c'est bon signe.
    if (in_array($errno, [1, 8, 48, 49], true)) {
        return [true, "Serveur LDAP joignable via {$proto} (bind anonyme refusé : {$err} — normal sur Active Directory). Renseignez LDAP_BIND_USER/LDAP_BIND_PASSWORD pour un test complet."];
    }
    return [false, "Échec de connexion LDAP : {$err}"];
}
