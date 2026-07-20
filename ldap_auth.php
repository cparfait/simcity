<?php
// ============================================================
//  SimCity — Authentification LDAP / Active Directory
//  Port PHP du module ldap_auth de Sentinelle : LDAPS (TLS),
//  validation de certificat configurable, restriction à un
//  groupe AD (groupes imbriqués inclus), provisionnement auto.
//  L'authentification locale et LDAP cohabitent : on tente
//  d'abord le mot de passe local, puis (si activé) un bind LDAP.
//
//  Configuration : page Référentiels → Paramètres (table settings),
//  comme le config_store de Sentinelle. Les variables d'environnement
//  LDAP_* (mêmes noms que Sentinelle) PRIMENT sur la base si définies
//  (déploiement Docker) — le champ correspondant est alors verrouillé
//  dans l'interface.
// ============================================================

// Clés gérées : setting_key (base) => variable d'environnement
const LDAP_KEYS = [
    'ldap_enabled'          => 'LDAP_ENABLED',
    'ldap_server'           => 'LDAP_SERVER',
    'ldap_port'             => 'LDAP_PORT',
    'ldap_use_ssl'          => 'LDAP_USE_SSL',
    'ldap_validate_cert'    => 'LDAP_VALIDATE_CERT',
    'ldap_ca_cert'          => 'LDAP_CA_CERT',
    'ldap_domain'           => 'LDAP_DOMAIN',
    'ldap_base_dn'          => 'LDAP_BASE_DN',
    'ldap_required_group'   => 'LDAP_REQUIRED_GROUP',
    'ldap_user_dn_template' => 'LDAP_USER_DN_TEMPLATE',
    'ldap_bind_user'        => 'LDAP_BIND_USER',
    'ldap_bind_password'    => 'LDAP_BIND_PASSWORD',
];
const LDAP_BOOL_KEYS = ['ldap_enabled', 'ldap_use_ssl', 'ldap_validate_cert'];

/**
 * Charge la configuration LDAP depuis la table settings (à appeler une fois
 * après la connexion PDO). Les variables d'environnement priment.
 */
function ldap_init(PDO $pdo): void {
    $cfg = [];
    try {
        $rows = $pdo->query("SELECT setting_key, setting_value FROM settings WHERE setting_key LIKE 'ldap%'")
                    ->fetchAll(PDO::FETCH_KEY_PAIR);
    } catch (Exception $e) {
        $rows = []; // table pas encore créée (install en cours) -> env uniquement
    }
    foreach (LDAP_KEYS as $key => $env) {
        $envVal = getenv($env);
        $raw = ($envVal !== false && $envVal !== '') ? $envVal : ($rows[$key] ?? '');
        if (in_array($key, LDAP_BOOL_KEYS, true)) {
            $cfg[$key] = filter_var($raw ?: 'false', FILTER_VALIDATE_BOOLEAN);
        } elseif ($key === 'ldap_port') {
            $cfg[$key] = (int)$raw;
        } else {
            $cfg[$key] = trim((string)$raw);
        }
    }
    $GLOBALS['__ldap_cfg'] = $cfg;
}

/** Valeur de configuration LDAP (après ldap_init). */
function ldap_cfg(string $key) {
    $cfg = $GLOBALS['__ldap_cfg'] ?? [];
    return $cfg[$key] ?? (in_array($key, LDAP_BOOL_KEYS, true) ? false : ($key === 'ldap_port' ? 0 : ''));
}

/** Vrai si la clé est imposée par une variable d'environnement (champ verrouillé dans l'UI). */
function ldap_env_locked(string $key): bool {
    $env = LDAP_KEYS[$key] ?? '';
    if ($env === '') return false;
    $v = getenv($env);
    return $v !== false && $v !== '';
}

/** Vrai si l'authentification LDAP est activée et utilisable. */
function ldap_auth_enabled(): bool {
    return ldap_cfg('ldap_enabled')
        && ldap_cfg('ldap_server') !== ''
        && extension_loaded('ldap');
}

/**
 * Construit l'URI de connexion et le port effectif.
 * Schéma optionnel : on accepte un simple FQDN/IP. Si l'utilisateur a saisi
 * ldap:// ou ldaps://, on le détecte pour en déduire le mode TLS.
 * Retourne [uri, use_ssl, port].
 */
function ldap_build_uri(): array {
    $raw = ldap_cfg('ldap_server');
    $low = strtolower($raw);
    $schemeSsl = null;
    if (str_starts_with($low, 'ldaps://'))    { $schemeSsl = true;  $raw = substr($raw, 8); }
    elseif (str_starts_with($low, 'ldap://')) { $schemeSsl = false; $raw = substr($raw, 7); }
    $host = trim(rtrim($raw, '/'));
    $useSsl = ldap_cfg('ldap_use_ssl') || $schemeSsl === true;
    $port = ldap_cfg('ldap_port') ?: ($useSsl ? 636 : 389);
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
                ldap_cfg('ldap_validate_cert') ? LDAP_OPT_X_TLS_DEMAND : LDAP_OPT_X_TLS_NEVER);
        }
        if (ldap_cfg('ldap_ca_cert') !== '' && defined('LDAP_OPT_X_TLS_CACERTFILE')) {
            ldap_set_option($conn, LDAP_OPT_X_TLS_CACERTFILE, ldap_cfg('ldap_ca_cert'));
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
    if (ldap_cfg('ldap_user_dn_template') !== '') {
        $bindUser = str_replace('{username}', $username, ldap_cfg('ldap_user_dn_template'));
    } elseif (ldap_cfg('ldap_domain') !== '') {
        $bindUser = $username . '@' . ldap_cfg('ldap_domain');
    } else {
        $bindUser = $username;
    }

    $conn = ldap_open_connection();
    if (!$conn) return null;
    if (!@ldap_bind($conn, $bindUser, $password)) {
        ldap_unbind($conn);
        return null;
    }

    $base = ldap_cfg('ldap_base_dn');
    $requiredGroup = ldap_cfg('ldap_required_group');

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
    if (!ldap_cfg('ldap_enabled')) {
        return [false, "LDAP désactivé : activez-le puis enregistrez avant de tester."];
    }
    if (ldap_cfg('ldap_server') === '') {
        return [false, "Aucun serveur LDAP configuré."];
    }
    if (!extension_loaded('ldap')) {
        return [false, "Extension PHP « ldap » non installée (php.ini : extension=ldap)."];
    }
    [, $useSsl, $port] = ldap_build_uri();
    $proto = $useSsl
        ? "LDAPS (TLS, port {$port}, " . (ldap_cfg('ldap_validate_cert') ? 'certificat validé' : 'certificat non validé') . ")"
        : "LDAP non chiffré (port {$port})";
    $conn = ldap_open_connection();
    if (!$conn) return [false, "URI LDAP invalide."];
    $bindUser = ldap_cfg('ldap_bind_user');
    $bindPw   = ldap_cfg('ldap_bind_password');
    if ($bindUser !== '' && $bindPw !== '') {
        if (!@ldap_bind($conn, $bindUser, $bindPw)) {
            $err = ldap_error($conn);
            ldap_unbind($conn);
            return [false, "Échec de connexion LDAP : {$err}"];
        }
        if (ldap_cfg('ldap_base_dn') !== '') {
            @ldap_read($conn, ldap_cfg('ldap_base_dn'), '(objectClass=*)', ['dn']);
        }
        ldap_unbind($conn);
        return [true, "Connexion et authentification réussies via {$proto} (compte de service : {$bindUser})."];
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
        return [true, "Serveur LDAP joignable via {$proto} (bind anonyme refusé : {$err} — normal sur Active Directory). Renseignez un compte de service pour un test complet."];
    }
    return [false, "Échec de connexion LDAP : {$err}"];
}
