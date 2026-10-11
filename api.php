<?php
// ============================================================
//  SimCity — API JSON en lecture seule pour chatIA
//
//  Point d'entrée distinct d'index.php : aucune session, aucun cookie,
//  aucun formulaire. Une seule méthode (GET), aucune route d'écriture.
//
//  Appel :
//    GET api.php?ressource=etat
//    GET api.php?ressource=ligne&numero=0612345678   (ou &agent=… ou &service=…)
//    GET api.php?ressource=agent&nom=Durand
//    GET api.php?ressource=stock
//    GET api.php?ressource=synthese
//    En-tête : Authorization: Bearer <clé générée dans SimCity>
//
//  Réglages (super-administrateurs) : Référentiels et Paramètres →
//  Paramètres → API chatIA — activation, clé (seule son empreinte
//  est stockée), limite de débit, adresses autorisées, identifiants
//  techniques transmis ou non. Contenu transmis : voir api_lib.php.
//
//  Réponses : 200 (JSON), 400 (paramètre), 401 (clé absente ou refusée),
//  403 (API désactivée, adresse non autorisée, HTTPS exigé), 404
//  (ressource inconnue), 405 (méthode), 429 (limite de débit), 503 (base).
// ============================================================

require __DIR__ . '/config.php';
require __DIR__ . '/api_lib.php';
date_default_timezone_set(defined('APP_TIMEZONE') ? APP_TIMEZONE : 'Europe/Paris');

// Jamais d'erreur PHP dans la réponse : elle casserait le JSON et pourrait
// révéler des chemins ou des requêtes. Le détail part dans le journal du serveur.
ini_set('display_errors', '0');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function simcity_api_reply(int $code, array $payload, array $headers = []): void {
    http_response_code($code);
    foreach ($headers as $h) header($h);
    echo simcity_api_json($payload);
    exit;
}

function simcity_api_https(): bool {
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') return true;
    if (($_SERVER['SERVER_PORT'] ?? '') === '443') return true;
    return strtolower(explode(',', (string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''))[0]) === 'https';
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET' && $method !== 'HEAD') {
    simcity_api_reply(405, ['erreur' => 'methode', 'message' => 'Lecture seule : méthode GET uniquement.'], ['Allow: GET, HEAD']);
}

// Même règle que l'interface (FORCE_HTTPS) : pas de redirection, qui ferait
// renvoyer la clé par le client ; un refus explicite à la place.
if (defined('FORCE_HTTPS') && FORCE_HTTPS && !simcity_api_https()) {
    simcity_api_reply(403, ['erreur' => 'https_requis', 'message' => 'HTTPS exigé : appelez l\'adresse en https://.']);
}

try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET, DB_USER, DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
} catch (Throwable $e) {
    error_log('SimCity API : base injoignable — ' . $e->getMessage());
    simcity_api_reply(503, ['erreur' => 'base_indisponible', 'message' => 'Base de données indisponible.'], ['Retry-After: 60']);
}

$cfg = simcity_api_settings($pdo);
if (!$cfg['enabled']) {
    simcity_api_reply(403, ['erreur' => 'api_desactivee',
        'message' => "API désactivée : Référentiels et Paramètres → Paramètres → API chatIA."]);
}

$ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');

// Anti-acharnement : trop d'échecs récents depuis cette adresse → tout est
// refusé pendant la fenêtre, clé correcte comprise.
if (simcity_api_rate_count($pdo, 'api_chatia_refus', $ip, SIMCITY_API_REFUS_MINUTES) >= SIMCITY_API_REFUS_MAX) {
    simcity_api_reply(429, ['erreur' => 'trop_d_echecs',
        'message' => 'Trop d\'échecs d\'authentification depuis cette adresse : réessayez dans ' . SIMCITY_API_REFUS_MINUTES . ' minutes.'],
        ['Retry-After: ' . (SIMCITY_API_REFUS_MINUTES * 60)]);
}

if (!simcity_api_ip_allowed($ip, $cfg['ip_allow'])) {
    simcity_api_rate_hit($pdo, 'api_chatia_refus', $ip);
    error_log("SimCity API : appel refusé depuis $ip (adresse non autorisée)");
    simcity_api_reply(403, ['erreur' => 'adresse_refusee', 'message' => 'Adresse appelante non autorisée.']);
}

$headers = function_exists('getallheaders') ? (getallheaders() ?: []) : [];
$cle = simcity_api_bearer($_SERVER, $headers);
if (!simcity_api_key_valid($cfg['key_hash'], $cle)) {
    simcity_api_rate_hit($pdo, 'api_chatia_refus', $ip);
    error_log("SimCity API : clé absente ou refusée depuis $ip");
    simcity_api_reply(401, ['erreur' => 'cle_refusee', 'message' => 'Clé d\'API absente, révoquée ou incorrecte.'],
        ['WWW-Authenticate: Bearer realm="SimCity"']);
}

if (simcity_api_rate_count($pdo, 'api_chatia', $ip, 1) >= $cfg['rate']) {
    simcity_api_reply(429, ['erreur' => 'limite_de_debit',
        'message' => "Limite de {$cfg['rate']} appels par minute atteinte : réessayez dans une minute."], ['Retry-After: 60']);
}
simcity_api_rate_hit($pdo, 'api_chatia', $ip);

[$ressource, $critere] = simcity_api_parse($_GET);
if ($ressource === null) {
    [$code, $erreur] = $critere;
    simcity_api_reply($code, $erreur);
}

try {
    [$code, $payload] = simcity_api_dispatch($pdo, $ressource, $critere, $cfg['identifiers']);
    // Dernier appel accepté (affiché dans Paramètres) : la ressource seule,
    // jamais le numéro ni le nom cherchés.
    simcity_api_setting_set($pdo, 'api_chatia_last_call', date('Y-m-d H:i:s') . '|' . $ip . '|' . $ressource);
} catch (Throwable $e) {
    error_log('SimCity API : ' . $e->getMessage());
    simcity_api_reply(500, ['erreur' => 'erreur_interne', 'message' => 'Erreur interne de SimCity.']);
}
simcity_api_reply($code, $payload);
