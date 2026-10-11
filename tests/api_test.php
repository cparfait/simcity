<?php
// ============================================================
//  SimCity — Tests de l'API en lecture seule pour chatIA
//
//  S'exécute sans base de données : les lignes de résultat sont
//  FABRIQUÉES par le test (valeurs inventées), et la validation des
//  paramètres se fait avant toute requête (simcity_api_parse).
//
//  Couvre :
//    - la lecture de la clé (« Authorization: Bearer », variantes CGI,
//      en-têtes de repli) et sa vérification à temps constant ;
//    - le filtrage des appelants par adresse (IPv4, IPv6, CIDR) ;
//    - la liste blanche des données : jamais de code PIN/PUK, RIO, code
//      d'activation eSIM, EID, e-mail, note, jeton ni signature, même si
//      la ligne lue en base les contenait ; identifiants techniques
//      seulement sur demande ;
//    - la validation des paramètres (ressource, numéro, nom, service).
//
//  Usage : php tests/api_test.php
// ============================================================

require __DIR__ . '/../api_lib.php';

$fails = 0;
function check(string $label, $expected, $actual): void {
    global $fails;
    if ($expected === $actual) { echo "  ✅ $label\n"; }
    else { $fails++; echo "  ❌ $label — attendu " . var_export($expected, true) . ", obtenu " . var_export($actual, true) . "\n"; }
}

$CLE = str_repeat('ab12', 16);   // 64 caractères hexadécimaux, inventée

// ─────────────────────────────────────────────────────────────
echo "\n── Clé d'API ──\n";
// ─────────────────────────────────────────────────────────────
check('Bearer lu dans HTTP_AUTHORIZATION', $CLE, simcity_api_bearer(['HTTP_AUTHORIZATION' => "Bearer $CLE"]));
check('Bearer lu après redirection CGI', $CLE, simcity_api_bearer(['REDIRECT_HTTP_AUTHORIZATION' => "bearer  $CLE "]));
check('Bearer lu dans les en-têtes (repli, casse ignorée)', $CLE, simcity_api_bearer([], ['authorization' => "Bearer $CLE"]));
check('Basic refusé', '', simcity_api_bearer(['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('admin:admin')]));
check('clé trop courte refusée', '', simcity_api_bearer(['HTTP_AUTHORIZATION' => 'Bearer abc']));
check('caractères parasites refusés', '', simcity_api_bearer(['HTTP_AUTHORIZATION' => "Bearer $CLE\r\nX-Injecte: 1"]));
check('en-tête absent', '', simcity_api_bearer([]));

$empreinte = simcity_api_key_hash($CLE);
check('empreinte SHA-256 (64 caractères)', 64, strlen($empreinte));
check("l'empreinte n'est pas la clé", false, $empreinte === $CLE);
check('bonne clé acceptée', true, simcity_api_key_valid($empreinte, $CLE));
check('mauvaise clé refusée', false, simcity_api_key_valid($empreinte, str_repeat('cd34', 16)));
check('clé vide refusée', false, simcity_api_key_valid($empreinte, ''));
check('aucune clé enregistrée : tout est refusé', false, simcity_api_key_valid('', $CLE));
$k1 = simcity_api_key_new(); $k2 = simcity_api_key_new();
check('nouvelle clé : 64 caractères hexadécimaux', 1, preg_match('/^[0-9a-f]{64}$/', $k1));
check('deux clés générées diffèrent', false, $k1 === $k2);
check('une clé générée passe la lecture Bearer', $k1, simcity_api_bearer(['HTTP_AUTHORIZATION' => "Bearer $k1"]));

// ─────────────────────────────────────────────────────────────
echo "\n── Adresses autorisées ──\n";
// ─────────────────────────────────────────────────────────────
check('IPv4 exacte', true, simcity_api_cidr_match('10.0.12.40', '10.0.12.40'));
check('IPv4 dans le /24', true, simcity_api_cidr_match('10.0.12.200', '10.0.12.0/24'));
check('IPv4 hors du /24', false, simcity_api_cidr_match('10.0.13.1', '10.0.12.0/24'));
check('IPv4 dans un /20 (masque non aligné sur l\'octet)', true, simcity_api_cidr_match('172.18.15.3', '172.18.0.0/20'));
check('IPv4 hors du /20', false, simcity_api_cidr_match('172.18.16.3', '172.18.0.0/20'));
check('IPv6 dans le /64', true, simcity_api_cidr_match('fd00:1::25', 'fd00:1::/64'));
check('familles différentes', false, simcity_api_cidr_match('10.0.0.1', 'fd00::/8'));
check('préfixe invalide', false, simcity_api_cidr_match('10.0.0.1', '10.0.0.0/33'));
[$ok, $ko] = simcity_api_ip_list_parse("10.0.12.40, 172.18.0.0/16\nfd00::/8 ; pas-une-ip 10.0.0.0/40");
check('liste : entrées valides', ['10.0.12.40', '172.18.0.0/16', 'fd00::/8'], $ok);
check('liste : entrées refusées', ['pas-une-ip', '10.0.0.0/40'], $ko);
check('liste vide : toutes les adresses', true, simcity_api_ip_allowed('203.0.113.9', ''));
check('adresse de la liste acceptée', true, simcity_api_ip_allowed('172.18.0.5', '10.0.12.40, 172.18.0.0/16'));
check('adresse hors liste refusée', false, simcity_api_ip_allowed('203.0.113.9', '10.0.12.40, 172.18.0.0/16'));
check('liste illisible : rien n\'est ouvert', false, simcity_api_ip_allowed('203.0.113.9', 'n-importe-quoi'));

// ─────────────────────────────────────────────────────────────
echo "\n── Liste blanche des données d'une ligne ──\n";
// ─────────────────────────────────────────────────────────────
// Ligne telle qu'un SELECT * négligent la renverrait : les secrets sont là,
// la mise en forme ne doit en laisser passer aucun.
$ligne = [
    'id' => 7, 'phone_number' => '+33 6 00 00 00 01', 'iccid' => '8933000000000000017', 'status' => 'Active', 'archived' => 0,
    'agent_id' => 3, 'esim' => 0, 'sim_vierge' => 0, 'personal_device' => 0, 'activation_date' => '2026-01-15',
    'l_service' => null, 'a_first' => 'Paul', 'a_last' => 'ESSAI', 'a_service' => 'Service fictif',
    'plan_name' => 'Forfait fictif 50 Go', 'plan_data' => '50 Go', 'operator_name' => 'Opérateur fictif',
    'billing_number' => 'CF-0001', 'billing_name' => 'Compte fictif',
    'd_id' => 11, 'd_imei' => '350000000000001', 'd_serial' => 'SN-FICTIF-1', 'd_inventory' => 'INV-1', 'd_status' => 'Deployed',
    'd_mdm' => 1, 'd_archived' => 0, 'd_brand' => 'Marque', 'd_model' => 'Modèle X', 'd_category' => 'Smartphone',
    // à ne JAMAIS transmettre :
    'pin' => '1111', 'puk' => '22222222', 'pin2' => '3333', 'puk2' => '44444444', 'rio' => 'RIO-SECRET',
    'activation_code' => 'LPA:1$sm-dp.exemple$SECRET', 'eid' => '89049000000000000000000000000001',
    'notes' => 'mot de passe du compte : xyz', 'options_details' => 'note libre', 'email' => 'paul.essai@ville.test',
    'token' => str_repeat('f', 64), 'signature_data' => 'data:image/png;base64,AAAA',
];
$vue = simcity_api_ligne_vue($ligne, true);
$json = simcity_api_json($vue);
foreach (['1111', '22222222', '3333', '44444444', 'RIO-SECRET', 'LPA:1', '8904900000', 'mot de passe', 'note libre',
          'paul.essai@ville.test', str_repeat('f', 64), 'data:image'] as $secret) {
    check("jamais transmis : « $secret »", false, strpos($json, $secret) !== false);
}
foreach (['pin', 'puk', 'pin2', 'puk2', 'rio', 'activation_code', 'eid', 'notes', 'email', 'token', 'signature_data'] as $cle) {
    check("aucune clé « $cle » dans la réponse", 0, preg_match('/"' . $cle . '"\s*:/', $json));
}
check('numéro ramené à la forme canonique', '0600000001', $vue['numero']);
check('numéro affiché par paires', '06 00 00 00 01', $vue['numero_affiche']);
check('statut et libellé', ['Active', 'Active'], [$vue['statut'], $vue['statut_libelle']]);
check('agent : nom, prénom, service seulement', ['nom' => 'ESSAI', 'prenom' => 'Paul', 'service' => 'Service fictif'], $vue['agent']);
check('service de la ligne : à défaut, celui de l\'agent', 'Service fictif', $vue['service']);
check('opérateur', 'Opérateur fictif', $vue['operateur']);
check('forfait', ['nom' => 'Forfait fictif 50 Go', 'data' => '50 Go'], $vue['forfait']);
check('SIM physique avec ICCID (identifiants transmis)', ['type' => 'physique', 'vierge' => false, 'iccid' => '8933000000000000017'], $vue['sim']);
check('terminal : modèle et MDM', ['Marque Modèle X', true], [$vue['terminal']['modele'], $vue['terminal']['mdm']]);
check('terminal : IMEI (identifiants transmis)', '350000000000001', $vue['terminal']['imei']);

$sansIds = simcity_api_json(simcity_api_ligne_vue($ligne, false));
foreach (['8933000000000000017', '350000000000001', 'SN-FICTIF-1', 'INV-1'] as $id) {
    check("identifiants retenus : « $id » absent", false, strpos($sansIds, $id) !== false);
}
$stock = simcity_api_ligne_vue(['phone_number' => '0700000002', 'status' => 'Stock', 'esim' => 1, 'sim_vierge' => 0,
                                'l_service' => 'Service de la ligne', 'a_service' => 'ignoré'], true);
check('ligne en stock : sans agent', null, $stock['agent']);
check('ligne en stock : sans terminal', null, $stock['terminal']);
check('eSIM reconnue', 'esim', $stock['sim']['type']);
check('service propre à la ligne', 'Service de la ligne', $stock['service']);

// ─────────────────────────────────────────────────────────────
echo "\n── Bons de remise et de restitution ──\n";
// ─────────────────────────────────────────────────────────────
$now = strtotime('2026-10-10 12:00:00');
$bon = ['numero' => 'BR-2026-0001', 'type' => 'remise', 'status' => 'pending', 'expires_at' => '2026-10-20 00:00:00',
        'created_at' => '2026-10-01 09:00:00', 'signed_at' => null, 'token' => str_repeat('e', 64),
        'signature_data' => 'data:image/png;base64,BBBB', 'items' => '{"lines":[{"pin":"1111"}]}', 'ip' => '10.0.0.9'];
$b = simcity_api_bon_vue($bon, $now);
check('bon en attente', ['en_attente', 'En attente de signature'], [$b['statut'], $b['statut_libelle']]);
check('bon : jamais le jeton, la signature, le contenu figé ni l\'IP', ['numero', 'type', 'statut', 'statut_libelle', 'cree_le', 'signe_le'], array_keys($b));
check('bon expiré', 'expire', simcity_api_bon_vue(['expires_at' => '2026-10-01 00:00:00', 'status' => 'pending'] + $bon, $now)['statut']);
check('bon signé : date de signature', '2026-10-02 10:00:00', simcity_api_bon_vue(['status' => 'signed', 'signed_at' => '2026-10-02 10:00:00'] + $bon, $now)['signe_le']);
check('bon annulé', 'annule', simcity_api_bon_vue(['status' => 'cancelled'] + $bon, $now)['statut']);
check('bon de restitution', 'restitution', simcity_api_bon_vue(['type' => 'restitution'] + $bon, $now)['type']);

// ─────────────────────────────────────────────────────────────
echo "\n── Paramètres d'appel ──\n";
// ─────────────────────────────────────────────────────────────
check('ressource inconnue : 404', 404, simcity_api_parse(['ressource' => 'factures'])[1][0]);
check('ressource absente : 404', 404, simcity_api_parse([])[1][0]);
check('ligne sans critère : 400', 400, simcity_api_parse(['ressource' => 'ligne'])[1][0]);
check('numéro illisible : 400', 400, simcity_api_parse(['ressource' => 'ligne', 'numero' => 'abc'])[1][0]);
check('numéro international ramené à 06…', ['ligne', ['numero' => '0600000001']], simcity_api_parse(['ressource' => 'ligne', 'numero' => '+33 6 00 00 00 01']));
check('paramètre en tableau ignoré (numero[]=)', 400, simcity_api_parse(['ressource' => 'ligne', 'numero' => ['06']])[1][0]);
check('agent : balises retirées', ['ligne', ['agent' => 'Essai']], simcity_api_parse(['ressource' => 'ligne', 'agent' => '<b>Essai</b>']));
check('service trop court : 400', 400, simcity_api_parse(['ressource' => 'ligne', 'service' => 'x'])[1][0]);
check('agent sans nom : 400', 400, simcity_api_parse(['ressource' => 'agent'])[1][0]);
check('agent : nom borné à 100 caractères', 100, mb_strlen(simcity_api_parse(['ressource' => 'agent', 'nom' => str_repeat('é', 300)])[1]['nom']));
check('stock sans paramètre', ['stock', []], simcity_api_parse(['ressource' => 'STOCK']));
check('mots d\'un nom : civilités retirées', ['Jean', 'Pierre', 'ESSAI'], simcity_api_mots('Mme Jean-Pierre ESSAI'));
check('mots d\'un nom : « M. » seul ne donne rien', [], simcity_api_mots('M.'));
check('jokers LIKE échappés', '%50\\%\\_x%', simcity_api_like('50%_x'));
check('JSON sans balise interprétable', false, strpos(simcity_api_json(['x' => '<script>']), '<script>') !== false);
check('JSON : accents gardés', true, strpos(simcity_api_json(['x' => 'Résiliée']), 'Résiliée') !== false);
check('libellé de statut connu', 'Perdu / Volé', simcity_api_statut_libelle('Lost'));
check('libellé de statut inconnu : valeur brute', 'Autre', simcity_api_statut_libelle('Autre'));

echo "\n" . ($fails === 0 ? "✅ Tous les tests passent.\n" : "❌ $fails test(s) en échec.\n");
exit($fails === 0 ? 0 : 1);
