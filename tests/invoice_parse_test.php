<?php
// ============================================================
//  SimCity — Test unitaire du parseur de factures (invoice_lib.php)
//
//  S'exécute sans base de données : parse une facture SYNTHÉTIQUE
//  (tests/fixtures/facture_9a_synthetique.txt, aucune donnée réelle)
//  au format texte produit par « pdftotext -layout » et vérifie les
//  valeurs extraites. Lancé par la CI.
//
//  Usage : php tests/invoice_parse_test.php
// ============================================================

require __DIR__ . '/../invoice_lib.php';

$fails = 0;
function check(string $label, $expected, $actual): void {
    global $fails;
    $okv = is_float($expected) ? abs($expected - (float)$actual) < 0.001 : $expected === $actual;
    if ($okv) { echo "  ✅ $label\n"; }
    else { $fails++; echo "  ❌ $label — attendu " . var_export($expected, true) . ", obtenu " . var_export($actual, true) . "\n"; }
}

$text = file_get_contents(__DIR__ . '/fixtures/facture_9a_synthetique.txt');
$p = simcity_invoice_parse($text);
$h = $p['header'];

echo "── En-tête\n";
check('numéro de facture',   '9A0000000001', $h['invoice_number']);
check('type détecté',        'lines',        $h['invoice_type']);
check('compte de facturation', '1234567H01', $h['billing_account']);
check('date de facture',     '2026-06-01',   $h['invoice_date']);
check('mois de consommation','2026-05',      $h['month_key']);
check('total HT',            123.45,         $h['total_ht']);
check('total TTC',           148.14,         $h['total_ttc']);

echo "── Lignes\n";
check('nombre de lignes', 2, count($p['lines']));
[$l1, $l2] = $p['lines'];

check('L1 numéro',        '0611223344',       $l1['phone_number']);
check('L1 utilisateur',   'M. DURAND Paul',   $l1['sfr_user']);
check('L1 forfait',       'Forfait Mobile 5G Eco 1Go', $l1['plan_name']);
check('L1 abonnement HT', 0.80,  $l1['abo_ht']);
check('L1 total HT',      0.80,  $l1['total_ht']);
check('L1 appels',        22,    $l1['calls_count']);
check('L1 durée (s)',     1292,  $l1['calls_seconds']);
check('L1 SMS',           8,     $l1['sms_count']);
check('L1 MMS',           1,     $l1['mms_count']);
check('L1 data (Ko)',     2486,  $l1['data_ko']);
check('L1 hors-forfait',  0.0,   $l1['hf_ht']);

check('L2 numéro',        '0655667788',       $l2['phone_number']);
check('L2 utilisateur (filigrane ignoré)', 'Autr ASTREINTE TECHNIQUE', $l2['sfr_user']);
check('L2 surtaxés (€)',  0.62,  $l2['surtaxe_ht']);
check('L2 surtaxés (nb)', 4,     $l2['surtaxe_count']);
check('L2 surtaxés (s)',  428,   $l2['surtaxe_seconds']);
check('L2 international (€)',  1.50, $l2['intl_ht']);
check('L2 international (nb)', 2,    $l2['intl_count']);
check('L2 hors-forfait total', 2.12, $l2['hf_ht']);
check('L2 data (Ko)',     575601, $l2['data_ko']);
check('L2 total HT (repli abo+conso, montant décroché)', 3.37, $l2['total_ht']);

echo "── Normalisation des noms\n";
check('civilité + accents', 'CAZAUX RIBEIRE ANAIS', simcity_inv_normalize_name('Mme CAZAUX RIBEIRE Anaïs'));
check('date année 2 chiffres', '2026-03-30', simcity_inv_date('30/03/26'));

echo "── Fusion des blocs d'un même numéro (clé UNIQUE invoice_id + numéro)\n";
$zl = fn(array $o) => array_merge(['phone_number'=>'0611223344','sfr_user'=>'','plan_name'=>null,
    'abo_ht'=>0.0,'conso_ht'=>0.0,'total_ht'=>0.0,'calls_count'=>0,'calls_seconds'=>0,'sms_count'=>0,
    'mms_count'=>0,'data_ko'=>0,'surtaxe_count'=>0,'surtaxe_seconds'=>0,'surtaxe_ht'=>0.0,
    'intl_count'=>0,'intl_seconds'=>0,'intl_ht'=>0.0,'hf_ht'=>0.0,'catalog_ht'=>null,'remise_pct'=>null,
    'period_start'=>null,'period_end'=>null], $o);
$merged = simcity_invoice_merge_lines([
    $zl(['sfr_user'=>'DURAND Jean','plan_name'=>'Forfait A','abo_ht'=>10.0,'total_ht'=>12.5,'calls_count'=>3]),
    $zl(['abo_ht'=>5.0,'total_ht'=>5.0,'calls_count'=>2,'data_ko'=>100]),
    $zl(['phone_number'=>'0655667788','total_ht'=>7.0]),
]);
check('deux numéros distincts en sortie', 2,      count($merged));
check('montants sommés (total)',          17.5,   $merged[0]['total_ht']);
check('montants sommés (abonnement)',     15.0,   $merged[0]['abo_ht']);
check('compteurs sommés',                 5,      $merged[0]['calls_count']);
check('nom et forfait conservés',         'DURAND Jean', $merged[0]['sfr_user']);

echo "── 9T : un enregistrement par IMEI d'un article multi-quantité\n";
$devs = simcity_invoice_parse_devices(
    "  558160 - MARQUE MODELE X 128GO     2      799,00     1 598,00\n"
  . "  IMEI 350000000000011 Garantie 12 mois\n"
  . "  IMEI 350000000000012 Garantie 12 mois\n");
check('une ligne par IMEI',   2, count($devs));
check('total réparti au centime', 1598.0, $devs[0]['total_ht'] + $devs[1]['total_ht']);
check('premier IMEI',  '350000000000011', $devs[0]['imei']);
check('second IMEI',   '350000000000012', $devs[1]['imei']);

echo "── Rubriques : libellé avec chiffre et pluriel « internationaux »\n";
$rb = simcity_invoice_parse_line_block(
    "Référence : 06.11.22.33.44\nUtilisateur : DURAND Jean          Vos abonnements\n"
  . "   Au-delà ou hors forfait\n"
  . "   Appels internationaux Zone 2      4   00:12:00      3,50\n");
check('appels classés en international (nb)', 4,   $rb['intl_count']);
check('appels classés en international (€)',  3.5, $rb['intl_ht']);
check('comptés au hors-forfait',              3.5, $rb['hf_ht']);

echo $fails ? "\nÉCHEC : $fails assertion(s) en erreur\n" : "\nOK : parseur validé\n";
exit($fails ? 1 : 0);
