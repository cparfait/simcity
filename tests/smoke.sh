#!/usr/bin/env bash
# ============================================================
#  SimCity — Test de recette (smoke test) en HTTP pur
#
#  ⚠️  À lancer UNIQUEMENT contre une instance de TEST :
#      le script crée un agent, une ligne et un matériel de test,
#      et active puis désactive l'API chatIA (sa clé est révoquée).
#
#  Usage :
#    BASE_URL=http://localhost/simcity/index.php \
#    ADMIN_USER=admin ADMIN_PASS=admin \
#    bash tests/smoke.sh
# ============================================================
set -u

BASE_URL="${BASE_URL:-http://localhost/simcity/index.php}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
STAMP=$(date +%s)
CJ=$(mktemp)
PASS=0; FAIL=0

ok()   { PASS=$((PASS+1)); echo "  ✅ $1"; }
ko()   { FAIL=$((FAIL+1)); echo "  ❌ $1"; }
step() { echo; echo "── $1"; }

echo "SimCity smoke test — $BASE_URL (données de test suffixées _$STAMP)"
read -r -p "Cette instance est-elle bien une instance de TEST ? (oui/NON) " CONFIRM
[ "$CONFIRM" = "oui" ] || { echo "Abandon."; exit 1; }

step "1. Connexion"
# Le formulaire de connexion est protégé par CSRF : récupérer d'abord le jeton
LOGIN_CSRF=$(curl -s -c "$CJ" "$BASE_URL" | grep -o 'name="_csrf" value="[a-f0-9]*"' | grep -o '[a-f0-9]\{64\}' | head -1)
curl -s -c "$CJ" -b "$CJ" -d "username=$ADMIN_USER&password=$ADMIN_PASS&login=1&_csrf=$LOGIN_CSRF" -o /dev/null "$BASE_URL"
CSRF=$(curl -s -b "$CJ" "$BASE_URL?page=dashboard" | grep -o 'const token = "[a-f0-9]*"' | grep -o '[a-f0-9]\{64\}')
[ -n "$CSRF" ] && ok "connecté (jeton CSRF récupéré)" || { ko "échec de connexion"; exit 1; }

step "2. Données de test"
curl -s -b "$CJ" -d "_entity=service&_action=add&name=TEST_$STAMP&direction=&notes=&_csrf=$CSRF" -o /dev/null "$BASE_URL?page=refs&tab=services"
curl -s -b "$CJ" -d "_entity=agent&_action=add&first_name=Test&last_name=Smoke$STAMP&email=&service_id=&_csrf=$CSRF" -o /dev/null "$BASE_URL?page=refs&tab=agents"
curl -s -b "$CJ" -d "_entity=model&_action=add&brand=TestBrand&name=Model$STAMP&category=Smartphone&_csrf=$CSRF" -o /dev/null "$BASE_URL?page=refs&tab=models"
AGENT_ID=$(curl -s -b "$CJ" "$BASE_URL?ajax_global_search=1&q=Smoke$STAMP" | grep -o '"link":"[^"]*"' | head -1 > /dev/null; \
           curl -s -b "$CJ" "$BASE_URL?page=refs&tab=agents" | grep -io "viewAgent([0-9]*, &quot;Test Smoke$STAMP&quot;)" | grep -o '[0-9]\+' | head -1)
[ -n "$AGENT_ID" ] && ok "agent de test créé (id $AGENT_ID)" || { ko "agent introuvable"; exit 1; }
MODEL_ID=$(curl -s -b "$CJ" "$BASE_URL?page=devices" | grep -o "<option value=\"[0-9]*\">TestBrand Model$STAMP</option>" | grep -o '[0-9]\+' | head -1)
curl -s -b "$CJ" -d "_entity=device&_action=add&imei=$STAMP&imei2=&serial_number=SN$STAMP&inventory_label=&model_id=${MODEL_ID:-1}&status=Stock&agent_id=$AGENT_ID&service_id=&purchase_date=&notes=&_csrf=$CSRF" -o /dev/null "$BASE_URL?page=devices"
curl -s -b "$CJ" -d "_entity=line&_action=add&phone_number=07${STAMP:2:8}&iccid=ICC$STAMP&pin=0000&puk=1234&agent_id=$AGENT_ID&billing_id=&plan_id=&service_id=&device_id=&activation_date=&options_details=&status=Active&notes=&_csrf=$CSRF" -o /dev/null "$BASE_URL?page=lines"
ok "matériel + ligne attribués"

step "3. Génération du bon de remise"
BON_URL=$(curl -s -b "$CJ" -d "_entity=bon&_action=generate_remise&agent_id=$AGENT_ID&_csrf=$CSRF" -o /dev/null -w "%{redirect_url}" "$BASE_URL")
echo "$BON_URL" | grep -q "bon_id=" && ok "bon généré ($BON_URL)" || ko "pas de redirection vers le bon"
BON_HTML=$(curl -s -b "$CJ" "$BON_URL")
echo "$BON_HTML" | grep -q "N° BR-" && ok "numéro de bon présent" || ko "numéro de bon absent"
echo "$BON_HTML" | grep -q "$STAMP" && ok "équipements du snapshot présents" || ko "snapshot vide"
TOKEN=$(echo "$BON_HTML" | grep -o 'page=sign&amp;token=[a-f0-9]*' | head -1 | grep -o '[a-f0-9]\{64\}')
[ -n "$TOKEN" ] && ok "lien de signature présent" || ko "lien de signature absent"

step "4. Signature électronique"
SIG="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5CYII="
SIGN_OUT=$(curl -s --data-urlencode "signature_data=$SIG" --data-urlencode "signer_name=Test Smoke" "$BASE_URL?page=sign&token=$TOKEN")
echo "$SIGN_OUT" | grep -q "Signature enregistrée" && ok "bon signé" || ko "échec de signature"
SIGN2=$(curl -s --data-urlencode "signature_data=$SIG" --data-urlencode "signer_name=Intrus" "$BASE_URL?page=sign&token=$TOKEN")
echo "$SIGN2" | grep -q "Déjà signé" && ok "double signature refusée" || ko "double signature acceptée !"
curl -s -b "$CJ" "$BON_URL" | grep -q "✅ Signé le" && ok "signature visible sur le bon" || ko "signature absente du bon"

step "5. Restitution"
FICHE=$(curl -s -b "$CJ" "$BASE_URL?ajax_agent_details=$AGENT_ID")
echo "$FICHE" | grep -q "Générer un bon de restitution" && ok "formulaire de restitution proposé" || ko "formulaire de restitution absent"
DEV_ID=$(echo "$FICHE" | grep -o "name='ret_devices\[\]' value='[0-9]*'" | grep -o '[0-9]\+' | head -1)
LINE_ID=$(echo "$FICHE" | grep -o "name='ret_lines\[\]' value='[0-9]*'" | grep -o '[0-9]\+' | head -1)
RESTIT_URL=$(curl -s -b "$CJ" -d "_entity=bon&_action=generate_restitution&agent_id=$AGENT_ID&ret_devices[]=$DEV_ID&ret_lines[]=$LINE_ID&_csrf=$CSRF" -o /dev/null -w "%{redirect_url}" "$BASE_URL")
RESTIT_HTML=$(curl -s -b "$CJ" "$RESTIT_URL")
echo "$RESTIT_HTML" | grep -q "N° BT-" && ok "bon de restitution généré" || ko "bon de restitution absent"
RTOKEN=$(echo "$RESTIT_HTML" | grep -o 'page=sign&amp;token=[a-f0-9]*' | head -1 | grep -o '[a-f0-9]\{64\}')
curl -s --data-urlencode "signature_data=$SIG" --data-urlencode "signer_name=Test Smoke" "$BASE_URL?page=sign&token=$RTOKEN" | grep -q "Signature enregistrée" && ok "restitution signée" || ko "échec signature restitution"
FICHE2=$(curl -s -b "$CJ" "$BASE_URL?ajax_agent_details=$AGENT_ID")
echo "$FICHE2" | grep -q "Aucun matériel" && ok "matériel retourné en stock" || ko "matériel toujours attribué"
echo "$FICHE2" | grep -q "Aucune ligne active" && ok "ligne retournée en stock" || ko "ligne toujours attribuée"

step "6. Historique"
curl -s -b "$CJ" "$BASE_URL?page=history" | grep -qi "Smoke$STAMP" && ok "cycle visible dans l'historique" || ko "cycle absent de l'historique"

step "7. Facturation / Contrôle"
for T in dash import reconcile conso alerts; do
  OUT=$(curl -s -b "$CJ" "$BASE_URL?page=invoices&tab=$T")
  if echo "$OUT" | grep -q "Facturation / Contrôle" && ! echo "$OUT" | grep -qi "Fatal error"; then
    ok "onglet $T répond"
  else
    ko "onglet $T en erreur"
  fi
done

step "8. API en lecture seule pour chatIA"
API_URL="${BASE_URL%index.php}api.php"
API_PAGE="$BASE_URL?page=refs&tab=settings&sub=api"
api_code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
[ "$(api_code "$API_URL?ressource=etat")" = "403" ] && ok "API désactivée par défaut (403)" || ko "API ouverte sans activation"
curl -s -b "$CJ" -d "_entity=api_chatia&_action=save&api_chatia_enabled=1&api_chatia_rate=120&api_chatia_ip_allow=&api_chatia_identifiers=1&_csrf=$CSRF" -o /dev/null "$API_PAGE"
curl -s -b "$CJ" -d "_entity=api_chatia&_action=generate&_csrf=$CSRF" -o /dev/null "$API_PAGE"
API_KEY=$(curl -s -b "$CJ" "$API_PAGE" | grep -o 'id="api-chatia-cle" value="[a-f0-9]*"' | grep -o '[a-f0-9]\{64\}')
[ -n "$API_KEY" ] && ok "clé générée et affichée" || ko "clé absente de la page"
curl -s -b "$CJ" "$API_PAGE" | grep -q 'id="api-chatia-cle"' && ko "clé affichée une seconde fois" || ok "clé montrée une seule fois"
AUTH="Authorization: Bearer $API_KEY"
[ "$(api_code "$API_URL?ressource=etat")" = "401" ] && ok "sans clé : 401" || ko "appel accepté sans clé"
[ "$(api_code -H "Authorization: Bearer $(printf '0%.0s' {1..64})" "$API_URL?ressource=etat")" = "401" ] && ok "fausse clé : 401" || ko "fausse clé acceptée"
[ "$(api_code -H "$AUTH" "$API_URL?ressource=etat")" = "200" ] && ok "bonne clé : 200" || ko "bonne clé refusée"
LIGNE=$(curl -s -H "$AUTH" "$API_URL?ressource=ligne&numero=07${STAMP:2:8}")
echo "$LIGNE" | grep -q "\"numero\":\"07${STAMP:2:8}\"" && ok "ligne retrouvée par son numéro" || ko "ligne introuvable"
echo "$LIGNE" | grep -qE '"(pin|puk|pin2|puk2|rio|activation_code|notes)"' && ko "code SIM ou note transmis !" || ok "ni PIN, ni PUK, ni RIO, ni note"
AGENT_JSON=$(curl -s -H "$AUTH" "$API_URL?ressource=agent&nom=Smoke$STAMP")
echo "$AGENT_JSON" | grep -q '"nombre":1' && ok "agent retrouvé par son nom" || ko "agent introuvable"
echo "$AGENT_JSON" | grep -q '"numero":"BR-' && ok "bons de l'agent listés" || ko "bons absents"
echo "$AGENT_JSON" | grep -qE '[a-f0-9]{64}|data:image' && ko "jeton ou signature transmis !" || ok "ni jeton ni signature"
for R in stock synthese; do
  [ "$(api_code -H "$AUTH" "$API_URL?ressource=$R")" = "200" ] && ok "ressource $R répond" || ko "ressource $R en erreur"
done
[ "$(api_code -X POST -H "$AUTH" "$API_URL?ressource=etat")" = "405" ] && ok "écriture refusée (405)" || ko "méthode POST acceptée"
[ "$(api_code -H "$AUTH" "$API_URL?ressource=ligne")" = "400" ] && ok "critère manquant : 400" || ko "critère manquant accepté"
curl -s -b "$CJ" -d "_entity=api_chatia&_action=revoke&_csrf=$CSRF" -o /dev/null "$API_PAGE"
[ "$(api_code -H "$AUTH" "$API_URL?ressource=etat")" = "401" ] && ok "clé révoquée : 401" || ko "clé révoquée encore acceptée"
curl -s -b "$CJ" -d "_entity=api_chatia&_action=save&api_chatia_rate=120&api_chatia_ip_allow=&_csrf=$CSRF" -o /dev/null "$API_PAGE"
[ "$(api_code -H "$AUTH" "$API_URL?ressource=etat")" = "403" ] && ok "API désactivée : 403" || ko "API toujours ouverte"

echo
echo "════════════════════════════════════"
echo " Résultat : $PASS réussi(s), $FAIL échec(s)"
echo "════════════════════════════════════"
rm -f "$CJ"
[ "$FAIL" -eq 0 ]
