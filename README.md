# 📱 SimCity v1.0
**Gestion du Parc Mobile — DSI**

SimCity est une application web PHP de gestion de parc téléphonique : lignes mobiles, cartes SIM, terminaux, agents et attributions, avec signature électronique des bons de remise/restitution.

---

## Prérequis

- PHP 8.3+ (version récente maintenue) avec extension PDO MySQL — extension `ldap` en plus pour l'authentification Active Directory (optionnelle)
- MySQL / MariaDB
- Serveur web : Apache, Nginx ou Laragon

---

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/cparfait/simcity.git
```

Placez le dossier dans le répertoire web de votre serveur (ex: `C:\laragon\www\simcity` sous Laragon).

### 2. Configurer la base de données

Les identifiants sont lus depuis les **variables d'environnement** si elles existent,
sinon depuis les valeurs de repli de `config.php`. **Le même `config.php` fonctionne donc
en local ET en conteneur**, sans modification :

```php
define('DB_HOST', getenv('DB_HOST') ?: 'localhost');   // repli local
define('DB_NAME', getenv('DB_NAME') ?: 'simcity_db');
define('DB_USER', getenv('DB_USER') ?: 'root');
define('DB_PASS', getenv('DB_PASS') ?: '');            // vide par défaut sous Laragon
```

- **Laragon / WAMP / XAMPP (local)** : aucune variable définie → repli sur
  `localhost` / `root` / mot de passe vide. Rien à éditer dans la plupart des cas.
- **Docker (prod)** : un `Dockerfile` (PHP 8.3 + Apache, extensions `pdo_mysql` et
  `ldap`) et un `docker-compose.yml` prêts à l'emploi sont fournis à la racine —
  même structure que Sentinelle. Changez le mot de passe `change-me`, puis
  `docker compose up -d`. Les variables d'environnement priment sur les valeurs
  de repli :
  ```yaml
  services:
    app:
      environment:
        DB_HOST: simcity_db        # nom du service MySQL
        DB_NAME: simcity_db
        DB_USER: simcity           # compte dédié (voir install.php)
        DB_PASS: "votre_mot_de_passe"
        FORCE_HTTPS: "false"       # true si pas de reverse proxy
      volumes:
        - ./uploads:/var/www/html/uploads   # persistance des pièces jointes
        - ./backups:/var/www/html/backups   # persistance des sauvegardes
  ```
  `APP_DEBUG` et `FORCE_HTTPS` sont aussi surchargeables par variable d'environnement.

> ⚠️ **Docker — persistance** : montez des volumes pour `uploads/`, `backups/` et les
> données MySQL, sinon leur contenu disparaît à chaque rebuild du conteneur.

### 2 bis. Authentification LDAP / Active Directory (optionnelle)

Les administrateurs peuvent se connecter avec leur **compte Active Directory**,
en complément des comptes locaux. L'ordre de vérification : mot de passe local
d'abord, puis bind LDAP. Un utilisateur AD valide et inconnu en base est
**provisionné automatiquement** (jamais super-admin ; le rôle se promeut
ensuite dans Référentiels → Comptes Admin).

**Configuration dans l'interface** (super-admins) : **Référentiels → Paramètres
→ carte « 🌐 Authentification Active Directory »** — serveur, LDAPS, validation
du certificat, domaine (bind UPN), Base DN, groupe AD requis, compte de service,
avec bouton **🔌 Tester la connexion**. Les réglages sont stockés en base
(table `settings`), comme les Préférences de Sentinelle.

Prérequis : extension PHP `ldap` (php.ini : `extension=ldap` ; Docker :
`docker-php-ext-install ldap` dans l'image). Un avertissement s'affiche dans la
carte si elle manque.

**Docker / production** : les variables d'environnement `LDAP_*` (mêmes noms que
Sentinelle) **priment sur la base** — le champ correspondant est alors verrouillé
🔒 dans l'interface :

```yaml
      environment:
        LDAP_ENABLED: "true"
        LDAP_SERVER: dc.chatillon.lan        # FQDN/IP, ou ldaps://dc.chatillon.lan
        LDAP_USE_SSL: "true"                 # LDAPS (port 636 par défaut)
        LDAP_VALIDATE_CERT: "true"           # false si CA interne/auto-signée
        LDAP_CA_CERT: ""                     # chemin d'un fichier CA (PEM), optionnel
        LDAP_DOMAIN: chatillon.lan           # bind UPN : utilisateur@domaine
        LDAP_BASE_DN: DC=chatillon,DC=lan
        LDAP_REQUIRED_GROUP: GG-SimCity-Admins   # ⚠️ fortement conseillé (DN ou nom du groupe)
        LDAP_ADMIN_GROUP: GG-SimCity-SuperAdmins # membres = super-administrateurs (optionnel)
        # Compte de service — uniquement pour le bouton « Tester la connexion » :
        LDAP_BIND_USER: svc-simcity@chatillon.lan
        LDAP_BIND_PASSWORD: "secret"
```

- Le **groupe AD requis** restreint la connexion aux membres du groupe
  (**groupes imbriqués inclus**). Sans lui, *tout* compte AD valide accède à
  l'application — à éviter.
- Le **groupe AD des super-administrateurs** (optionnel) pilote les droits
  depuis l'annuaire : appartenance vérifiée à chaque connexion, statut accordé
  ou retiré automatiquement. Le retrait ne concerne que les comptes AD et
  épargne toujours le dernier super-administrateur, pour ne pas se verrouiller
  hors de la configuration. Laissé vide, les droits restent gérés à la main.
- Un compte provisionné depuis l'AD est marqué **🌐 AD** dans Référentiels →
  Comptes Admin : il n'a pas de mot de passe local (le champ est ignoré) et
  s'authentifie toujours via LDAP.

### 2 ter. Envoi d'e-mails (SMTP)

Comme le LDAP, le SMTP se configure dans **Référentiels → Paramètres** (carte
« 📧 Envoi d'e-mails ») et peut être imposé par variables d'environnement —
**mêmes noms que Sentinelle** : `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`
(ou `MAIL_SECURE` : `tls`/`ssl`/`none`), `MAIL_USERNAME`, `MAIL_PASSWORD`,
`MAIL_DEFAULT_SENDER` (+ `MAIL_FROM_NAME`, propre à SimCity). Une variable
définie prime sur la base et verrouille 🔒 le champ dans l'interface.

### 3. Créer les tables

> Étape réservée aux installations manuelles (LAMP / WAMP). **En Docker, il n'y a
> rien à faire** : le schéma s'applique seul au premier chargement d'`index.php`,
> et `install.php` est retiré de l'image (il réinitialise le mot de passe du
> super-administrateur sans authentification).

Accédez à `install.php` depuis votre navigateur :

```
http://localhost/simcity/install.php
```

L'écran doit afficher **"✅ Installation terminée"** avec la liste des tables créées.

### 4. Première connexion

Connectez-vous sur `index.php` avec le compte par défaut :

| Identifiant | Mot de passe |
|---|---|
| `admin` | `admin` |

> ⚠️ **Changez ce mot de passe immédiatement** via Référentiels → Comptes Admin.

### 5. Après installation

- **Renommez le fichier `htaccess` en `.htaccess`** (avec le point initial) à la racine du site.
  Tant qu'il n'a pas ce nom, Apache l'ignore : `config.php`, `install.php` et `reset.php`
  restent accessibles et l'exécution de scripts PHP dans `uploads/` n'est pas bloquée.
  > ℹ️ Ce point n'a d'effet que sous Apache. Sous nginx, reportez ces règles dans la conf du serveur.
- Supprimez ou protégez `install.php` et `reset.php` (accès restreint en production)
- Configurez l'**URL publique du site** dans Paramètres → URL publique pour que les QR codes de signature pointent vers la bonne adresse

---

## Mise en production — checklist

À traiter **avant d'ouvrir l'accès**. Les points 1 à 4 sont des go/no-go de sécurité.

> 💡 `install.php` automatise l'essentiel de cette checklist : il propose de **définir le
> mot de passe administrateur**, de **créer un compte MySQL dédié** (et de basculer
> `config.php` dessus), d'**activer le `.htaccess`**, et affiche un panneau de
> **contrôles d'environnement** (extensions PHP, droits d'écriture, identifiants DB par
> défaut, `APP_DEBUG`). Les points restants ci-dessous sont à faire à la main.

### 🔴 Bloquants

1. **Compte MySQL dédié** — depuis `install.php` (bloc « Créer un compte MySQL dédié »),
   le compte `root` crée un utilisateur limité à `simcity_db` et met à jour `config.php`
   automatiquement. L'application ne se connecte alors plus jamais en `root`.
   > Si `config.php` n'est pas modifiable par le serveur web, `install.php` affiche les
   > identifiants générés à reporter à la main. Pensez ensuite à définir un mot de passe
   > fort pour `root` MySQL (côté serveur) — l'app n'en dépend plus, mais c'est une hygiène de base.
2. **Mot de passe admin** — définissez-le directement depuis `install.php` (bloc
   « Compte administrateur »), ou plus tard via Référentiels → Comptes Admin.
   Ne laissez jamais `admin` / `admin` en production.
3. **Activer le `.htaccess`** — bouton « Activer la protection » dans `install.php`,
   ou renommez manuellement `htaccess` → `.htaccess` (avec le point) à la racine.
   Sans ce fichier, Apache ne protège rien et `config.php` (vos identifiants DB)
   devient téléchargeable en clair. **Point le plus critique.**
4. **Supprimer ou protéger `install.php` et `reset.php`** une fois l'installation terminée.

### 🟠 Fortement recommandés

5. **HTTPS** — deux cas :
   - **Serveur direct** : une fois le certificat TLS en place, passez `FORCE_HTTPS` à `true`
     dans `config.php` (redirige http → https) et décommentez la ligne **HSTS** dans `.htaccess`.
   - **Derrière un reverse proxy** (nginx, Traefik, Cloudflare…) qui termine le TLS :
     laissez `FORCE_HTTPS` à `false` et laissez le proxy gérer la redirection et le HSTS.
     Assurez-vous simplement que le proxy transmet l'en-tête **`X-Forwarded-Proto: https`**
     (l'application le lit pour poser le cookie `Secure` et générer les bons liens).
6. **Fuseau horaire** — vérifiez `APP_TIMEZONE` dans `config.php` (défaut `Europe/Paris`) ;
   il pilote les horodatages des bons, signatures et journaux.
7. **Extension `fileinfo`** — assurez-vous qu'elle est activée dans `php.ini`
   (utilisée pour valider les fichiers uploadés ; absente = tout upload échoue).
8. **Sauvegardes automatiques** — l'application embarque un module complet
   (Référentiels → Paramètres → « Sauvegardes ») : sauvegarde manuelle sur le serveur,
   téléchargement, **restauration**, et suppression. Les fichiers sont conservés en
   `BACKUP_RETENTION` exemplaires glissants (défaut 7) dans `BACKUP_DIR` (`backups/`,
   protégé du web). Le dossier contient des données sensibles (signatures, mot de passe
   SMTP) : il n'est jamais servi directement (le téléchargement passe par l'app authentifiée).

   **Les fichiers téléversés sont archivés avec la base** (`BACKUP_INCLUDE_FILES`, activé
   par défaut) : un `…_uploads.tar.gz` accompagne chaque dump, avec sa propre rétention
   (`BACKUP_FILES_RETENTION`, défaut 3 — ces archives pèsent bien plus lourd) et un
   garde-fou de taille (`BACKUP_FILES_MAX_BYTES`, défaut 500 Mo). Sans cette archive, une
   restauration ne remet que la base : les PDF de factures et les pièces jointes du disque
   restent au présent, d'où des documents orphelins d'un côté et des références cassées de
   l'autre. L'écran **« Cohérence fichiers ↔ base »** (Paramètres → Maintenance) liste les
   deux et permet de supprimer les orphelins après contrôle.

   **Sauvegarde nocturne — choisissez selon votre hébergement :**
   - **Sans cron (recommandé, idéal en conteneur)** : la constante `BACKUP_AUTO` (activée
     par défaut) déclenche une sauvegarde toutes les `BACKUP_AUTO_INTERVAL` secondes (24 h),
     à la première visite passé le délai. Aucune configuration serveur. Limite : ne se
     déclenche que s'il y a du trafic.
   - **Endpoint HTTP + planificateur externe** : définissez la variable d'environnement
     `BACKUP_TOKEN`, puis appelez `https://votre-site/backup.php?token=…` depuis un cron
     de l'hôte, un conteneur planificateur, une GitHub Action, etc.
   - **Cron classique** (serveur non conteneurisé) :
     ```
     0 2 * * * /usr/bin/php /chemin/simcity/backup.php >> /var/log/simcity_backup.log 2>&1
     ```
   - **Depuis l'hôte Docker** : `0 2 * * * docker exec <conteneur> php /var/www/html/backup.php`

### 🟡 À connaître

- Le **mot de passe SMTP** et celui du **compte de service AD** sont stockés en clair dans la table `settings`, donc présents dans chaque sauvegarde SQL. Hasher est impossible (l'authentification SMTP exige le mot de passe en clair) et chiffrer n'apporterait rien en conteneur, où la clé devrait de toute façon venir de l'environnement. **La bonne réponse est de les fournir par `MAIL_PASSWORD` / `LDAP_BIND_PASSWORD`** : la variable prime sur la base et verrouille le champ. Attention, elle ne *supprime* pas la valeur déjà enregistrée : un bouton **« Effacer la valeur stockée »** apparaît alors sous la carte concernée (Paramètres → Envoi d'e-mails, et Sécurité) — les sauvegardes antérieures restent à traiter à la main.
- Les **codes PIN / PUK** des cartes SIM sont également en clair (saisie manuelle, import CSV ou import depuis SFR) : même précaution sur l'accès à la base et aux fichiers `.sql`.
- Les tables `history_logs` et `sim_history` ne sont jamais purgées ; prévoyez un archivage si la volumétrie devient importante.

---

## Utilisation

### Démarrage rapide

1. **Référentiels** — Commencez par créer vos services, opérateurs, forfaits et modèles d'appareils
2. **Agents** — Ajoutez les utilisateurs (employés) avec leur service
3. **Parc Matériel** — Enregistrez vos téléphones/tablettes (IMEI, S/N) — ils arrivent en stock
4. **Lignes & SIM** — Créez les lignes mobiles et associez un agent, un forfait et un téléphone
5. **Bon de remise** — Depuis la fiche agent (bouton 📄) ou l'icône 🖨️ d'une ligne, générez le bon : contenu figé, numéro unique, signature via QR code

### Bons de remise / restitution

- Chaque bon est un **document numéroté et immuable** (`BR-2026-0001`, `BT-2026-0001`…) : son contenu est photographié à la génération et ne change plus jamais, même après le retour du matériel — un bon signé reste imprimable à vie
- Le **bon de remise** se génère depuis la fiche agent ; l'agent le signe depuis son téléphone via QR code ou lien — à la signature, les équipements listés sur le bon passent en service
- Le **bon de restitution** se génère au moment du retour, en cochant les équipements rendus (**restitution partielle possible**) ; à la signature, seuls les équipements du bon retournent en stock
- Si la dotation change (changement de SIM, de téléphone, transfert…), les bons **en attente** sont annulés automatiquement et un nouveau bon doit être généré ; les bons **signés** ne sont jamais modifiés
- La page **Historique des bons** montre chaque cycle remise/restitution (lié structurellement, pas par date) avec impression individuelle
- **Lien de signature** : le bouton 🔗 copie le lien à transmettre par le canal de votre choix (Teams, SMS…) ; en option, configurez le SMTP (Paramètres → Envoi d'e-mails) pour faire apparaître un bouton 📧 d'envoi direct
- **Remise partielle** : le bloc repliable de la fiche agent permet de générer un bon ne couvrant que certains équipements
- **Visa DSI** : chaque compte admin a sa propre signature, gérée dans Référentiels → Comptes Admin (bouton ✍️) ; elle est apposée sur les bons qu'il génère. Chacun dessine la sienne ; un super-admin peut gérer celles des autres comptes
- Le **tableau de bord** liste les bons en attente de signature et alerte quand un lien expire bientôt

### Changement de SIM

Utilisez le bouton 🔄 dans les actions d'une ligne pour enregistrer un changement de carte SIM (perte, casse, migration eSIM…). L'historique des SIM précédentes est conservé.

### Stock et alertes

- Les seuils d'alerte stock sont configurables dans **Paramètres**
- Une alerte apparaît sur le tableau de bord quand le stock SIM ou matériel passe sous le seuil
- Le tableau de bord signale aussi les **lignes facturées sans aucune consommation**, avec leur coût mensuel et annuel (donnée issue du module Facturation)

### Facturation / Contrôle

Le module compare ce que l'opérateur **facture** à ce que contient le référentiel. Il travaille sur les PDF de factures déposés dans l'onglet **Import** — rien n'est récupéré automatiquement chez l'opérateur.

**Une période commune à tout le module.** Un couple *mois de départ / mois d'arrivée* pilote les compteurs, les graphiques, les tops, l'historique, les consommations, le rapprochement et les alertes. Un second filtre restreint à un **compte de facturation**. Le mois d'arrivée sert de mois de référence aux vues mensuelles.

**Onglets :**

- **Tableau de bord** — compteurs de la période, évolution du coût et du nombre de lignes, top 10 multi-critères (coût, SMS, hors-forfait, international, surtaxés, data, appels), et des sections repliables : historique mensuel, répartition par forfait, remise marché, répartition par service, terminaux facturés, **régularisations et avoirs**, activité du parc. Toutes ces sections sont bornées à la période retenue — à une exception près, assumée : les **régularisations et avoirs** n'ont pas de borne haute (ces documents sont émis après coup et datés hors période ; le libellé de la section dit « depuis {mois} »)
- **Factures** — dépôt multi-fichiers, contrôle des doublons par numéro de facture avec compte rendu fichier par fichier, et bouton de **ré-analyse** qui relit les PDF archivés avec la version courante du parseur (utile après une mise à jour, sans re-téléverser)
- **Consommations** — une ligne par numéro, cumulée sur la période, avec recherche, filtres (forfait, service, signalement), tri par colonne et pagination. **Les totaux du pied de tableau portent sur toute la sélection filtrée, pas sur la page affichée**
  - *Clic sur un numéro* → l'historique complet de la ligne, sur toute sa profondeur facturée. Le graphique **grise les mois antérieurs à la prise en main par le titulaire actuel** et la carte d'en-tête donne la date de détention : la consommation d'avant est celle d'un titulaire précédent, et la lire comme celle du titulaire actuel est un contresens. Le tableau mensuel porte une colonne *Titulaire*
  - *Clic sur un nom d'utilisateur* → le même graphique pour **toutes les lignes qu'il détient ou a détenues**, cumulées ; chaque mois ne compte que les lignes détenues à cette date. Suivent le détail de chaque ligne avec sa période de détention et le détail mensuel cumulé
  - Ces périodes sont **reconstruites depuis le journal** (`history_logs`) : le référentiel ne garde que le titulaire courant. Quand une ligne est attribuée sans que le journal l'ait enregistré (fiche antérieure au journal), la date affichée est celle de la création de la fiche et le dit explicitement
- **Alertes** — un tableau unique trié par impact en € HT/mois : facture manquante, ligne sans consommation, hors-forfait, surtaxés, international, remise marché, variations de volume. Les seuils sont réglables (super-admins)
- **Rapprochement des noms** — facture ↔ référentiel, par statut de concordance

**Ce que le parseur lit dans les factures SFR :** le détail par ligne (utilisateur, forfait, appels, SMS/MMS, data, surtaxés, international, hors-forfait), et la **remise marché** écrite en clair dans chaque bloc (`Remise sur abonnement (96,00% de 20,00€ HT)`) — d'où le prix catalogue, le taux appliqué et l'économie réelle du marché. Types reconnus : `9A…` mensuelle, `9T…` terminaux, `9AF…` régularisation, `9AA…` avoir.

Le **libellé du forfait est nettoyé de sa période de prorata** (`Forfait … du 02/06/2026 au 30/06/2026` → `Forfait …`) : une ligne activée ou résiliée en cours de mois est facturée au prorata et la facture accole alors les dates au nom du forfait, ce qui créait autant de faux forfaits que de prorata dans la liste de filtres. Les factures déjà importées sont nettoyées une fois au démarrage.

**Ce que couvrent les compteurs.** Le chiffre « Lignes mobiles facturées » et tout ce qui en découle (graphiques, tops, alertes, consommations) sont construits sur le **détail par ligne** des factures `9A…`. Les `9T…` (terminaux) et les `9AF…` / `9AA…` (régularisations et avoirs) n'ont pas ce détail : elles ont leur propre section repliable, et la carte principale rappelle le montant qu'elle ne comprend pas. Un net de régularisations proche de zéro signifie qu'une régularisation a été compensée par son avoir.

> Le **vidage des données de test** et la **réinitialisation complète** suppriment aussi les factures et leurs PDF archivés : elles décrivent le parc effacé, et le module analyserait sinon des numéros qui n'existent plus.

> 🔒 Les PDF archivés ne sont **pas** servis directement par le serveur web : une facture mensuelle contient la liste nominative complète du parc. Le `.htaccess` bloque `uploads/invoices/` et la diffusion passe par l'application, après contrôle de session. Il en va de même pour les pièces jointes des fiches agents.

> L'import de factures est réservé aux **super-administrateurs** (il verse en base des données nominatives de consommation) ; les onglets d'analyse restent consultables par tous les comptes admin.

### Import depuis SFR (état de parc)

**Référentiels et Paramètres → Maintenance → Import depuis SFR.** Déposez l'export « État de parc » de l'espace client (`EdP_….xlsx`) : l'écran compare **ligne par ligne** l'état réel chez l'opérateur et le référentiel SimCity, et **rien n'est écrit sans validation**.

Écarts détectés : ligne inconnue du référentiel, titulaire différent, forfait, statut, compte de facturation, carte SIM, IMEI différent du matériel associé, terminal utilisé ≠ terminal acheté, IMEI utilisé absent du parc, codes SIM à compléter — plus les lignes actives dans SimCity que l'opérateur ne connaît plus (résiliations à enregistrer).

La mise à jour est ensuite **cochée poste par poste** : comptes de facturation, forfaits, statuts, ICCID (seulement si le champ est vide), codes SIM, création des lignes inconnues (en stock, sans utilisateur). Les titulaires ne sont jamais écrasés automatiquement. L'opération est idempotente.

Deux points à connaître :

- La lecture du `.xlsx` ne dépend d'aucune extension PHP supplémentaire (le ZIP est lu directement, `zlib` suffit) : rien à installer, y compris dans l'image Docker qui n'embarque pas `ZipArchive`.
- **PIN 1/2 et PUK 1/2** sont repris si vous cochez le poste correspondant, et stockés en clair comme ceux saisis à la main — restreignez l'accès à la base et aux sauvegardes SQL en conséquence. Le **RIO** n'est pas dans ce fichier (le portail y renvoie vers un export dédié).

L'import CSV d'inventaire propose le **même écran de comparaison**, en plus du rapprochement des utilisateurs : les deux sources partagent le même moteur et les mêmes règles.

---

## Structure du projet

```
simcity/
├── config.php        # Configuration (DB, sessions, uploads) — ne pas versionner en prod
├── index.php         # Application principale
├── schema.php        # Schéma et migrations de la base de données
├── install.php       # Installation initiale (LAMP/WAMP) — retiré de l'image Docker
├── reset.php         # Réinitialisation complète — à supprimer après usage
├── import_lib.php    # Import CSV en masse (Paramètres → Maintenance)
├── invoice_lib.php   # Factures opérateur : parseur PDF, remise marché, noms
├── sfr_parc_lib.php  # Export « état de parc » SFR : lecteur xlsx + contrôles
├── lib_format.php    # Normalisation des noms / e-mails (partagé)
├── backup.php        # Sauvegarde automatique (cron / tâche planifiée)
├── backup_lib.php    # Fonctions de sauvegarde / restauration (partagées)
├── files_lib.php     # Archive tar.gz des fichiers téléversés + cohérence disque ↔ base
├── ldap_auth.php     # Authentification LDAP / Active Directory (optionnelle)
├── assets/
│   └── logo.svg      # Logo (sidebar, login, favicon) — style Sentinelle
├── vendor/
│   ├── bootstrap-icons.css   # Icônes Bootstrap Icons hors-ligne (thème…)
│   ├── plex.css              # Polices IBM Plex Sans/Mono auto-hébergées (RGPD : aucune requête vers Google Fonts)
│   ├── chart.umd.min.js      # Chart.js auto-hébergé (graphiques stats & facturation, MIT)
│   └── fonts/                # Fichiers woff/woff2 (icônes + polices Plex)
├── js/
│   └── qrcode.min.js # Génération QR codes (client-side)
├── tests/            # Tests unitaires + recette HTTP (hors image Docker)
├── htaccess          # Protections Apache — renommé « .htaccess » au build
├── Dockerfile        # Image PHP 8.3 + Apache (pdo_mysql, ldap, pdftotext)
├── docker-compose.yml
├── uploads/          # Pièces jointes et logo — créé automatiquement, servi
│   └── invoices/     #   par index.php seulement ; PDF de factures archivés
└── backups/          # Sauvegardes .sql — créé automatiquement, protégé du web
```

> ⚠️ `.dockerignore` doit rester aligné sur `.gitignore` : le `COPY .` du Dockerfile
> embarque tout ce qui traîne dans le répertoire de travail. Un dossier de factures
> réelles déposé pour analyse se retrouverait dans l'image, servi par Apache.

---

## Mise à jour (Docker / Portainer)

L'image `simcity:local` est **construite localement** : elle n'existe dans aucun registre.
Un `git pull` seul ne suffit pas (le code PHP est copié dans l'image au build), et le bouton
« Re-pull image » de Portainer échouera toujours avec *pull access denied* — c'est normal.

**1. Sur l'hôte Docker**, récupérer le code et reconstruire l'image :

```bash
git pull && docker build -t simcity:local .
```

**2. Dans Portainer**, recréer les conteneurs avec la nouvelle image, au choix :

- **Update the stack** en laissant « Re-pull image and redeploy » **décoché** ; ou
- **Suppression / recréation du stack** : *Stop this stack* → *Delete this stack*
  (sans supprimer les volumes) → recréer le stack. Les données survivent tant que les
  volumes sont conservés : base MySQL (`dbdata`), `uploads` et `backups`.

> 💾 Par prudence, téléchargez une sauvegarde SQL depuis l'application avant toute mise à jour.

---

## Sauvegarde

**Depuis l'application** (recommandé) : Paramètres → **💾 Sauvegarde de la base de données** →
« Télécharger la sauvegarde (.sql) ». Copiez le fichier sur une clé USB. Réservé aux super-admins.

> ⚠️ Un `.sql` seul ne suffit pas à revenir en arrière : téléchargez aussi l'archive
> **`…_uploads.tar.gz`** de la même ligne (colonne « Fichiers téléversés »). Elle contient les
> PDF de factures, les pièces jointes des fiches agents et le logo — aucun n'est dans le dump SQL.

**En ligne de commande** (alternative) :

```bash
mysqldump -u root -p simcity_db > sauvegarde_simcity_$(date +%Y%m%d).sql
```

Restauration (dans les deux cas) :

```bash
mysql -u root -p simcity_db < simcity_sauvegarde_XXXX.sql
```

> 💡 Sous Windows/Laragon : `mysql`/`mysqldump` se trouvent dans `C:\laragon\bin\mysql\mysql-*\bin\`.
> Pensez à sauvegarder **avant chaque mise à jour** de l'application.

---

## Test de recette

Trois niveaux, tous rejoués par la CI GitHub à chaque push.

**Tests unitaires** — sans base de données ni fichier de données réel :

```bash
php tests/invoice_parse_test.php
```

```bash
php tests/parc_import_test.php
```

```bash
php tests/files_backup_test.php
```

Le premier valide le parseur de factures sur une facture synthétique (`tests/fixtures/`). Le deuxième fabrique lui-même un classeur `.xlsx` et un CSV, et couvre le lecteur ZIP (méthodes « stocké » et « deflate »), la reconnaissance des colonnes, les normalisations (dates, codes SIM, statuts, en-têtes accentués) et la règle de rapprochement des noms commune aux deux contrôles. Le troisième couvre l'archive `tar.gz` des fichiers téléversés (aller-retour à l'octet près, noms longs, refus d'une archive piégée : remontée `../`, chemin absolu, extension exécutable) et le rapprochement disque ↔ base (orphelins, références cassées).

**Test de recette HTTP** — `tests/smoke.sh` rejoue le parcours complet (connexion → attribution → génération du bon → signature → restitution → vérifications). À lancer **uniquement contre une instance de test** :

```bash
BASE_URL=http://localhost/simcity/index.php ADMIN_USER=admin ADMIN_PASS=admin bash tests/smoke.sh
```

---

## Réinitialisation

Pour repartir de zéro (supprime toutes les données) :

1. Accédez à `reset.php`
2. Saisissez `SUPPRIMER` pour confirmer
3. Relancez `install.php` pour recréer les tables

---

## Licence

Projet interne — Tous droits réservés.
