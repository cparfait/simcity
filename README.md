# 📱 SimCity v1.0
**Gestion du Parc Mobile — DSI**

SimCity est une application web PHP de gestion de parc téléphonique : lignes mobiles, cartes SIM, terminaux, agents et attributions, avec signature électronique des bons de remise/restitution.

---

## Prérequis

- PHP 7.4+ avec extension PDO MySQL
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

Éditez `config.php` avec vos identifiants MySQL :

```php
define('DB_HOST', 'localhost');      // Hôte MySQL (ou nom du conteneur Docker)
define('DB_NAME', 'simcity_db');     // Nom de la base (créée automatiquement)
define('DB_USER', 'root');
define('DB_PASS', '');               // Vide par défaut sous Laragon
```

### 3. Créer les tables

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

5. **Forcer HTTPS** — une fois le certificat TLS en place, passez `FORCE_HTTPS` à `true`
   dans `config.php` (redirige http → https) et décommentez la ligne **HSTS** dans `.htaccess`.
6. **Fuseau horaire** — vérifiez `APP_TIMEZONE` dans `config.php` (défaut `Europe/Paris`) ;
   il pilote les horodatages des bons, signatures et journaux.
7. **Extension `fileinfo`** — assurez-vous qu'elle est activée dans `php.ini`
   (utilisée pour valider les fichiers uploadés ; absente = tout upload échoue).
8. **Sauvegardes** — planifiez un `mysqldump` régulier en plus de l'export SQL manuel
   (Paramètres → Sauvegarde). Le contenu inclut les signatures électroniques :
   stockez les sauvegardes dans un emplacement à accès restreint.

### 🟡 À connaître

- Le **mot de passe SMTP** est stocké en clair dans la table `settings` (exposé via l'export SQL) — restreignez l'accès à la base et aux sauvegardes.
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

---

## Structure du projet

```
simcity/
├── config.php        # Configuration (DB, sessions, uploads) — ne pas versionner en prod
├── index.php         # Application principale
├── schema.php        # Schéma et migrations de la base de données
├── install.php       # Installation initiale — à supprimer après usage
├── reset.php         # Réinitialisation complète — à supprimer après usage
├── import.php        # Import CSV en masse
├── js/
│   └── qrcode.min.js # Génération QR codes (client-side)
└── uploads/          # Pièces jointes — créé automatiquement
```

---

## Sauvegarde

**Depuis l'application** (recommandé) : Paramètres → **💾 Sauvegarde de la base de données** →
« Télécharger la sauvegarde (.sql) ». Copiez le fichier sur une clé USB. Réservé aux super-admins.

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

Le script `tests/smoke.sh` rejoue le parcours complet en HTTP (connexion → attribution →
génération du bon → signature → restitution → vérifications). À lancer **uniquement contre
une instance de test** :

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
