# 📱 SimCity v5.0
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

- Supprimez ou protégez `install.php` et `reset.php` (accès restreint en production)
- Configurez l'**URL publique du site** dans Paramètres → URL publique pour que les QR codes de signature pointent vers la bonne adresse

---

## Utilisation

### Démarrage rapide

1. **Référentiels** — Commencez par créer vos services, opérateurs, forfaits et modèles d'appareils
2. **Agents** — Ajoutez les utilisateurs (employés) avec leur service
3. **Parc Matériel** — Enregistrez vos téléphones/tablettes (IMEI, S/N) — ils arrivent en stock
4. **Lignes & SIM** — Créez les lignes mobiles et associez un agent, un forfait et un téléphone
5. **Bon de remise** — Cliquez sur 🖨️ dans les actions d'une ligne pour générer le bon, l'imprimer et le faire signer via QR code

### Signature électronique

- Le bon de remise contient deux QR codes : un pour la **remise** (attribution), un pour la **restitution** (retour)
- L'agent scanne le QR code et signe depuis son téléphone
- À la signature du bon de restitution, le matériel et la ligne sont **automatiquement remis en stock**

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

## Réinitialisation

Pour repartir de zéro (supprime toutes les données) :

1. Accédez à `reset.php`
2. Saisissez `SUPPRIMER` pour confirmer
3. Relancez `install.php` pour recréer les tables

---

## Licence

Projet interne — Tous droits réservés.
