# 📱 SimCity v5.0

**Gestion du Parc Mobile — DSI**

SimCity est une application web PHP permettant de gérer l'ensemble du parc de téléphonie mobile d'une organisation : lignes, cartes SIM, terminaux, agents et attributions. Elle intègre un système de signature électronique des bons de remise/restitution pour une gestion zéro papier.

## Fonctionnalités

- **Tableau de bord** — Vue d'ensemble avec KPI (lignes actives, terminaux, agents), alertes de stock et recherche globale
- **Gestion des lignes & SIM** — Suivi des lignes mobiles, cartes SIM (physiques et eSIM), codes PIN/PUK, ICCID, historique des changements de SIM
- **Parc matériel & terminaux** — Inventaire des smartphones et appareils avec IMEI, numéro de série, statut (Stock, Attribué, SAV…)
- **Référentiels** — Gestion des agents, services/directions, opérateurs, forfaits, comptes de facturation et modèles d'appareils
- **Signature électronique** — Génération de bons de remise et de restitution avec signature en ligne via lien sécurisé et QR code
- **Retour automatique en stock** — À la signature d'un bon de restitution, le matériel et la ligne sont automatiquement remis en stock
- **Import CSV** — Importation en masse des données (lignes, appareils, agents…)
- **Historique & traçabilité** — Journal complet des actions et modifications sur chaque entité
- **Pièces jointes** — Upload de documents liés aux lignes ou appareils
- **Gestion des utilisateurs** — Authentification sécurisée avec sessions, protection CSRF et comptes administrateurs

## Prérequis

- PHP 7.4+ (avec extension PDO MySQL)
- MySQL / MariaDB
- Un serveur web (Apache, Nginx, Laragon…)

## Installation

1. Clonez le dépôt dans votre répertoire web :
   ```bash
   git clone https://github.com/VOTRE_USERNAME/simcity.git
   ```

2. Modifiez le fichier `config.php` avec vos identifiants de base de données :
   ```php
   define('DB_HOST', 'localhost');
   define('DB_NAME', 'simcity_db');
   define('DB_USER', 'votre_user');
   define('DB_PASS', 'votre_mot_de_passe');
   ```

3. Accédez à `install.php` depuis votre navigateur pour créer la base de données et les tables :
   ```
   http://localhost/telephonie_mobile/install.php
   ```

4. Connectez-vous avec le compte par défaut :
   - **Identifiant :** `admin`
   - **Mot de passe :** `admin`

   ⚠️ **Changez le mot de passe par défaut après la première connexion.**

5. Supprimez ou protégez le fichier `install.php` en production.

## Structure du projet

```
telephonie_mobile/
├── config.php       # Configuration (DB, sessions, sécurité, uploads)
├── index.php        # Application principale (routage, vues, logique métier)
├── schema.php       # Schéma de base de données et migrations
├── install.php      # Script d'installation initiale
├── import.php       # Outil d'importation CSV
├── reset.php        # Réinitialisation de la base de données
├── htaccess         # Règles Apache de protection
├── js/
│   └── qrcode.min.js  # Génération de QR codes côté client
└── uploads/         # Pièces jointes (créé automatiquement)
```

## Sécurité

- Sessions sécurisées (HttpOnly, SameSite Strict)
- Protection CSRF sur les formulaires
- Mots de passe hachés avec `password_hash()`
- Validation et échappement des entrées utilisateur
- Restriction des types de fichiers uploadés (images uniquement, SVG exclus)

## Licence

Projet interne — Tous droits réservés.
