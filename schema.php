<?php
// ============================================================
//  SimCity — Schéma de base de données (source unique)
//
//  Ce fichier est la SEULE référence pour :
//    - la création des tables (CREATE TABLE IF NOT EXISTS)
//    - les migrations de colonnes (ALTER TABLE)
//    - les données par défaut (settings, compte admin)
//
//  Inclus par : index.php, install.php
//  NE PAS inclure directement dans reset.php.
//
//  Prérequis : $pdo doit être connecté et la DB sélectionnée.
// ============================================================

if (!isset($pdo) || !($pdo instanceof PDO)) {
    throw new RuntimeException('schema.php requiert une instance $pdo connectée.');
}

// ─────────────────────────────────────────────────────────────
// FONCTION PRINCIPALE : créer / mettre à jour toutes les tables
// ─────────────────────────────────────────────────────────────
function simcity_apply_schema(PDO $pdo): void
{
    $pdo->exec("SET FOREIGN_KEY_CHECKS = 0");

    // ── Référentiels ─────────────────────────────────────────
    $pdo->exec("CREATE TABLE IF NOT EXISTS models (
        id       INT AUTO_INCREMENT PRIMARY KEY,
        brand    VARCHAR(50),
        name     VARCHAR(100),
        category VARCHAR(50) DEFAULT 'Smartphone'
    ) ENGINE=InnoDB;");

    $pdo->exec("CREATE TABLE IF NOT EXISTS services (
        id        INT AUTO_INCREMENT PRIMARY KEY,
        name      VARCHAR(100),
        direction VARCHAR(100),
        notes     TEXT
    ) ENGINE=InnoDB;");

    $pdo->exec("CREATE TABLE IF NOT EXISTS operators (
        id      INT AUTO_INCREMENT PRIMARY KEY,
        name    VARCHAR(100),
        website VARCHAR(150) NULL,
        notes   TEXT
    ) ENGINE=InnoDB;");

    $pdo->exec("CREATE TABLE IF NOT EXISTS plan_types (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        name        VARCHAR(100),
        data_limit  VARCHAR(50),
        notes       TEXT,
        operator_id INT NULL
    ) ENGINE=InnoDB;");

    $pdo->exec("CREATE TABLE IF NOT EXISTS billing_accounts (
        id             INT AUTO_INCREMENT PRIMARY KEY,
        account_number VARCHAR(50),
        name           VARCHAR(100),
        notes          TEXT
    ) ENGINE=InnoDB;");

    // ── Agents ───────────────────────────────────────────────
    $pdo->exec("CREATE TABLE IF NOT EXISTS agents (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(100),
        last_name  VARCHAR(100),
        email      VARCHAR(150) NULL,
        service_id INT NULL,
        archived   TINYINT(1) DEFAULT 0,
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE SET NULL
    ) ENGINE=InnoDB;");

    // ── Historique ───────────────────────────────────────────
    $pdo->exec("CREATE TABLE IF NOT EXISTS history_logs (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        entity_type VARCHAR(20),
        entity_id   INT,
        agent_id    INT NULL,
        action_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        action_desc TEXT,
        author      VARCHAR(100) NULL
    ) ENGINE=InnoDB;");

    // ── Matériels ────────────────────────────────────────────
    $pdo->exec("CREATE TABLE IF NOT EXISTS devices (
        id              INT AUTO_INCREMENT PRIMARY KEY,
        imei            VARCHAR(50) UNIQUE,
        imei2           VARCHAR(50),
        serial_number   VARCHAR(100),
        inventory_label VARCHAR(100) NULL,
        model_id        INT,
        status          VARCHAR(20) DEFAULT 'Stock',
        agent_id        INT NULL,
        service_id      INT NULL,
        purchase_date   DATE NULL,
        notes           TEXT,
        archived        TINYINT(1) DEFAULT 0,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL
    ) ENGINE=InnoDB;");

    // ── Lignes mobiles ───────────────────────────────────────
    $pdo->exec("CREATE TABLE IF NOT EXISTS mobile_lines (
        id              INT AUTO_INCREMENT PRIMARY KEY,
        phone_number    VARCHAR(20) UNIQUE,
        iccid           VARCHAR(30),
        pin             VARCHAR(10),
        puk             VARCHAR(15),
        agent_id        INT NULL,
        billing_id      INT NULL,
        plan_id         INT NULL,
        service_id      INT NULL,
        device_id       INT NULL,
        activation_date DATE NULL,
        options_details TEXT,
        status          VARCHAR(20) DEFAULT 'Active',
        notes           TEXT,
        archived        TINYINT(1) DEFAULT 0,
        personal_device TINYINT(1) DEFAULT 0,
        sim_vierge      TINYINT(1) DEFAULT 0,
        esim            TINYINT(1) DEFAULT 0,
        eid             VARCHAR(40) NULL,
        activation_code TEXT NULL,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (agent_id)   REFERENCES agents(id)           ON DELETE SET NULL,
        FOREIGN KEY (billing_id) REFERENCES billing_accounts(id) ON DELETE SET NULL,
        FOREIGN KEY (plan_id)    REFERENCES plan_types(id)       ON DELETE SET NULL,
        FOREIGN KEY (device_id)  REFERENCES devices(id)          ON DELETE SET NULL
    ) ENGINE=InnoDB;");

    // ── Pièces jointes ───────────────────────────────────────
    $pdo->exec("CREATE TABLE IF NOT EXISTS attachments (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        entity_type VARCHAR(20),
        entity_id   INT,
        file_name   VARCHAR(255),
        file_path   VARCHAR(255),
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB;");

    // ── Historique changements SIM ───────────────────────────
    $pdo->exec("CREATE TABLE IF NOT EXISTS sim_history (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        line_id    INT NOT NULL,
        old_iccid  VARCHAR(30),
        old_pin    VARCHAR(10),
        old_puk    VARCHAR(15),
        new_iccid  VARCHAR(30),
        new_pin    VARCHAR(10),
        new_puk    VARCHAR(15),
        reason     VARCHAR(150),
        swapped_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        author     VARCHAR(100)
    ) ENGINE=InnoDB;");

    // ── Tokens de signature électronique ─────────────────────
    $pdo->exec("CREATE TABLE IF NOT EXISTS sign_tokens (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        token      VARCHAR(64) UNIQUE,
        agent_id   INT NOT NULL,
        bon_type   VARCHAR(20) DEFAULT 'remise',
        created_by VARCHAR(100),
        dsi_name   VARCHAR(200) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        used_at    DATETIME NULL
    ) ENGINE=InnoDB;");

    // ── Signatures électroniques ─────────────────────────────
    $pdo->exec("CREATE TABLE IF NOT EXISTS signatures (
        id             INT AUTO_INCREMENT PRIMARY KEY,
        token          VARCHAR(64),
        agent_id       INT NOT NULL,
        bon_type       VARCHAR(20) DEFAULT 'remise',
        signature_data MEDIUMTEXT,
        signer_name    VARCHAR(200),
        signed_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip             VARCHAR(45),
        superseded     TINYINT(1) DEFAULT 0
    ) ENGINE=InnoDB;");

    // ── Bons de remise / restitution ─────────────────────────
    // Le bon est un document immuable : son contenu (items) est figé
    // à la génération et ne change jamais après signature.
    $pdo->exec("CREATE TABLE IF NOT EXISTS bons (
        id             INT AUTO_INCREMENT PRIMARY KEY,
        numero         VARCHAR(20) UNIQUE,
        type           VARCHAR(20) NOT NULL DEFAULT 'remise',
        agent_id       INT NOT NULL,
        parent_id      INT NULL,
        items          MEDIUMTEXT NULL,
        status         VARCHAR(20) NOT NULL DEFAULT 'pending',
        cancel_reason  VARCHAR(255) NULL,
        token          VARCHAR(64) UNIQUE,
        expires_at     DATETIME NULL,
        created_by     VARCHAR(100) NULL,
        dsi_name       VARCHAR(200) NULL,
        created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
        signed_at      DATETIME NULL,
        signer_name    VARCHAR(200) NULL,
        signature_data MEDIUMTEXT NULL,
        dsi_signature_data MEDIUMTEXT NULL,
        ip             VARCHAR(45) NULL,
        INDEX idx_bons_agent (agent_id),
        INDEX idx_bons_parent (parent_id)
    ) ENGINE=InnoDB;");

    // ── Demandes de téléphone (attribution / renouvellement) ─
    // La demande reprend le formulaire papier « Demande de téléphone
    // portable » : identité de l'agent, contexte, motivation, puis un
    // circuit de visas. agent_name/service_name sont des snapshots :
    // le formulaire est public, l'agent peut ne pas exister au référentiel.
    $pdo->exec("CREATE TABLE IF NOT EXISTS requests (
        id                  INT AUTO_INCREMENT PRIMARY KEY,
        numero              VARCHAR(20) UNIQUE,
        type                VARCHAR(20) NOT NULL DEFAULT 'attribution',
        agent_id            INT NULL,
        agent_name          VARCHAR(200),
        agent_fonction      VARCHAR(150) NULL,
        service_id          INT NULL,
        service_name        VARCHAR(150) NULL,
        replace_agent       TINYINT(1) NOT NULL DEFAULT 0,
        replaced_agent_name VARCHAR(200) NULL,
        replace_device      TINYINT(1) NOT NULL DEFAULT 0,
        replace_motif       VARCHAR(30) NULL,
        motivation          TEXT,
        requester_email     VARCHAR(150) NULL,
        track_token         VARCHAR(64) UNIQUE,
        status              VARCHAR(20) NOT NULL DEFAULT 'a_qualifier',
        current_step        INT NOT NULL DEFAULT 0,
        refusal_reason      VARCHAR(255) NULL,
        device_id           INT NULL,
        line_id             INT NULL,
        bon_id              INT NULL,
        created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
        launched_at         DATETIME NULL,
        closed_at           DATETIME NULL,
        delivered_at        DATETIME NULL,
        INDEX idx_requests_status (status),
        INDEX idx_requests_agent (agent_id)
    ) ENGINE=InnoDB;");

    // Circuit de validation FIGÉ sur la demande (snapshot, concept Sesame) :
    // les étapes sont copiées du circuit proposé au lancement et ne bougent
    // plus, même si les valideurs par défaut changent ensuite.
    $pdo->exec("CREATE TABLE IF NOT EXISTS request_steps (
        id              INT AUTO_INCREMENT PRIMARY KEY,
        request_id      INT NOT NULL,
        ordre           INT NOT NULL,
        label           VARCHAR(100),
        validator_name  VARCHAR(200) NULL,
        validator_email VARCHAR(150),
        token           VARCHAR(64) UNIQUE,
        expires_at      DATETIME NULL,
        decision        VARCHAR(10) NULL,
        avis            TEXT NULL,
        decided_at      DATETIME NULL,
        ip              VARCHAR(45) NULL,
        notified_at     DATETIME NULL,
        reminded_at     DATETIME NULL,
        INDEX idx_reqsteps_request (request_id),
        INDEX idx_reqsteps_email (validator_email)
    ) ENGINE=InnoDB;");

    // Circuits de validation réutilisables (modèles proposés à la
    // qualification d'une demande) : steps = JSON [{label, name, email}, …].
    // Le circuit reste FIGÉ sur la demande (request_steps) : modifier un
    // modèle ne touche pas les demandes déjà lancées.
    $pdo->exec("CREATE TABLE IF NOT EXISTS request_circuits (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        name       VARCHAR(100) NOT NULL,
        steps      TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB;");

    // ── Tentatives de connexion (anti-brute-force) ───────────
    $pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        username     VARCHAR(100),
        ip           VARCHAR(45),
        attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_login_user (username, attempted_at),
        INDEX idx_login_ip   (ip, attempted_at)
    ) ENGINE=InnoDB;");

    // ── Comptes administrateurs ──────────────────────────────
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id             INT AUTO_INCREMENT PRIMARY KEY,
        username       VARCHAR(50) UNIQUE,
        password       VARCHAR(255),
        first_name     VARCHAR(100) NULL,
        last_name      VARCHAR(100) NULL,
        email          VARCHAR(150) NULL,
        active         TINYINT(1) NOT NULL DEFAULT 1,
        is_admin       TINYINT(1) NOT NULL DEFAULT 0,
        auth_source    VARCHAR(10) NOT NULL DEFAULT 'local',
        signature_data MEDIUMTEXT NULL,
        created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB;");

    // ── Paramètres ───────────────────────────────────────────
    $pdo->exec("CREATE TABLE IF NOT EXISTS settings (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        setting_key   VARCHAR(50) UNIQUE,
        setting_value VARCHAR(255),
        label         VARCHAR(150)
    ) ENGINE=InnoDB;");

    $pdo->exec("SET FOREIGN_KEY_CHECKS = 1");

    // ─────────────────────────────────────────────────────────
    // MIGRATIONS — colonnes ajoutées progressivement
    // Chaque bloc vérifie avant d'agir (idempotent).
    // ─────────────────────────────────────────────────────────

    // plan_types.operator_id
    if (empty($pdo->query("SHOW COLUMNS FROM plan_types LIKE 'operator_id'")->fetchAll())) {
        $pdo->exec("ALTER TABLE plan_types ADD COLUMN operator_id INT NULL AFTER notes");
    }

    // mobile_lines : personal_device, sim_vierge, esim, eid, activation_code
    if (empty($pdo->query("SHOW COLUMNS FROM mobile_lines LIKE 'personal_device'")->fetchAll())) {
        $pdo->exec("ALTER TABLE mobile_lines ADD COLUMN personal_device TINYINT(1) NOT NULL DEFAULT 0 AFTER notes");
    }
    if (empty($pdo->query("SHOW COLUMNS FROM mobile_lines LIKE 'sim_vierge'")->fetchAll())) {
        $pdo->exec("ALTER TABLE mobile_lines ADD COLUMN sim_vierge TINYINT(1) NOT NULL DEFAULT 0 AFTER personal_device");
    }
    if (empty($pdo->query("SHOW COLUMNS FROM mobile_lines LIKE 'esim'")->fetchAll())) {
        $pdo->exec("ALTER TABLE mobile_lines ADD COLUMN esim            TINYINT(1) NOT NULL DEFAULT 0 AFTER sim_vierge");
        $pdo->exec("ALTER TABLE mobile_lines ADD COLUMN eid             VARCHAR(40) NULL              AFTER esim");
        $pdo->exec("ALTER TABLE mobile_lines ADD COLUMN activation_code TEXT NULL                     AFTER eid");
    }

    // devices.inventory_label
    if (empty($pdo->query("SHOW COLUMNS FROM devices LIKE 'inventory_label'")->fetchAll())) {
        $pdo->exec("ALTER TABLE devices ADD COLUMN inventory_label VARCHAR(100) NULL AFTER serial_number");
    }

    // sign_tokens.dsi_name
    if (empty($pdo->query("SHOW COLUMNS FROM sign_tokens LIKE 'dsi_name'")->fetchAll())) {
        $pdo->exec("ALTER TABLE sign_tokens ADD COLUMN dsi_name VARCHAR(200) NULL AFTER created_by");
    }

    // signatures.superseded
    if (empty($pdo->query("SHOW COLUMNS FROM signatures LIKE 'superseded'")->fetchAll())) {
        $pdo->exec("ALTER TABLE signatures ADD COLUMN superseded TINYINT(1) DEFAULT 0 AFTER ip");
    }

    // users : first_name, last_name, email, active
    if (empty($pdo->query("SHOW COLUMNS FROM users LIKE 'first_name'")->fetchAll())) {
        $pdo->exec("ALTER TABLE users ADD COLUMN first_name VARCHAR(100) NULL AFTER password");
        $pdo->exec("ALTER TABLE users ADD COLUMN last_name  VARCHAR(100) NULL AFTER first_name");
        $pdo->exec("ALTER TABLE users ADD COLUMN email      VARCHAR(150) NULL AFTER last_name");
    }
    if (empty($pdo->query("SHOW COLUMNS FROM users LIKE 'active'")->fetchAll())) {
        $pdo->exec("ALTER TABLE users ADD COLUMN active TINYINT(1) NOT NULL DEFAULT 1 AFTER email");
    }
    if (empty($pdo->query("SHOW COLUMNS FROM users LIKE 'is_admin'")->fetchAll())) {
        $pdo->exec("ALTER TABLE users ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0 AFTER active");
        // Le compte admin initial devient super-admin
        $pdo->exec("UPDATE users SET is_admin=1 WHERE username='admin'");
    }

    // users.auth_source (provenance du compte : 'local' ou 'ldap')
    if (empty($pdo->query("SHOW COLUMNS FROM users LIKE 'auth_source'")->fetchAll())) {
        $pdo->exec("ALTER TABLE users ADD COLUMN auth_source VARCHAR(10) NOT NULL DEFAULT 'local' AFTER is_admin");
    }

    // users.signature_data (visa DSI apposé sur les bons)
    if (empty($pdo->query("SHOW COLUMNS FROM users LIKE 'signature_data'")->fetchAll())) {
        $pdo->exec("ALTER TABLE users ADD COLUMN signature_data MEDIUMTEXT NULL AFTER is_admin");
    }

    // bons.dsi_signature_data (copie du visa au moment de la génération — immuable)
    if (empty($pdo->query("SHOW COLUMNS FROM bons LIKE 'dsi_signature_data'")->fetchAll())) {
        $pdo->exec("ALTER TABLE bons ADD COLUMN dsi_signature_data MEDIUMTEXT NULL AFTER signature_data");
    }

    // settings.setting_value passe en TEXT : les textes paramétrables du
    // formulaire public de demande (intro, nota…) dépassent 255 caractères.
    $svCol = $pdo->query("SHOW COLUMNS FROM settings LIKE 'setting_value'")->fetch();
    if ($svCol && stripos($svCol['Type'], 'varchar') !== false) {
        $pdo->exec("ALTER TABLE settings MODIFY setting_value TEXT");
    }

    // requests.agent_email : e-mail du bénéficiaire (pré-rempli depuis l'AD).
    // Sert au rapprochement fiable avec le référentiel ; n'est PAS une cible de
    // notification (le circuit part sur l'adresse de base paramétrée).
    if (empty($pdo->query("SHOW COLUMNS FROM requests LIKE 'agent_email'")->fetchAll())) {
        $pdo->exec("ALTER TABLE requests ADD COLUMN agent_email VARCHAR(150) NULL AFTER agent_fonction");
    }

    // requests.requester_name : identité du demandeur (affichée sur la fiche
    // admin à côté de son e-mail).
    if (empty($pdo->query("SHOW COLUMNS FROM requests LIKE 'requester_name'")->fetchAll())) {
        $pdo->exec("ALTER TABLE requests ADD COLUMN requester_name VARCHAR(200) NULL AFTER motivation");
    }

    // requests.replaced_agent_email : e-mail de l'agent remplacé (pré-rempli
    // depuis l'AD) — rapprochement fiable avec le référentiel pour afficher
    // sa dotation actuelle à la DSI.
    if (empty($pdo->query("SHOW COLUMNS FROM requests LIKE 'replaced_agent_email'")->fetchAll())) {
        $pdo->exec("ALTER TABLE requests ADD COLUMN replaced_agent_email VARCHAR(150) NULL AFTER replaced_agent_name");
    }

    // agents.fonction : intitulé de poste de la fiche utilisateur (pré-rempli
    // depuis l'AD à la création).
    if (empty($pdo->query("SHOW COLUMNS FROM agents LIKE 'fonction'")->fetchAll())) {
        $pdo->exec("ALTER TABLE agents ADD COLUMN fonction VARCHAR(150) NULL AFTER last_name");
    }

    // services : valideurs du circuit de demande (chef de service, DGA de secteur)
    if (empty($pdo->query("SHOW COLUMNS FROM services LIKE 'chef_name'")->fetchAll())) {
        $pdo->exec("ALTER TABLE services ADD COLUMN chef_name  VARCHAR(200) NULL AFTER direction");
        $pdo->exec("ALTER TABLE services ADD COLUMN chef_email VARCHAR(150) NULL AFTER chef_name");
        $pdo->exec("ALTER TABLE services ADD COLUMN dga_name   VARCHAR(200) NULL AFTER chef_email");
        $pdo->exec("ALTER TABLE services ADD COLUMN dga_email  VARCHAR(150) NULL AFTER dga_name");
    }

    // ─────────────────────────────────────────────────────────
    // MIGRATION UNIQUE : sign_tokens / signatures → bons
    // Reprend l'historique de l'ancien système. Les tokens copiés
    // restent valides : les QR codes déjà imprimés fonctionnent.
    // Les anciennes tables sont conservées (archives) mais plus utilisées.
    // ─────────────────────────────────────────────────────────
    $bonsCount = (int)$pdo->query("SELECT COUNT(*) FROM bons")->fetchColumn();
    $tokCount  = (int)$pdo->query("SELECT COUNT(*) FROM sign_tokens")->fetchColumn();
    if ($bonsCount === 0 && $tokCount > 0) {
        $pdo->beginTransaction();
        try {
            // remise avant restitution à date égale (créés ensemble dans l'ancien système)
            $tokens = $pdo->query("SELECT * FROM sign_tokens ORDER BY agent_id, created_at, bon_type")->fetchAll();
            $ins = $pdo->prepare("INSERT INTO bons (numero, type, agent_id, parent_id, items, status, cancel_reason, token, expires_at, created_by, dsi_name, created_at, signed_at, signer_name, signature_data, ip)
                                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
            $sigSt = $pdo->prepare("SELECT * FROM signatures WHERE token=? ORDER BY superseded ASC, signed_at DESC LIMIT 1");
            $seq = []; $lastRemiseBon = [];
            foreach ($tokens as $t) {
                $sigSt->execute([$t['token']]);
                $sig = $sigSt->fetch();
                $isExpired = $t['expires_at'] && strtotime($t['expires_at']) < time();
                if ($sig && empty($sig['superseded'])) {
                    $status = 'signed'; $reason = null;
                } elseif ($sig) {
                    $status = 'cancelled'; $reason = 'Remplacé (migration ancien système)';
                } elseif ($isExpired) {
                    $status = 'cancelled'; $reason = 'Expiré (migration ancien système)';
                } else {
                    $status = 'pending'; $reason = null;
                }
                $year   = substr($t['created_at'], 0, 4);
                $prefix = ($t['bon_type'] === 'remise' ? 'BR' : 'BT') . "-$year-";
                $seq[$prefix] = ($seq[$prefix] ?? 0) + 1;
                $numero = $prefix . str_pad((string)$seq[$prefix], 4, '0', STR_PAD_LEFT);
                $parentId = ($t['bon_type'] === 'restitution') ? ($lastRemiseBon[$t['agent_id']] ?? null) : null;
                $ins->execute([
                    $numero, $t['bon_type'], $t['agent_id'], $parentId, null, $status, $reason,
                    $t['token'], $t['expires_at'], $t['created_by'], $t['dsi_name'] ?? null, $t['created_at'],
                    $sig['signed_at'] ?? null, $sig['signer_name'] ?? null, $sig['signature_data'] ?? null, $sig['ip'] ?? null,
                ]);
                if ($t['bon_type'] === 'remise') $lastRemiseBon[$t['agent_id']] = (int)$pdo->lastInsertId();
            }
            $pdo->commit();
        } catch (Exception $e) {
            $pdo->rollBack();
            throw $e;
        }
    }

    // ─────────────────────────────────────────────────────────
    // DONNÉES PAR DÉFAUT
    // ─────────────────────────────────────────────────────────

    // Compte admin initial (seulement si la table est vide) — super-admin d'office
    if ($pdo->query("SELECT COUNT(*) FROM users")->fetchColumn() == 0) {
        $pdo->prepare("INSERT INTO users (username, password, is_admin) VALUES ('admin', ?, 1)")
            ->execute([password_hash('admin', PASSWORD_DEFAULT)]);
    }

    // Garde-fou : s'il n'existe aucun super-admin (bug des installations neuves
    // antérieures), promouvoir le compte 'admin' pour ne pas verrouiller
    // la zone dangereuse et la sauvegarde.
    if ($pdo->query("SELECT COUNT(*) FROM users WHERE is_admin=1")->fetchColumn() == 0) {
        $pdo->exec("UPDATE users SET is_admin=1 WHERE username='admin'");
    }

    // Paramètres par défaut
    foreach ([
        ['sim_stock_alert',    '5', "Seuil d'alerte Stock SIM (cartes SIM disponibles)"],
        ['device_stock_alert', '3', "Seuil d'alerte Stock Smartphones (matériels disponibles)"],
        ['pdf_logo_path',      '',  "Logo affiché sur les bons de remise PDF"],
        ['site_url',           '',  "URL publique du site (base des QR codes de signature)"],
        ['smtp_host',          '',    "Serveur SMTP (envoi des liens de signature)"],
        ['smtp_port',          '587', "Port SMTP"],
        ['smtp_secure',        'tls', "Chiffrement SMTP (tls, ssl ou none)"],
        ['smtp_user',          '',    "Identifiant SMTP"],
        ['smtp_pass',          '',    "Mot de passe SMTP"],
        ['smtp_from',          '',    "Adresse e-mail expéditrice"],
        ['smtp_from_name',     'SimCity — DSI', "Nom de l'expéditeur"],
        ['last_auto_backup',   '',    "Horodatage de la dernière sauvegarde automatique"],
        // Demandes de téléphone (formulaire public + circuit de validation)
        ['request_notify_email',        '',  "Adresse notifiée à chaque nouvelle demande de téléphone"],
        ['request_reminder_days',       '5', "Relance automatique des valideurs après N jours sans réponse"],
        ['request_dsi_name',            '',  "Visa D.S.I. — nom du valideur par défaut"],
        ['request_dsi_email',           '',  "Visa D.S.I. — e-mail du valideur par défaut"],
        ['request_dgs_name',            '',  "Visa D.G.S. — nom du valideur par défaut"],
        ['request_dgs_email',           '',  "Visa D.G.S. — e-mail du valideur par défaut"],
        ['request_last_reminder_check', '',  "Horodatage du dernier contrôle de relances des demandes"],
        // Textes du formulaire public de demande (modifiables dans Paramètres)
        ['request_form_title',            'Demande de téléphone portable', "Formulaire public — titre"],
        ['request_form_intro',            "Attribution ou renouvellement — la demande suivra le circuit de validation habituel (Direction du service, D.S.I., D.G.A., D.G.S.).", "Formulaire public — texte d'introduction"],
        ['request_form_motivation_label', "Motivation du besoin (astreinte, types de déplacement, fréquence d'utilisation…)", "Formulaire public — libellé du champ motivation"],
        ['request_form_motifs',           "Panne\nCasse\nPerte\nVol\nObsolescence", "Formulaire public — motifs de remplacement (un par ligne)"],
        ['request_form_nota',             "Nous vous rappelons que l'attribution d'un téléphone portable relève des avantages en nature susceptibles de demande de justificatif par la Chambre Régionale des Comptes. Il vous appartient de bien évaluer le besoin et d'en contrôler l'usage.", "Formulaire public — nota affiché sous le formulaire"],
        ['request_form_success',          "Votre demande a bien été transmise à la DSI. Un accusé de réception vous a été envoyé par e-mail ; vous pourrez suivre son avancement via le lien ci-dessous.", "Formulaire public — message de confirmation"],
        // Authentification LDAP / Active Directory (modifiable dans Paramètres ;
        // les variables d'environnement LDAP_* priment si définies — Docker)
        ['ldap_enabled',          '0', "Authentification Active Directory activée (0/1)"],
        ['ldap_server',           '',  "Serveur LDAP (FQDN, ldap:// ou ldaps://)"],
        ['ldap_port',             '0', "Port LDAP (0 = auto : 389, ou 636 en LDAPS)"],
        ['ldap_use_ssl',          '1', "LDAPS — connexion chiffrée TLS (0/1)"],
        ['ldap_validate_cert',    '1', "Validation du certificat serveur en LDAPS (0/1)"],
        ['ldap_ca_cert',          '',  "Chemin d'un fichier CA (PEM), optionnel"],
        ['ldap_domain',           '',  "Domaine AD — bind UPN utilisateur@domaine"],
        ['ldap_base_dn',          '',  "Base DN (ex : DC=exemple,DC=lan)"],
        ['ldap_required_group',   '',  "Groupe AD requis (DN ou nom) — fortement conseillé"],
        ['ldap_bind_user',        '',  "Compte de service (bouton Tester la connexion)"],
        ['ldap_bind_password',    '',  "Mot de passe du compte de service"],
    ] as [$k, $v, $l]) {
        $pdo->prepare("INSERT IGNORE INTO settings (setting_key, setting_value, label) VALUES (?,?,?)")
            ->execute([$k, $v, $l]);
    }

    // ── Retrait du gabarit DN de bind (remplacé par le seul bind UPN) ──
    // La valeur devait être supprimée et pas seulement masquée : conservée en
    // base, elle continuerait de primer sur l'UPN et de casser le bind.
    $pdo->exec("DELETE FROM settings WHERE setting_key='ldap_user_dn_template'");

    // ── Normalisation unique des noms / e-mails existants ────────
    // Nom en MAJUSCULES, prénom en Casse-Titre (composés gérés), e-mail en
    // minuscules. Exécutée une seule fois (verrou en base) ; les écritures
    // ultérieures sont normalisées à la volée par index.php / import_lib.php.
    require_once __DIR__ . '/lib_format.php';
    $done = $pdo->query("SELECT setting_value FROM settings WHERE setting_key='names_normalized_v1'")->fetchColumn();
    if ($done === false || $done === '' || $done === '0') {
        foreach (['agents', 'users'] as $tbl) {
            $rows = $pdo->query("SELECT id, first_name, last_name, email FROM $tbl")->fetchAll();
            $upd = $pdo->prepare("UPDATE $tbl SET first_name=?, last_name=?, email=? WHERE id=?");
            foreach ($rows as $r) {
                $fn = fmtFirstName($r['first_name']); $ln = fmtLastName($r['last_name']); $em = fmtEmail($r['email']);
                if ($fn !== $r['first_name'] || $ln !== $r['last_name'] || $em !== $r['email']) {
                    $upd->execute([$fn, $ln, $em, $r['id']]);
                }
            }
        }
        $pdo->prepare("INSERT INTO settings (setting_key, setting_value, label) VALUES ('names_normalized_v1','1','Normalisation initiale des noms/e-mails effectuée')
                       ON DUPLICATE KEY UPDATE setting_value='1'")->execute();
    }
}

// Appel immédiat si inclus depuis index.php
// (install.php appellera la fonction manuellement après l'avoir inclus)
if (!defined('SIMCITY_SCHEMA_MANUAL')) {
    simcity_apply_schema($pdo);
}
