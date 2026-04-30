<?php
// ============================================================
//  SimCity — Schéma de base de données (source unique)
//
//  Ce fichier est la SEULE référence pour :
//    - la création des tables (CREATE TABLE IF NOT EXISTS)
//    - les migrations de colonnes (ALTER TABLE)
//    - les données par défaut (settings, compte admin)
//
//  Inclus par : index.php, install.php, import.php
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
        id            INT AUTO_INCREMENT PRIMARY KEY,
        imei          VARCHAR(50) UNIQUE,
        imei2         VARCHAR(50),
        serial_number VARCHAR(100),
        model_id      INT,
        status        VARCHAR(20) DEFAULT 'Stock',
        agent_id      INT NULL,
        service_id    INT NULL,
        purchase_date DATE NULL,
        notes         TEXT,
        archived      TINYINT(1) DEFAULT 0,
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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

    // ── Comptes administrateurs ──────────────────────────────
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        username   VARCHAR(50) UNIQUE,
        password   VARCHAR(255),
        first_name VARCHAR(100) NULL,
        last_name  VARCHAR(100) NULL,
        email      VARCHAR(150) NULL,
        active     TINYINT(1) NOT NULL DEFAULT 1,
        is_admin   TINYINT(1) NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

    // ─────────────────────────────────────────────────────────
    // DONNÉES PAR DÉFAUT
    // ─────────────────────────────────────────────────────────

    // Compte admin initial (seulement si la table est vide)
    if ($pdo->query("SELECT COUNT(*) FROM users")->fetchColumn() == 0) {
        $pdo->prepare("INSERT INTO users (username, password) VALUES ('admin', ?)")
            ->execute([password_hash('admin', PASSWORD_DEFAULT)]);
    }

    // Paramètres par défaut
    foreach ([
        ['sim_stock_alert',    '5', "Seuil d'alerte Stock SIM (cartes SIM disponibles)"],
        ['device_stock_alert', '3', "Seuil d'alerte Stock Smartphones (matériels disponibles)"],
        ['pdf_logo_path',      '',  "Logo affiché sur les bons de remise PDF"],
        ['site_url',           '',  "URL publique du site (base des QR codes de signature)"],
    ] as [$k, $v, $l]) {
        $pdo->prepare("INSERT IGNORE INTO settings (setting_key, setting_value, label) VALUES (?,?,?)")
            ->execute([$k, $v, $l]);
    }
}

// Appel immédiat si inclus depuis index.php ou import.php
// (install.php appellera la fonction manuellement après l'avoir inclus)
if (!defined('SIMCITY_SCHEMA_MANUAL')) {
    simcity_apply_schema($pdo);
}
