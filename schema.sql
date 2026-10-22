-- =============================================================
--  DETECTIVE : schéma de base de données (à importer une seule fois)
--
--  Installation :
--    mysql -u root -p < schema.sql
--  Puis, de préférence, un compte dédié (pas root) :
--    CREATE USER 'detective_app'@'localhost' IDENTIFIED BY 'change-moi';
--    GRANT SELECT,INSERT,UPDATE,DELETE ON detective.* TO 'detective_app'@'localhost';
--  Renseigne ensuite ces identifiants dans config.php (voir config.sample.php).
-- =============================================================

CREATE DATABASE IF NOT EXISTS detective CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE detective;

-- --- missions / projets ---------------------------------------
CREATE TABLE IF NOT EXISTS projects (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(160) NOT NULL,
  target     VARCHAR(255) DEFAULT NULL,
  note       TEXT DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --- nœuds : entités (personnes, domaines, IP, documents...) --
CREATE TABLE IF NOT EXISTS nodes (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  project_id INT UNSIGNED NOT NULL DEFAULT 1,
  type       VARCHAR(40)  NOT NULL DEFAULT 'autre',
  label      VARCHAR(120) NOT NULL,
  value      VARCHAR(500) DEFAULT NULL,
  importance ENUM('critique','eleve','normal','faible','lacune','exclu') NOT NULL DEFAULT 'normal',
  statut     ENUM('a_verifier','en_cours','confirme','vuln','rien','ecarte') NOT NULL DEFAULT 'a_verifier',
  confidence ENUM('h','m','l') NOT NULL DEFAULT 'm',
  source     VARCHAR(500) DEFAULT NULL,
  image      VARCHAR(500) DEFAULT NULL,
  file_url   VARCHAR(500) DEFAULT NULL,
  file_name  VARCHAR(255) DEFAULT NULL,
  note       TEXT DEFAULT NULL,
  x          FLOAT DEFAULT NULL,
  y          FLOAT DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_nodes_project (project_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --- liens : relations entre nœuds -----------------------------
CREATE TABLE IF NOT EXISTS links (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  project_id INT UNSIGNED NOT NULL DEFAULT 1,
  source     INT UNSIGNED NOT NULL,
  target     INT UNSIGNED NOT NULL,
  label      VARCHAR(120) DEFAULT NULL,
  confidence ENUM('h','m','l') NOT NULL DEFAULT 'm',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_links_project (project_id),
  INDEX (source), INDEX (target)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --- mission de démarrage (vide, purement structurelle) --------
INSERT INTO projects (id, name, target, note)
SELECT 1, 'Mission 1', NULL, NULL
WHERE NOT EXISTS (SELECT 1 FROM projects WHERE id = 1);
