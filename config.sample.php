<?php
/**
 * Copie ce fichier en config.php (dans le même dossier qu'index.php) et
 * renseigne tes propres identifiants. config.php ne doit JAMAIS être
 * versionné (voir .gitignore). Il contient des secrets.
 *
 * Alternative sans fichier : définir les variables d'environnement
 *   DETECTIVE_DB_HOST / DETECTIVE_DB_NAME / DETECTIVE_DB_USER / DETECTIVE_DB_PASS
 * Elles sont utilisées automatiquement si config.php est absent.
 */
return [
  'db_host' => '127.0.0.1',
  'db_name' => 'detective',
  'db_user' => 'detective_app',
  'db_pass' => 'change-moi',
];
