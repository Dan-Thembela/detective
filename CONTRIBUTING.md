# Contribuer à Detective

Merci de l'intérêt porté à ce projet. Quelques repères avant de proposer une modification.

## Philosophie du projet

Detective tient volontairement en un seul fichier applicatif (`index.php`), sans framework ni dépendance externe. C'est un choix assumé : rester simple à lire intégralement, à auditer et à déployer sur un hébergement basique (type XAMPP). Les contributions qui fragmentent cette structure (multiplier les fichiers, ajouter des dépendances lourdes) ne seront en général pas retenues, sauf si la fonctionnalité l'exige vraiment. Dans ce cas, ouvrez d'abord une issue pour en discuter.

## Signaler un bug

Ouvrez une issue avec :
- ce que vous attendiez,
- ce qui s'est réellement passé,
- les étapes pour reproduire,
- votre environnement (version de PHP, de MySQL/MariaDB, navigateur).

Pour une **faille de sécurité**, ne passez pas par une issue publique. Voir [SECURITY.md](SECURITY.md).

## Proposer une modification

1. Forkez le dépôt et créez une branche depuis `main`.
2. Gardez les changements ciblés : une pull request = un sujet.
3. Conservez le style existant (PHP/JS compact, pas d'indentation à 4 espaces généralisée, pas de dépendance ajoutée).
4. Vérifiez au minimum `php -l index.php` avant de proposer la modification, et testez manuellement le ou les parcours utilisateurs concernés.
5. Décrivez dans la pull request ce qui change et pourquoi.

## Idées de fonctionnalités

Ouvrez une issue pour en discuter avant de développer quelque chose de conséquent. Cela évite du travail qui ne correspondrait pas à la direction du projet.
