# Politique de sécurité

## Signaler une vulnérabilité

Si vous découvrez une faille de sécurité dans Detective, merci de **ne pas** ouvrir d'issue publique. Contactez directement le mainteneur du dépôt (voir le profil GitHub associé) en décrivant :

- la nature de la vulnérabilité et son impact potentiel,
- les étapes pour la reproduire,
- si possible, une suggestion de correctif.

Un délai raisonnable sera pris pour analyser et corriger le problème avant toute divulgation publique.

## Périmètre

Ce projet est un outil auto-hébergé : vous contrôlez votre propre déploiement et votre propre base de données. Relèvent de cette politique les failles dans le code de Detective lui-même (ex. contournement des contrôles d'upload, injection, faille d'authentification applicative). Ne relèvent pas de cette politique la configuration de votre serveur, de votre base de données ou de votre réseau.

## Bonnes pratiques de déploiement

- Ne jamais versionner `config.php` (voir `.gitignore`).
- Utiliser un compte MySQL dédié, avec les droits strictement nécessaires (`SELECT, INSERT, UPDATE, DELETE`), jamais `root`.
- Déployer derrière HTTPS si l'instance est accessible au-delà de `localhost`.
- Vérifier que le serveur web empêche l'exécution de scripts dans `uploads/` (le `.htaccess` fourni couvre Apache : voir le README pour les autres serveurs).
- Ne jamais exposer une instance contenant des données réelles de mission sur un réseau non maîtrisé sans contrôle d'accès additionnel (Detective ne fournit pas d'authentification applicative à ce stade).
