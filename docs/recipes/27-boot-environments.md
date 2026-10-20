# Boot environments

## 1. Objectif

Supprimer les boot environments inactifs d'une ancienne version.

## 2. Prérequis

Système de fichiers ZFS.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/boot_environments.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.boot_environments`

## 6. Sortie attendue en test=True

`module.run` est annoncé sans être exécuté.

## 7. Vérification

`salt '<minion>' pfsense_be.list_be` ne liste plus la version.

## 8. Retour arrière

Aucun : une suppression est définitive.

## 9. Pièges connus

- **Environnement actif.** Il n'est jamais supprimé.
