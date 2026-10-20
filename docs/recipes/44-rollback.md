# Retour arrière

## 1. Objectif

Revenir au backend FauxAPI, ou à une configuration antérieure.

## 2. Prérequis

FauxAPI toujours installé (jusqu'au décommissionnement).

## 3. Pillar

`pfsense:api_backend: fauxapi`.

## 4. SLS

Aucun SLS nouveau.

## 5. Commande

`salt '<minion>' saltutil.refresh_pillar`, puis `state.highstate test=True`

## 6. Sortie attendue en test=True

Aucun changement attendu : les deux backends visent la même configuration.

## 7. Vérification

`config.get pfsense:api_backend` renvoie `fauxapi`.

## 8. Retour arrière

Pour annuler une écriture : Diagnostics > Backup & Restore > Config History, restaurer la révision précédente.

## 9. Pièges connus

- **Historique de configuration.** pfrest n'a pas d'endpoint de restauration : la restauration se fait dans le WebGUI.
