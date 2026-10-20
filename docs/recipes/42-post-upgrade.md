# Après une mise à jour de pfSense

## 1. Objectif

Retrouver l'API après une mise à jour de pfSense, qui supprime les paquets non officiels.

## 2. Prérequis

La nouvelle base pfSense est supportée par la version épinglée.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/restapi.sls`, en tête du highstate.

## 5. Commande

`salt '<minion>' state.highstate`

## 6. Sortie attendue en test=True

`pfrest-installed` annonce la réinstallation.

## 7. Vérification

`salt '<minion>' pfsense_restapi.status` répond ; la clé a été restaurée (`backup.json`) ou réécrite par `bootstrapped`.

## 8. Retour arrière

Recette 44 si la nouvelle base n'est pas supportée.

## 9. Pièges connus

- **Base non supportée.** `installed` échoue explicitement, plutôt que d'installer une version incompatible.
