# VLAN et interfaces

## 1. Objectif

Créer un VLAN et l'interface qui l'utilise.

## 2. Prérequis

Interface parente existante ; identifiant `optN` choisi libre.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/vlan.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.vlan test=True`

## 6. Sortie attendue en test=True

Chaque state concerné en `result: None` avec le changement prévu ; aucun state en `False`.

## 7. Vérification

Interfaces > Assignments ; `ifconfig igb1.20` ; second passage sans changement.

## 8. Retour arrière

`pfsense_interface.absent` puis `pfsense_vlan.absent`, dans cet ordre.

## 9. Pièges connus

- **Identité du VLAN.** Changer l'interface parente ou le tag détruit le VLAN : il faut le supprimer puis le recréer.
- **Identifiant de la nouvelle interface.** Sur pfrest, une nouvelle interface doit recevoir l'identifiant demandé ; sinon le state échoue.
- **PPPoE.** Refusé sur pfrest.
