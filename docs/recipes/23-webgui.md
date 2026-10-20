# WebGUI et noms d'hôte alternatifs

## 1. Objectif

Ajouter un nom d'hôte alternatif au WebGUI et régler une option.

## 2. Prérequis

Aucun prérequis spécifique.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/webgui.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.webgui test=True`

## 6. Sortie attendue en test=True

Chaque state concerné en `result: None` avec le changement prévu ; aucun state en `False`.

## 7. Vérification

System > Advanced > Admin Access.

## 8. Retour arrière

`pfsense_althostname.absent` ; remettre `value: False`.

## 9. Pièges connus

- **Coupure de l'API.** Changer `protocol`, `port` ou `sslcertref` redémarre le WebGUI, et donc l'API.
- **Ordre.** Placer ces changements en fin de highstate.
