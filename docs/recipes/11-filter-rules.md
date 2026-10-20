# Règles de filtrage

## 1. Objectif

Déclarer des règles par interface ou flottantes, à une position donnée.

## 2. Prérequis

Alias utilisés déclarés avant (recette 10).

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/filter_rule.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.filter_rule test=True`

## 6. Sortie attendue en test=True

Chaque state concerné en `result: None` avec le changement prévu ; aucun state en `False`.

## 7. Vérification

Firewall > Rules : la règle est à la position `index` du groupe de son interface ; second passage sans changement.

## 8. Retour arrière

`pfsense_filter_rule.absent` (supprime toutes les règles de même description sur l'interface).

## 9. Pièges connus

- **Identité de la règle.** La description et l'interface identifient la règle : deux règles de même description sur la même interface sont considérées comme une seule.
- **Mise à jour.** Une règle existante n'est pas modifiée par `present` : la supprimer puis la recréer.
- **`tracker`.** Il est attribué par pfSense.
