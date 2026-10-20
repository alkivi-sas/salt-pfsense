# Alias

## 1. Objectif

Déclarer les alias host, network et port.

## 2. Prérequis

Recette 06 (ou backend FauxAPI).

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/alias.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.alias test=True`

## 6. Sortie attendue en test=True

Chaque state concerné en `result: None` avec le changement prévu ; aucun state en `False`.

## 7. Vérification

Firewall > Aliases ; second passage sans changement.

## 8. Retour arrière

Remettre les anciennes adresses dans le SLS, ou passer en `pfsense_alias.absent`.

## 9. Pièges connus

- **Type d'alias.** Le type d'un alias existant ne change pas : il faut le supprimer puis le recréer.
- **URL table.** Les alias URL table sont refusés sur pfrest.
