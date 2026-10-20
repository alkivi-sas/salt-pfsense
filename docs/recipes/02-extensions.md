# Distribuer les extensions

## 1. Objectif

Rendre les modules, states, utils et grains de ce dépôt disponibles sur les minions.

## 2. Prérequis

Ce dépôt accessible au master (submodule du dépôt de states, `file_roots` ou `gitfs`).

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`_modules/`, `_states/`, `_utils/` et `_grains/` sont placés à la racine d'un `file_roots`, ou liés depuis le dépôt de states par des liens symboliques. Aucun SLS n'est nécessaire.

## 5. Commande

`salt '<minion>' saltutil.sync_all`

## 6. Sortie attendue en test=True

Sans objet : `sync_all` n'a pas de mode test.

## 7. Vérification

`salt '<minion>' saltutil.list_extmods` liste `pfsense_restapi`, `pfsense_apply` et `pfrest`.

## 8. Retour arrière

Revenir au commit précédent du dépôt, puis relancer `saltutil.sync_all`.

## 9. Pièges connus

- **Nouveaux utils.** Ils ne sont visibles qu'après `sync_utils` ou `sync_all`.
- **Cache du minion.** Le minion garde les anciennes extensions en cache tant que la synchronisation n'a pas été relancée.
