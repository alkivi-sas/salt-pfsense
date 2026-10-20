# Monter la version de pfrest

## 1. Objectif

Passer le parc à une nouvelle version épinglée de pfrest.

## 2. Prérequis

Nouvelle version testée hors production (contrat régénéré et tests verts, voir `docs/migration/restapi.md`).

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

Aucun SLS nouveau : la version épinglée vit dans `_utils/pfrest_lifecycle.py`.

## 5. Commande

Après merge et `saltutil.sync_all` : recette 40 avec `pfsense.restapi`

## 6. Sortie attendue en test=True

`pfrest-installed` annonce `old: <ancienne> new: <nouvelle>`.

## 7. Vérification

`grains.item pfrest_version` sur le parc.

## 8. Retour arrière

Revenir au commit précédent : `installed` exécute `pfsense-restapi revert <ancien tag>`.

## 9. Pièges connus

- **Versions mineures.** Elles contiennent des changements cassants : ne jamais utiliser `latest`.
