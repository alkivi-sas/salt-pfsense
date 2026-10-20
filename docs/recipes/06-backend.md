# Basculer un pare-feu de FauxAPI vers pfrest

## 1. Objectif

Faire passer un pare-feu, ou un seul module, sur le backend pfrest, avec un retour arrière immédiat.

## 2. Prérequis

Recette 05 faite sur le pare-feu.

## 3. Pillar

```yaml
pfsense:
  api_backend: pfrest
  api_backend_overrides:
    pfsense_alias: fauxapi   # exemple : garder un module sur FauxAPI
```

## 4. SLS

Aucun SLS nouveau : les states existants choisissent le backend au moment de l'appel.

## 5. Commande

`salt '<minion>' saltutil.refresh_pillar`, puis `salt '<minion>' state.highstate test=True`

## 6. Sortie attendue en test=True

Idéalement aucun changement. Un changement en mode test signale un écart d'équivalence à expliquer avant le passage réel (`tests/oracle/accepted_diffs.yaml`).

## 7. Vérification

Passage réel, puis second passage à zéro changement. `salt '<minion>' config.get pfsense:api_backend` renvoie `pfrest`.

## 8. Retour arrière

Remettre `api_backend: fauxapi`, puis `saltutil.refresh_pillar` ; aucune donnée n'est à restaurer.

## 9. Pièges connus

- **Données non modélisées.** Les champs que pfrest ne modélise pas sont refusés explicitement : alias URL table, champs avancés des règles, PPPoE, champs TFTP des static maps. Garder le module concerné sur FauxAPI avec `api_backend_overrides`.
- **Hors périmètre.** Les pare-feux hors périmètre restent sur FauxAPI.
