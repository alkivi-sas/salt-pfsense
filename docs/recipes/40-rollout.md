# Déploiement sur le parc

## 1. Objectif

Appliquer une évolution à un ensemble de pare-feux, par vagues.

## 2. Prérequis

Évolution validée sur un pare-feu pilote ; cibles définies (voir `docs/migration/versions.md`).

## 3. Pillar

`rollout:targets` (motif de minions) passé en pillar à l'orchestration.

## 4. SLS

`examples/salt/orch/rollout.sls`

## 5. Commande

`salt-run state.orchestrate orch.rollout pillar='{rollout: {targets: "gateway.example-*"}}'`

## 6. Sortie attendue en test=True

L'étape `check` affiche les changements prévus par pare-feu ; rien n'est appliqué.

## 7. Vérification

Supervision des pare-feux de la vague ; second passage de `apply` sans changement.

## 8. Retour arrière

Repasser le pillar `pfsense:api_backend` à `fauxapi` sur la vague (recette 44).

## 9. Pièges connus

- **Paires HA.** Les traiter en dernier, nœud par nœud (recette 41).
- **`failhard`.** Il arrête la vague au premier échec.
