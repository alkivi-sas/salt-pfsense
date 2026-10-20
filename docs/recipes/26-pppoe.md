# PPPoE noyau

## 1. Objectif

Activer l'implémentation PPPoE noyau (`if_pppoe`).

## 2. Prérequis

Fenêtre de maintenance : l'activation demande un redémarrage.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/pppoe.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.pppoe`

## 6. Sortie attendue en test=True

`module.run` est annoncé sans être exécuté.

## 7. Vérification

`salt '<minion>' pfsense_if_pppoe.status` renvoie `True`.

## 8. Retour arrière

`pfsense_if_pppoe.disable`, puis redémarrer.

## 9. Pièges connus

- **Redémarrage.** Avec `reboot: True` (valeur par défaut du module), le pare-feu redémarre une minute après le changement.
