# Liste blanche sshguard

## 1. Objectif

Exclure un réseau d'administration du blocage sshguard.

## 2. Prérequis

Aucun prérequis spécifique.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/sshguard.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.sshguard test=True`

## 6. Sortie attendue en test=True

Chaque state concerné en `result: None` avec le changement prévu ; aucun state en `False`.

## 7. Vérification

System > Advanced > Admin Access > Login Protection.

## 8. Retour arrière

`pfsense_sshguard_whitelist.absent`.

## 9. Pièges connus

- **Format.** La valeur est normalisée en CIDR.
