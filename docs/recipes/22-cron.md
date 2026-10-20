# Tâches cron

## 1. Objectif

Déclarer une tâche planifiée sur le pare-feu.

## 2. Prérequis

Paquet Cron installé (exigé par pfrest).

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/cron.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.cron test=True`

## 6. Sortie attendue en test=True

Chaque state concerné en `result: None` avec le changement prévu ; aucun state en `False`.

## 7. Vérification

Services > Cron ; `crontab -l` contient la commande.

## 8. Retour arrière

`pfsense_cron.absent` avec la même commande.

## 9. Pièges connus

- **Identifiant.** Il ne sert que dans Salt : sur pfrest, la tâche est retrouvée par sa commande.
