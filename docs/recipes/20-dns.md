# Serveurs DNS système

## 1. Objectif

Déclarer les serveurs DNS du pare-feu, avec une passerelle de sortie éventuelle.

## 2. Prérequis

Passerelle existante si `gateway` est utilisé.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/dns.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.dns test=True`

## 6. Sortie attendue en test=True

Chaque state concerné en `result: None` avec le changement prévu ; aucun state en `False`.

## 7. Vérification

System > General Setup ; `cat /etc/resolv.conf`.

## 8. Retour arrière

`pfsense_dns.absent` sur le serveur ajouté.

## 9. Pièges connus

- **Position des passerelles.** Une passerelle est rattachée à la position du serveur dans la liste. Supprimer un serveur décale donc les passerelles des suivants.
