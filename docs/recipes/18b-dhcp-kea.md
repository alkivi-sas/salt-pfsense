# Migrer le DHCP d'ISC vers Kea

## 1. Objectif

Basculer un pare-feu d'ISC DHCP vers Kea en conservant les options personnalisées.

## 2. Prérequis

Pare-feu classé « migrable automatiquement » dans `docs/migration/dhcp.md` ; table d'options dans le pillar.

## 3. Pillar

`pfsense:dhcp_kea:options` dans `examples/pillar/pfsense.sls`.

## 4. SLS

`examples/salt/dhcp_kea.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.dhcp.kea test=True`, puis sans `test`

## 6. Sortie attendue en test=True

`result: None` avec, par interface, l'ancien et le nouveau JSON Kea, et `dhcpbackend: isc -> kea`.

## 7. Vérification

- Services > DHCP Server indique Kea.
- `pgrep -l kea-dhcp4` répond.
- Un client renouvelle son bail avec les mêmes options (capture `tcpdump -vvv port 67`).
- Un second passage n'affiche aucun changement.

## 8. Retour arrière

Services > DHCP Server > repasser le backend sur ISC : les `numberoptions` ont été vidées, il faut les ressaisir (ou restaurer la révision de configuration précédente).

## 9. Pièges connus

- **Refus explicites.** Le state refuse un failover ISC, une option absente de la table ou une configuration Kea divergente. Le failover se migre à la main vers Kea HA.
- **Option 66.** Kea refuse probablement la redéfinition d'une option standard : à valider avant de l'ajouter à la table (EXP-08).
