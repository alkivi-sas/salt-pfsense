# Ordonnancer les applies

## 1. Objectif

Regrouper l'application des changements : un seul rechargement par domaine et par run.

## 2. Prérequis

Backend pfrest (recette 06).

## 3. Pillar

`pfsense:pfrest:apply: deferred` (sinon `immediate`, la valeur par défaut, applique chaque écriture).

## 4. SLS

`examples/salt/apply.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.apply test=True`, puis sans `test`

## 6. Sortie attendue en test=True

Les states `pfsense_alias` et `pfsense_filter_rule` en `result: None` ; `firewall-applied` en `result: None` s'ils changent.

## 7. Vérification

Un seul `POST firewall/apply` dans les journaux pfrest pour le run, quel que soit le nombre de règles modifiées.

## 8. Retour arrière

Repasser `pfsense:pfrest:apply` à `immediate`.

## 9. Pièges connus

- **Domaines.** `firewall`, `interface`, `routing`, `dhcp` et `wireguard` ont un apply. Les réglages système (DNS, syslog, utilisateurs, cron, VLAN) s'appliquent d'eux-mêmes.
- **Changements en attente.** En mode `deferred`, un state oublié dans `onchanges` laisse des changements en attente.
