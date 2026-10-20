# Désinstaller FauxAPI

## 1. Objectif

Retirer FauxAPI d'un pare-feu entièrement passé sur pfrest (lot 8).

## 2. Prérequis

- Pare-feu sur pfrest depuis au moins 30 jours, tous modules compris (aucune surcharge vers `fauxapi`).
- Pare-feu dans le périmètre : les pare-feux hors périmètre gardent FauxAPI.

## 3. Pillar

`pfsense:api_backend: pfrest`, et aucune valeur `fauxapi` dans `pfsense:api_backend_overrides`.

## 4. SLS

`examples/salt/fauxapi_absent.sls` : il ne produit rien tant que la condition du pillar n'est pas remplie.

## 5. Commande

`salt '<minion>' state.apply pfsense.fauxapi_absent test=True`, puis sans `test`

## 6. Sortie attendue en test=True

`fauxapi-package` et `/etc/fauxapi` en `result: None` ; aucun state si le pare-feu utilise encore FauxAPI.

## 7. Vérification

`pkg info -e pfSense-pkg-FauxAPI` échoue ; `/etc/fauxapi` n'existe plus ; un highstate complet reste à zéro changement.

## 8. Retour arrière

Réinstaller FauxAPI avec le SLS d'installation existant (`pfsense/api`), puis remettre `api_backend: fauxapi` si besoin.

## 9. Pièges connus

- **Retrait du code.** Le code du backend FauxAPI reste dans ce dépôt tant qu'un pare-feu hors périmètre est en service.
- **Ordre.** Retirer FauxAPI du highstate avant de désinstaller, sinon le SLS d'installation le réinstalle.
