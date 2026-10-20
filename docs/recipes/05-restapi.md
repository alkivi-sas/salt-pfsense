# Installer et amorcer pfrest

## 1. Objectif

Installer la version épinglée de pfSense-pkg-RESTAPI, créer l'utilisateur API dédié et sa clé, appliquer les réglages.

## 2. Prérequis

Recettes 02, 03 et 04 ; base pfSense supportée par la version épinglée (`_utils/pfrest_lifecycle.py`).

## 3. Pillar

`examples/pillar/pfsense.sls` (`pfsense:restapi`).

## 4. SLS

`examples/salt/restapi.sls`, en tête du highstate du pare-feu.

## 5. Commande

`salt '<minion>' state.apply pfsense.restapi test=True`, puis sans `test`

## 6. Sortie attendue en test=True

- `pfrest-installed` en `result: None`, avec `old: ''` et `new: 2.10_2`.
- `pfrest-bootstrapped` en `result: None` (`bootstrap: would run`).
- `pfrest-configured` : lors d'une première installation, il échoue en mode test tant que la clé n'existe pas encore. Il faut donc enchaîner un passage réel.

## 7. Vérification

- `salt '<minion>' pfsense_restapi.status` renvoie la version de pfSense.
- Un second passage n'affiche aucun changement.
- Dans le WebGUI, System > REST API : authentification `KeyAuth` seule, utilisateur `salt-api` sans `page-all`.

## 8. Retour arrière

`pfsense-restapi delete` sur le pare-feu, puis `pfsense:api_backend: fauxapi` dans le pillar.

## 9. Pièges connus

- **Plus.** L'installation passe par `pkg-static -C /dev/null add` pour contourner les dépôts Netgate.
- **Restart du WebGUI.** `configured` change `represent_interfaces_as` en `id` : le WebGUI redémarre une fois.
- **Access list.** Effet d'une access list réduite à 127.0.0.1/32 non vérifié sans lab.
